package server

import (
	"dns3000/internal/dns"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	mdns "github.com/miekg/dns"
)

func StartDoHServer(port int, cert, key, path string, handler *dns.Handler) {
	fmt.Printf("Starting DoH server on port %d, path %s\n", port, path)

	mux := http.NewServeMux()
	// Handle specific path (and subpaths by default in Go 1.22+ or careful prefix matching)
	// For Go < 1.22, used strip prefix logic manually often, but ServeMux supports prefix matching.

	// We register two handlers: one for exact match (maybe) and one for subpaths?
	// Actually http.ServeMux "/foo/" matches "/foo/bar".
	pathPrefix := path
	if !strings.HasSuffix(pathPrefix, "/") {
		pathPrefix += "/"
	}

	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		handleDoH(w, r, path, handler)
	})
	if path != "/" {
		mux.HandleFunc(pathPrefix, func(w http.ResponseWriter, r *http.Request) {
			handleDoH(w, r, path, handler)
		})
	}

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	if err := srv.ListenAndServeTLS(cert, key); err != nil {
		log.Fatalf("DoH server failed: %v", err)
	}
}

func handleDoH(w http.ResponseWriter, r *http.Request, basePath string, handler *dns.Handler) {
	// 1. Extract MAC from path if present
	mac := ""
	if len(r.URL.Path) > len(basePath) {
		sub := r.URL.Path[len(basePath):]
		sub = strings.TrimPrefix(sub, "/")
		if sub != "" {
			// Basic validation: dots/dashes/colons allowed in MAC usually, or just hex.
			// The user spec says "from url path".
			mac = sub
		}
	}

	// 2. Parse DNS Message
	var msg *mdns.Msg
	if r.Method == "POST" {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}
		msg = new(mdns.Msg)
		if err := msg.Unpack(body); err != nil {
			http.Error(w, "Invalid DNS message", http.StatusBadRequest)
			return
		}
	} else if r.Method == "GET" {
		// base64url decode dns parameter
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			http.Error(w, "Missing dns parameter", http.StatusBadRequest)
			return
		}
		// TODO: Implement GET if needed, skipping for now to focus on POST/MAC
		http.Error(w, "GET not supported yet", http.StatusMethodNotAllowed)
		return
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// 3. Resolve
	remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if remoteIP == "" {
		remoteIP = r.RemoteAddr
	}

	rw := &HttpDNSWriter{W: w, LocalAddrStr: r.Host, RemoteAddrStr: r.RemoteAddr}

	ctx := dns.RequestContext{
		ClientIP:  remoteIP,
		ClientMAC: mac,
		Protocol:  "doh",
	}

	handler.Resolve(rw, msg, ctx)
}

// HttpDNSWriter implements dns.ResponseWriter
type HttpDNSWriter struct {
	W             http.ResponseWriter
	LocalAddrStr  string
	RemoteAddrStr string
}

func (w *HttpDNSWriter) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443}
}
func (w *HttpDNSWriter) RemoteAddr() net.Addr {
	host, _, _ := net.SplitHostPort(w.RemoteAddrStr)
	return &net.TCPAddr{IP: net.ParseIP(host), Port: 0}
}
func (w *HttpDNSWriter) WriteMsg(msg *mdns.Msg) error {
	buf, err := msg.Pack()
	if err != nil {
		return err
	}
	w.W.Header().Set("Content-Type", "application/dns-message")
	w.W.Write(buf)
	return nil
}
func (w *HttpDNSWriter) Write(b []byte) (int, error) { return w.W.Write(b) }
func (w *HttpDNSWriter) Close() error                { return nil }
func (w *HttpDNSWriter) TsigStatus() error           { return nil }
func (w *HttpDNSWriter) TsigTimersOnly(bool)         {}
func (w *HttpDNSWriter) Hijack()                     {}
