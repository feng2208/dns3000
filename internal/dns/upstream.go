package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func ForwardToUpstream(req *dns.Msg, servers []string) (*dns.Msg, string, error) {
	if len(servers) == 0 {
		return nil, "", fmt.Errorf("no upstream servers")
	}

	// Limit to 3 concurrent? Requirement says "simultaneously query up to 3".
	maxConcurrent := 3
	if len(servers) > maxConcurrent {
		servers = servers[:maxConcurrent]
	}

	type result struct {
		msg      *dns.Msg
		err      error
		upstream string
	}

	resCh := make(chan result, len(servers))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, s := range servers {
		go func(upstream string) {
			msg, err := exchange(ctx, req, upstream)
			select {
			case resCh <- result{msg, err, upstream}:
			case <-ctx.Done():
			}
		}(s)
	}

	// Return first success
	// We wait for first success or all failures? "return the result that is obtained fastest" (and valid).
	var errs []error
	for i := 0; i < len(servers); i++ {
		res := <-resCh
		if res.err == nil && res.msg != nil {
			return res.msg, res.upstream, nil
		}
		if res.err != nil {
			errs = append(errs, res.err)
		}
	}

	return nil, "", fmt.Errorf("all upstreams failed: %v", errs)
}

func exchange(ctx context.Context, req *dns.Msg, upstream string) (*dns.Msg, error) {
	// Protocol detection
	if strings.HasPrefix(upstream, "https://") {
		return exchangeDoH(ctx, req, upstream)
	}

	// TCP/UDP
	// If upstream has no port, add :53
	address := upstream
	if !strings.Contains(address, ":") {
		address += ":53"
	}

	// Default UDP
	client := new(dns.Client)
	// client.Net = "udp" // Default
	// Use ExchangeContext if available in this version of miekg/dns?
	// It is `ExchangeContext`.

	msg, _, err := client.ExchangeContext(ctx, req, address)
	// If truncated, try TCP? Standard dns client handles fallback if configured?
	// No, miekg/dns keeps it simple.
	if msg != nil && msg.Truncated {
		client.Net = "tcp"
		msg, _, err = client.ExchangeContext(ctx, req, address)
	}
	return msg, err
}

func exchangeDoH(ctx context.Context, req *dns.Msg, url string) (*dns.Msg, error) {
	buf, err := req.Pack()
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")

	// Disable cert check for now or use default (user provided tls certs are for Server, not client)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH upstream returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	msg := new(dns.Msg)
	err = msg.Unpack(body)
	return msg, err
}
