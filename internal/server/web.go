package server

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"dns3000/data"
	"dns3000/internal/config"
	"dns3000/internal/device"
	"dns3000/internal/dns"
	"dns3000/internal/logging"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// WebServer struct needs DataDir to save config
type WebServer struct {
	Cfg           *config.Config
	Logger        *logging.Logger
	DeviceManager *device.Manager
	DNSHandler    *dns.Handler
	DataDir       string
	Sessions      map[string]time.Time
	SessionsMu    sync.Mutex
	assetsHandler http.Handler
}

func StartWebServer(port int, cfg *config.Config, logger *logging.Logger, devMgr *device.Manager, dnsHandler *dns.Handler, dataDir string) {
	sub, _ := fs.Sub(data.Assets, "www")
	ws := &WebServer{
		Cfg:           cfg,
		Logger:        logger,
		DeviceManager: devMgr,
		DNSHandler:    dnsHandler,
		DataDir:       dataDir,
		Sessions:      make(map[string]time.Time),
		assetsHandler: http.FileServer(http.FS(sub)),
	}

	http.HandleFunc("/", ws.gzipMiddleware(ws.handleIndex))
	http.HandleFunc("/api/auth/status", ws.gzipMiddleware(ws.handleAuthStatus))
	http.HandleFunc("/api/auth/login", ws.gzipMiddleware(ws.handleAuthLogin))
	http.HandleFunc("/api/auth/register", ws.gzipMiddleware(ws.handleAuthRegister))
	http.HandleFunc("/api/auth/logout", ws.gzipMiddleware(ws.handleAuthLogout))

	http.HandleFunc("/api/logs", ws.requireAuth(ws.gzipMiddleware(ws.handleLogs)))
	http.HandleFunc("/api/stats", ws.requireAuth(ws.gzipMiddleware(ws.handleStats)))
	http.HandleFunc("/api/rewrites", ws.requireAuth(ws.gzipMiddleware(ws.handleRewrites)))
	http.HandleFunc("/api/settings", ws.requireAuth(ws.gzipMiddleware(ws.handleSettings)))
	http.HandleFunc("/api/devices", ws.requireAuth(ws.gzipMiddleware(ws.handleDevices)))
	http.HandleFunc("/api/active-devices", ws.requireAuth(ws.gzipMiddleware(ws.handleActiveDevices)))
	http.HandleFunc("/api/device-groups", ws.requireAuth(ws.gzipMiddleware(ws.handleDeviceGroups)))
	http.HandleFunc("/api/rule-groups", ws.requireAuth(ws.gzipMiddleware(ws.handleRuleGroups)))
	http.HandleFunc("/api/services", ws.requireAuth(ws.gzipMiddleware(ws.handleServices)))
	http.HandleFunc("/api/upstreams", ws.requireAuth(ws.gzipMiddleware(ws.handleUpstreams)))

	fmt.Printf("Starting Web server on port %d\n", port)
	if err := http.ListenAndServe(":"+strconv.Itoa(port), nil); err != nil {
		fmt.Printf("Web server failed: %v\n", err)
	}
}

func (ws *WebServer) Reload() {
	if ws.DNSHandler != nil {
		ws.DNSHandler.Reload(ws.Cfg)
	}
}

func (ws *WebServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" || r.URL.Path == "/index.html" {
		// Check Auth
		authorized := false
		cookie, err := r.Cookie("dns3000_session")
		if err == nil {
			ws.SessionsMu.Lock()
			expiry, ok := ws.Sessions[cookie.Value]
			ws.SessionsMu.Unlock()
			if ok && time.Now().Before(expiry) {
				authorized = true
				// Refresh session
				ws.SessionsMu.Lock()
				ws.Sessions[cookie.Value] = time.Now().Add(24 * time.Hour)
				ws.SessionsMu.Unlock()
			}
		}

		if !authorized {
			if ws.Cfg.Auth.Username == "" {
				http.Redirect(w, r, "/register.html", http.StatusFound)
			} else {
				http.Redirect(w, r, "/login.html", http.StatusFound)
			}
			return
		}

		r.URL.Path = "/"
		ws.assetsHandler.ServeHTTP(w, r)
		return
	}
	ws.assetsHandler.ServeHTTP(w, r)
}

func (ws *WebServer) handleLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	if page < 1 {
		page = 1
	}

	domain := strings.ToLower(q.Get("domain"))
	device := strings.ToLower(q.Get("device"))
	status := q.Get("status")

	allLogs := ws.Logger.GetLogs(0, 10000)

	// Filter
	var filtered []logging.QueryLog
	for i := len(allLogs) - 1; i >= 0; i-- {
		log := allLogs[i]
		if domain != "" && !strings.Contains(strings.ToLower(log.Domain), domain) {
			continue
		}
		if device != "" && !strings.Contains(strings.ToLower(log.DeviceIP), device) && !strings.Contains(strings.ToLower(log.DeviceName), device) {
			continue
		}
		if status != "" && log.Status != status {
			continue
		}
		filtered = append(filtered, log)
	}

	total := len(filtered)
	start := (page - 1) * limit
	end := start + limit
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	result := map[string]interface{}{
		"logs":  filtered[start:end],
		"total": total,
		"page":  page,
		"limit": limit,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (ws *WebServer) handleStats(w http.ResponseWriter, r *http.Request) {
	allLogs := ws.Logger.GetLogs(0, 10000)
	total := len(allLogs)
	blocked := 0
	for _, log := range allLogs {
		if log.Status == "Blocked" {
			blocked++
		}
	}
	percentage := 0.0
	if total > 0 {
		percentage = float64(blocked) / float64(total) * 100
	}

	stats := map[string]interface{}{
		"total_queries":      total,
		"blocked":            blocked,
		"allowed":            total - blocked,
		"blocked_percentage": percentage,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (ws *WebServer) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		settings := map[string]interface{}{
			"log_count":            ws.Cfg.LogCount,
			"rule_update_interval": ws.Cfg.RuleUpdateInterval.String(),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(settings)
		return
	}

	if r.Method == "POST" {
		var req struct {
			LogCount           int    `json:"log_count"`
			RuleUpdateInterval string `json:"rule_update_interval"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if req.LogCount > 0 {
			ws.Cfg.LogCount = req.LogCount
		}
		if req.RuleUpdateInterval != "" {
			d, err := time.ParseDuration(req.RuleUpdateInterval)
			if err != nil {
				http.Error(w, "Invalid duration format", 400)
				return
			}
			ws.Cfg.RuleUpdateInterval = d
		}
		ws.Cfg.Save(ws.DataDir)
		go ws.Reload()
		w.WriteHeader(http.StatusOK)
		return
	}
}

func (ws *WebServer) handleRewrites(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		q := r.URL.Query()
		page, _ := strconv.Atoi(q.Get("page"))
		limit, _ := strconv.Atoi(q.Get("limit"))
		if limit <= 0 {
			limit = 50
		}
		if page < 1 {
			page = 1
		}

		total := len(ws.Cfg.Rewrites)
		start := (page - 1) * limit
		end := start + limit
		if start > total {
			start = total
		}
		if end > total {
			end = total
		}

		result := map[string]interface{}{
			"rewrites": ws.Cfg.Rewrites[start:end],
			"total":    total,
			"page":     page,
			"limit":    limit,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
		return
	}

	if r.Method == "POST" {
		var rewrite config.Rewrite
		if err := json.NewDecoder(r.Body).Decode(&rewrite); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		ws.Cfg.Rewrites = append(ws.Cfg.Rewrites, rewrite)
		ws.Cfg.Save(ws.DataDir)
		go ws.Reload()
		return
	}

	if r.Method == "PUT" {
		var req struct {
			OldName string `json:"old_name"`
			Name    string `json:"name"`
			Value   string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		for i, rw := range ws.Cfg.Rewrites {
			if rw.Name == req.OldName {
				ws.Cfg.Rewrites[i].Name = req.Name
				ws.Cfg.Rewrites[i].Value = req.Value
				break
			}
		}
		ws.Cfg.Save(ws.DataDir)
		go ws.Reload()
		return
	}

	if r.Method == "DELETE" {
		name := r.URL.Query().Get("name")
		newRewrites := []config.Rewrite{}
		for _, rw := range ws.Cfg.Rewrites {
			if rw.Name != name {
				newRewrites = append(newRewrites, rw)
			}
		}
		ws.Cfg.Rewrites = newRewrites
		ws.Cfg.Save(ws.DataDir)
		go ws.Reload()
	}
}

func (ws *WebServer) handleDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ws.Cfg.Devices)
		return
	}

	if r.Method == "POST" {
		var device config.Device
		if err := json.NewDecoder(r.Body).Decode(&device); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if device.DeviceGroup == "" {
			http.Error(w, "Device group is required", 400)
			return
		}
		ws.Cfg.Devices = append(ws.Cfg.Devices, device)
		ws.Cfg.Save(ws.DataDir)
		go ws.Reload()
		return
	}

	if r.Method == "PUT" {
		var req struct {
			OldMAC      string `json:"old_mac"`
			Name        string `json:"name"`
			MAC         string `json:"mac"`
			DeviceGroup string `json:"device_group"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if req.DeviceGroup == "" {
			http.Error(w, "Device group is required", 400)
			return
		}
		for i, d := range ws.Cfg.Devices {
			if d.MAC == req.OldMAC {
				ws.Cfg.Devices[i].Name = req.Name
				ws.Cfg.Devices[i].MAC = req.MAC
				ws.Cfg.Devices[i].DeviceGroup = req.DeviceGroup
				break
			}
		}
		ws.Cfg.Save(ws.DataDir)
		go ws.Reload()
		return
	}

	if r.Method == "DELETE" {
		mac := r.URL.Query().Get("mac")
		newDevices := []config.Device{}
		for _, d := range ws.Cfg.Devices {
			if d.MAC != mac {
				newDevices = append(newDevices, d)
			}
		}
		ws.Cfg.Devices = newDevices
		ws.Cfg.Save(ws.DataDir)
		go ws.DeviceManager.Reload(ws.Cfg)
	}
}

func (ws *WebServer) handleActiveDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		activeDevices := ws.DeviceManager.GetActiveDevices()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(activeDevices)
		return
	}
}

func (ws *WebServer) handleDeviceGroups(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ws.Cfg.DeviceGroups)
		return
	}

	if r.Method == "POST" {
		var group config.DeviceGroup
		if err := json.NewDecoder(r.Body).Decode(&group); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		ws.Cfg.DeviceGroups = append(ws.Cfg.DeviceGroups, group)
		ws.Cfg.Save(ws.DataDir)
		go ws.Reload()
		return
	}

	if r.Method == "PUT" {
		var req struct {
			OldName    string                        `json:"old_name"`
			Name       string                        `json:"name"`
			RuleGroups []config.DeviceGroupRuleGroup `json:"rule_groups"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		for i, g := range ws.Cfg.DeviceGroups {
			if g.Name == req.OldName {
				ws.Cfg.DeviceGroups[i].Name = req.Name
				ws.Cfg.DeviceGroups[i].RuleGroups = req.RuleGroups
				break
			}
		}
		ws.Cfg.Save(ws.DataDir)
		go ws.Reload()
		return
	}

	if r.Method == "DELETE" {
		name := r.URL.Query().Get("name")
		// Check if any device uses this group
		for _, d := range ws.Cfg.Devices {
			if d.DeviceGroup == name {
				http.Error(w, "Cannot delete: group has devices", 400)
				return
			}
		}
		newGroups := []config.DeviceGroup{}
		for _, g := range ws.Cfg.DeviceGroups {
			if g.Name != name {
				newGroups = append(newGroups, g)
			}
		}
		ws.Cfg.DeviceGroups = newGroups
		ws.Cfg.Save(ws.DataDir)
		go ws.Reload()
	}
}

func (ws *WebServer) handleRuleGroups(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ws.Cfg.RuleGroups)
		return
	}

	if r.Method == "POST" {
		var group config.RuleGroup
		if err := json.NewDecoder(r.Body).Decode(&group); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		ws.Cfg.RuleGroups = append(ws.Cfg.RuleGroups, group)
		ws.Cfg.Save(ws.DataDir)
		go ws.Reload()
		return
	}

	if r.Method == "PUT" {
		var group config.RuleGroup
		if err := json.NewDecoder(r.Body).Decode(&group); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		oldName := r.URL.Query().Get("name")
		for i, g := range ws.Cfg.RuleGroups {
			if g.Name == oldName {
				ws.Cfg.RuleGroups[i] = group
				break
			}
		}
		ws.Cfg.Save(ws.DataDir)
		go ws.Reload()
		return
	}

	if r.Method == "DELETE" {
		name := r.URL.Query().Get("name")
		// Check if any device group uses this rule group
		for _, dg := range ws.Cfg.DeviceGroups {
			for _, rg := range dg.RuleGroups {
				if rg.Name == name {
					http.Error(w, "Cannot delete: rule group is in use by device group", 400)
					return
				}
			}
		}
		newGroups := []config.RuleGroup{}
		for _, g := range ws.Cfg.RuleGroups {
			if g.Name != name {
				newGroups = append(newGroups, g)
			}
		}
		ws.Cfg.RuleGroups = newGroups
		ws.Cfg.Save(ws.DataDir)
		go ws.Reload()
	}
}

func (ws *WebServer) handleServices(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ws.Cfg.Services)
		return
	}

	if r.Method == "POST" {
		var svc config.Service
		if err := json.NewDecoder(r.Body).Decode(&svc); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		ws.Cfg.Services = append(ws.Cfg.Services, svc)
		ws.Cfg.Save(ws.DataDir)
		go ws.Reload()
		return
	}

	if r.Method == "PUT" {
		var svc config.Service
		if err := json.NewDecoder(r.Body).Decode(&svc); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		oldName := r.URL.Query().Get("name")
		for i, s := range ws.Cfg.Services {
			if s.Name == oldName {
				ws.Cfg.Services[i] = svc
				break
			}
		}
		ws.Cfg.Save(ws.DataDir)
		go ws.Reload()
		return
	}

	if r.Method == "DELETE" {
		name := r.URL.Query().Get("name")
		// Check if any rule group source uses this service
		for _, rg := range ws.Cfg.RuleGroups {
			for _, src := range rg.Sources {
				for _, svcName := range src.Services {
					if svcName == name {
						http.Error(w, "Cannot delete: service is in use by rule group", 400)
						return
					}
				}
			}
		}
		newServices := []config.Service{}
		for _, s := range ws.Cfg.Services {
			if s.Name != name {
				newServices = append(newServices, s)
			}
		}
		ws.Cfg.Services = newServices
		ws.Cfg.Save(ws.DataDir)
		go ws.Reload()
	}
}

func (ws *WebServer) handleUpstreams(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ws.Cfg.Upstreams)
		return
	}

	if r.Method == "POST" {
		var upstreams config.UpstreamsConfig
		if err := json.NewDecoder(r.Body).Decode(&upstreams); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		ws.Cfg.Upstreams = upstreams
		ws.Cfg.Save(ws.DataDir)
		go ws.Reload()
		return
	}
}

func (ws *WebServer) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("dns3000_session")
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		ws.SessionsMu.Lock()
		expiry, ok := ws.Sessions[cookie.Value]
		ws.SessionsMu.Unlock()

		if !ok || time.Now().After(expiry) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Refresh session
		ws.SessionsMu.Lock()
		ws.Sessions[cookie.Value] = time.Now().Add(24 * time.Hour)
		ws.SessionsMu.Unlock()

		next(w, r)
	}
}

func (ws *WebServer) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]bool{
		"needs_setup": ws.Cfg.Auth.Username == "",
		"logged_in":   false,
	}

	cookie, err := r.Cookie("dns3000_session")
	if err == nil {
		ws.SessionsMu.Lock()
		expiry, ok := ws.Sessions[cookie.Value]
		ws.SessionsMu.Unlock()
		if ok && time.Now().Before(expiry) {
			status["logged_in"] = true
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (ws *WebServer) handleAuthRegister(w http.ResponseWriter, r *http.Request) {
	if ws.Cfg.Auth.Username != "" {
		// If already set up, check if user is logged in to allow changing password?
		// For now, strict: only if not set up.
		// Or maybe we allow overwrite if authenticated?
		// The prompt says "If NOT set... jump to register". Implicitly if set, login.
		// Let's protect it: if set, require auth?
		// Simplest for now: if set, forbid register without auth.

		// Check auth
		cookie, err := r.Cookie("dns3000_session")
		authorized := false
		if err == nil {
			ws.SessionsMu.Lock()
			expiry, ok := ws.Sessions[cookie.Value]
			ws.SessionsMu.Unlock()
			if ok && time.Now().Before(expiry) {
				authorized = true
			}
		}

		if !authorized {
			http.Error(w, "Already set up", http.StatusForbidden)
			return
		}
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	if req.Username == "" || req.Password == "" {
		http.Error(w, "Username and password required", 400)
		return
	}

	hash := sha256.Sum256([]byte(req.Password))
	ws.Cfg.Auth.Username = req.Username
	ws.Cfg.Auth.Password = hex.EncodeToString(hash[:])
	ws.Cfg.Save(ws.DataDir)

	w.WriteHeader(http.StatusOK)
}

func (ws *WebServer) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	hash := sha256.Sum256([]byte(req.Password))
	hashStr := hex.EncodeToString(hash[:])

	if req.Username != ws.Cfg.Auth.Username || hashStr != ws.Cfg.Auth.Password {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Generate session
	b := make([]byte, 32)
	rand.Read(b)
	sessionID := base64.URLEncoding.EncodeToString(b)

	ws.SessionsMu.Lock()
	ws.Sessions[sessionID] = time.Now().Add(24 * time.Hour)
	ws.SessionsMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "dns3000_session",
		Value:    sessionID,
		Path:     "/",
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
	})

	w.WriteHeader(http.StatusOK)
}

func (ws *WebServer) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("dns3000_session")
	if err == nil {
		ws.SessionsMu.Lock()
		delete(ws.Sessions, cookie.Value)
		ws.SessionsMu.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "dns3000_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	w.WriteHeader(http.StatusOK)
}

type gzipResponseWriter struct {
	http.ResponseWriter
	io.Writer
	status int
}

func (w *gzipResponseWriter) WriteHeader(status int) {
	w.status = status
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

func (ws *WebServer) gzipMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next(w, r)
			return
		}

		// Use a buffer to capture the output and decide whether to compress
		var buf bytes.Buffer
		capture := &gzipResponseWriter{ResponseWriter: w, Writer: &buf}

		next(capture, r)

		data := buf.Bytes()
		if len(data) == 0 {
			if capture.status != 0 {
				w.WriteHeader(capture.status)
			}
			return
		}

		contentType := w.Header().Get("Content-Type")
		if contentType == "" {
			// Try to detect common types by path if not set
			path := r.URL.Path
			if path == "/" || strings.HasSuffix(path, ".html") {
				contentType = "text/html"
			} else if strings.HasSuffix(path, ".js") {
				contentType = "application/javascript"
			} else if strings.HasSuffix(path, ".json") {
				contentType = "application/json"
			} else {
				contentType = http.DetectContentType(data)
			}
			w.Header().Set("Content-Type", contentType)
		}

		shouldCompress := (strings.Contains(contentType, "html") ||
			strings.Contains(contentType, "javascript") ||
			strings.Contains(contentType, "json")) &&
			len(data) > 20*1024

		if shouldCompress {
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Del("Content-Length")
			if capture.status != 0 {
				w.WriteHeader(capture.status)
			}
			gz := gzip.NewWriter(w)
			gz.Write(data)
			gz.Close()
		} else {
			if capture.status != 0 {
				w.WriteHeader(capture.status)
			}
			w.Write(data)
		}
	}
}
