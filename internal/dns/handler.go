package dns

import (
	"dns3000/internal/config"
	"dns3000/internal/device"
	"dns3000/internal/logging"
	"dns3000/internal/rules"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Handler struct {
	Cfg            *config.Config
	DeviceManager  *device.Manager
	RuleManager    *rules.Manager
	Cache          *Cache
	Logger         *logging.Logger
	UpstreamRoutes *config.UpstreamRoute
	RewriteEngine  *RewriteEngine
	mu             sync.RWMutex
}

func (h *Handler) Reload(cfg *config.Config) {
	h.mu.Lock()
	h.Cfg = cfg
	h.UpstreamRoutes = cfg.ParseUpstreamRoutes()
	h.RewriteEngine = NewRewriteEngine(cfg.Rewrites)
	h.mu.Unlock()

	// Perform time-consuming reloads outside the handler lock
	h.RuleManager.Reload(cfg)
	h.DeviceManager.Reload(cfg)
}

type RequestContext struct {
	ClientIP string
	ClientID string
	Protocol string
}

func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	// Extract context from standard UDP/TCP
	ctx := RequestContext{
		Protocol: "udp", // default
	}
	if addr, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		ctx.ClientIP = addr.IP.String()
	} else if addr, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		ctx.ClientIP = addr.IP.String()
		ctx.Protocol = "tcp"
	}

	h.Resolve(w, r, ctx)
}

func (h *Handler) Resolve(w dns.ResponseWriter, r *dns.Msg, ctx RequestContext) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if len(r.Question) == 0 {
		dns.HandleFailed(w, r)
		return
	}

	q := r.Question[0]
	domain := strings.TrimSuffix(q.Name, ".")
	ctxKey := fmt.Sprintf("%s:%d", q.Name, q.Qtype)

	// 1. Identify Device
	d, clientID := h.identifyDevice(ctx)
	deviceRouteKey, deviceName := h.getDeviceDetails(d, clientID, ctx.ClientIP)

	// Record activity
	h.DeviceManager.RecordActivity(ctx.ClientIP, clientID, deviceName)

	logEntry := logging.QueryLog{
		Time:       time.Now(),
		Domain:     domain,
		Type:       dns.TypeToString[q.Qtype],
		Protocol:   ctx.Protocol,
		DeviceIP:   ctx.ClientIP,
		DeviceName: deviceName,
		DeviceID:   clientID,
	}

	// 2. Check Rewrites (Exact and Wildcard)
	if h.checkRewrites(w, r, domain, deviceRouteKey, q, &logEntry) {
		return
	}

	// 3. Match Rules
	activeRuleGroups := h.getActiveRuleGroups(d)
	reqInfo := rules.RequestInfo{
		ClientIP:   ctx.ClientIP,
		ClientID:   clientID,
		ClientName: deviceName,
		Protocol:   ctx.Protocol,
		QType:      dns.TypeToString[q.Qtype],
		Domain:     domain,
	}

	blockRule, blockGroup := h.matchRuleGroups(domain, activeRuleGroups, reqInfo)
	if blockRule != nil {
		h.handleBlock(w, r, blockRule, blockGroup, q, &logEntry)
		return
	}

	// 4. Check Cache
	if h.checkCache(w, r, ctxKey, deviceRouteKey, &logEntry) {
		return
	}

	// 5. Forward to Upstream
	h.resolveUpstream(w, r, domain, deviceRouteKey, ctxKey, &logEntry)
}

func (h *Handler) identifyDevice(ctx RequestContext) (*config.Device, string) {
	var d *config.Device
	id := ctx.ClientID

	// 1. Try ID Lookup first (Prioritized)
	if id != "" {
		d = h.DeviceManager.GetDeviceByID(id)
	}

	// 2. If not found by ID, try IP Lookup
	if d == nil && ctx.ClientIP != "" {
		d = h.DeviceManager.GetDeviceByIP(ctx.ClientIP)
	}

	// If found by IP and we don't have ID yet, try to use ID from config if available
	if d != nil && id == "" && d.ID != "" {
		id = d.ID
	}

	return d, id
}

func (h *Handler) getDeviceDetails(d *config.Device, id, ip string) (string, string) {
	deviceRouteKey := "default"
	deviceName := "Unknown"
	if d != nil {
		deviceName = d.Name
		if d.ID != "" {
			deviceRouteKey = d.ID
		} else if d.IP != "" {
			deviceRouteKey = d.IP
		}
	} else if id != "" {
		deviceRouteKey = id
	} else if ip != "" {
		deviceRouteKey = ip
	}
	return deviceRouteKey, deviceName
}

func (h *Handler) checkCache(w dns.ResponseWriter, r *dns.Msg, key, group string, logEntry *logging.QueryLog) bool {
	cachedMsg, cachedStatus, ok := h.Cache.Get(key, group)
	if !ok {
		return false
	}
	cachedMsg.SetReply(r)
	w.WriteMsg(cachedMsg)

	logEntry.Status = cachedStatus
	logEntry.Response = summarizeResponse(cachedMsg)
	h.Logger.Log(*logEntry)
	return true
}

func (h *Handler) checkRewrites(w dns.ResponseWriter, r *dns.Msg, domain, group string, q dns.Question, logEntry *logging.QueryLog) bool {
	rewriteVal := h.RewriteEngine.Match(domain)
	if rewriteVal == "" {
		return false
	}

	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	if IsIP(rewriteVal) {
		msg.Rcode = dns.RcodeSuccess
		switch q.Qtype {
		case dns.TypeA:
			rr, _ := dns.NewRR(fmt.Sprintf("%s 30 IN A %s", q.Name, rewriteVal))
			msg.Answer = append(msg.Answer, rr)
		case dns.TypeAAAA:
			if ip := net.ParseIP(rewriteVal); ip != nil && ip.To4() == nil {
				rr, _ := dns.NewRR(fmt.Sprintf("%s 30 IN AAAA %s", q.Name, rewriteVal))
				msg.Answer = append(msg.Answer, rr)
			}
		}
		w.WriteMsg(msg)

		logEntry.Status = "Rewritten"
		logEntry.Rule = rewriteVal
		logEntry.Response = summarizeResponse(msg)
		h.Logger.Log(*logEntry)
		return true
	}

	// Domain rewrite (CNAME behavior)
	reqFn := r.Copy()
	reqFn.Question[0].Name = dns.Fqdn(rewriteVal)
	targetUpstreams := h.getUpstreams(domain, group)
	resp, upstream, err := ForwardToUpstream(reqFn, targetUpstreams)

	if err == nil && resp != nil {
		rr, _ := dns.NewRR(fmt.Sprintf("%s 30 IN CNAME %s", q.Name, dns.Fqdn(rewriteVal)))
		msg.Answer = append(msg.Answer, rr)
		msg.Answer = append(msg.Answer, resp.Answer...) // Flatten answer?
		msg.Rcode = resp.Rcode
		w.WriteMsg(msg)

		logEntry.Status = "Rewritten"
		logEntry.Rule = rewriteVal
		logEntry.Upstream = upstream
		logEntry.Response = summarizeResponse(msg)
		h.Logger.Log(*logEntry)
		return true
	}

	return false
}

func (h *Handler) matchRuleGroups(domain string, activeRuleGroups []string, reqInfo rules.RequestInfo) (*rules.Rule, string) {
	for _, rgName := range activeRuleGroups {
		engine := h.RuleManager.GetEngine(rgName)
		if engine == nil {
			continue
		}
		match := engine.Match(domain, reqInfo)
		if match != nil {
			if match.IsWhitelist {
				// If whitelisted, we stop looking and return NO block.
				// Wait, if it matched a whitelist, we should proceed to upstream?
				// Yes.
				return nil, ""
			}
			// It's a block
			return match, rgName
		}
	}
	return nil, ""
}

func (h *Handler) handleBlock(w dns.ResponseWriter, r *dns.Msg, rule *rules.Rule, groupName string, q dns.Question, logEntry *logging.QueryLog) {
	msg := new(dns.Msg)
	msg.SetReply(r)

	statusStr := "Blocked"
	if rwVal, ok := rule.Modifiers["dnsrewrite"]; ok {
		statusStr = "Rewritten"
		if rwVal == "NXDOMAIN" {
			msg.Rcode = dns.RcodeNameError
		} else if rwVal == "REFUSED" {
			msg.Rcode = dns.RcodeRefused
		} else if IsIP(rwVal) {
			msg.Rcode = dns.RcodeSuccess
			if q.Qtype == dns.TypeA {
				rr, _ := dns.NewRR(fmt.Sprintf("%s 30 IN A %s", q.Name, rwVal))
				msg.Answer = append(msg.Answer, rr)
			}
		}
	} else {
		msg.Rcode = dns.RcodeNameError
		if q.Qtype == dns.TypeA {
			rr, _ := dns.NewRR(fmt.Sprintf("%s 30 IN A 0.0.0.0", q.Name))
			msg.Answer = append(msg.Answer, rr)
		}
	}

	w.WriteMsg(msg)

	logEntry.Status = statusStr
	logEntry.Rule = rule.Raw
	logEntry.RuleGroup = groupName
	logEntry.RuleSource = rule.SourceName
	logEntry.Response = summarizeResponse(msg)
	h.Logger.Log(*logEntry)
}

func (h *Handler) resolveUpstream(w dns.ResponseWriter, r *dns.Msg, domain, group, key string, logEntry *logging.QueryLog) {
	start := time.Now()
	targetUpstreams := h.getUpstreams(domain, group)
	resp, upstream, err := ForwardToUpstream(r, targetUpstreams)

	if err == nil && resp != nil {
		resp.Compress = true
		minTTL := uint32(1800)
		if len(resp.Answer) > 0 {
			minTTL = resp.Answer[0].Header().Ttl
			for _, rr := range resp.Answer {
				if rr.Header().Ttl < minTTL {
					minTTL = rr.Header().Ttl
				}
			}
		}
		h.Cache.Set(key, group, resp, time.Duration(minTTL)*time.Second, "Allowed")
		w.WriteMsg(resp)

		logEntry.Status = "Allowed"
		logEntry.LatencyMs = float64(time.Since(start).Milliseconds())
		logEntry.Upstream = upstream
		logEntry.Response = summarizeResponse(resp)
		h.Logger.Log(*logEntry)
		return
	}

	dns.HandleFailed(w, r)
	logEntry.Status = "Failed"
	logEntry.Response = "Failed"
	h.Logger.Log(*logEntry)
}

func summarizeResponse(msg *dns.Msg) string {
	if msg == nil {
		return ""
	}
	if msg.Rcode != dns.RcodeSuccess {
		return dns.RcodeToString[msg.Rcode]
	}

	var parts []string
	for _, ans := range msg.Answer {
		hdr := ans.Header()
		switch rr := ans.(type) {
		case *dns.A:
			parts = append(parts, fmt.Sprintf("A: %s (ttl=%d)", rr.A.String(), hdr.Ttl))
		case *dns.AAAA:
			parts = append(parts, fmt.Sprintf("AAAA: %s (ttl=%d)", rr.AAAA.String(), hdr.Ttl))
		case *dns.CNAME:
			parts = append(parts, fmt.Sprintf("CNAME: %s (ttl=%d)", rr.Target, hdr.Ttl))
		case *dns.TXT:
			parts = append(parts, fmt.Sprintf("TXT: %s (ttl=%d)", strings.Join(rr.Txt, " "), hdr.Ttl))
		case *dns.MX:
			parts = append(parts, fmt.Sprintf("MX: %d %s (ttl=%d)", rr.Preference, rr.Mx, hdr.Ttl))
		case *dns.NS:
			parts = append(parts, fmt.Sprintf("NS: %s (ttl=%d)", rr.Ns, hdr.Ttl))
		default:
			parts = append(parts, fmt.Sprintf("%s: %s (ttl=%d)", dns.TypeToString[hdr.Rrtype], hdr.Name, hdr.Ttl))
		}
	}

	if len(parts) == 0 {
		return "No Answer"
	}

	// Use | as a delimiter that we can split on in JS
	res := strings.Join(parts, "|")
	if len(res) > 2000 {
		res = res[:1997] + "..."
	}
	return res
}

func (h *Handler) getUpstreams(domain string, deviceRouteKey string) []string {
	var targetUpstreams []string
	var longestMatch string
	for d, ups := range h.UpstreamRoutes.DomainRoutes {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			if len(d) > len(longestMatch) {
				longestMatch = d
				targetUpstreams = ups
			}
		}
	}
	if len(targetUpstreams) == 0 {
		if ups, ok := h.UpstreamRoutes.DeviceRoutes[deviceRouteKey]; ok {
			targetUpstreams = ups
		}
	}
	if len(targetUpstreams) == 0 {
		targetUpstreams = h.Cfg.Upstreams.Default
	}
	return targetUpstreams
}

func (h *Handler) getActiveRuleGroups(d *config.Device) []string {
	if d == nil || len(d.RuleGroups) == 0 {
		return []string{"default"}
	}

	var target []string
	now := time.Now()
	for _, rg := range d.RuleGroups {
		active := true
		for _, s := range rg.Schedules {
			if s.IsActive(now) {
				active = false
				break
			}
		}
		if active {
			target = append(target, rg.Name)
		}
	}
	return target
}
