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
	ClientIP  string
	ClientMAC string
	Protocol  string
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
	d, clientMac := h.identifyDevice(ctx)
	groupName, deviceName := h.getDeviceDetails(d, clientMac)

	// Record activity
	h.DeviceManager.RecordActivity(ctx.ClientIP, clientMac, deviceName)

	logEntry := logging.QueryLog{
		Time:       time.Now(),
		Domain:     domain,
		Type:       dns.TypeToString[q.Qtype],
		Protocol:   ctx.Protocol,
		DeviceIP:   ctx.ClientIP,
		DeviceName: deviceName,
		DeviceMAC:  clientMac,
	}

	// 2. Check Cache
	if h.checkCache(w, r, ctxKey, groupName, &logEntry) {
		return
	}

	// 3. Check Rewrites (Exact and Wildcard)
	if h.checkRewrites(w, r, domain, groupName, ctxKey, q, &logEntry) {
		return
	}

	// 4. Match Rules
	reqInfo := rules.RequestInfo{
		ClientIP:    ctx.ClientIP,
		ClientMAC:   clientMac,
		ClientName:  deviceName,
		DeviceGroup: groupName,
		Protocol:    ctx.Protocol,
		QType:       dns.TypeToString[q.Qtype],
		Domain:      domain,
	}

	blockRule, blockGroup := h.matchRuleGroups(domain, groupName, reqInfo)
	if blockRule != nil {
		h.handleBlock(w, r, blockRule, blockGroup, ctxKey, groupName, q, &logEntry)
		return
	}

	// 5. Forward to Upstream
	h.resolveUpstream(w, r, domain, groupName, ctxKey, &logEntry)
}

func (h *Handler) identifyDevice(ctx RequestContext) (*config.Device, string) {
	var d *config.Device
	mac := ctx.ClientMAC

	// 1. Try IP Lookup first
	if ctx.ClientIP != "" {
		d = h.DeviceManager.GetDeviceByIP(ctx.ClientIP)
	}

	// 2. If not found by IP, try MAC
	if d == nil {
		if mac != "" {
			d = h.DeviceManager.GetDeviceByMAC(mac)
		}
		if d == nil {
			// Try ARP
			if foundMac, err := h.DeviceManager.GetMAC(ctx.ClientIP); err == nil && foundMac != "" {
				mac = foundMac
				d = h.DeviceManager.GetDeviceByMAC(mac)
			}
		}
	} else if mac == "" && d.MAC != "" {
		// If found by IP and we don't have MAC yet, try to use MAC from config if available
		// This is just for context/logging consistency if needed, but not strictly required for lookup.
		mac = d.MAC
	}

	return d, mac
}

func (h *Handler) getDeviceDetails(d *config.Device, mac string) (string, string) {
	groupName := "default"
	deviceName := "Unknown"
	if d != nil {
		groupName = d.DeviceGroup
		deviceName = d.Name
	}
	return groupName, deviceName
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

func (h *Handler) checkRewrites(w dns.ResponseWriter, r *dns.Msg, domain, group, key string, q dns.Question, logEntry *logging.QueryLog) bool {
	rewriteVal := h.RewriteEngine.Match(domain)
	if rewriteVal == "" {
		return false
	}

	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	if IsIP(rewriteVal) {
		msg.Rcode = dns.RcodeSuccess
		if q.Qtype == dns.TypeA {
			rr, _ := dns.NewRR(fmt.Sprintf("%s 30 IN A %s", q.Name, rewriteVal))
			msg.Answer = append(msg.Answer, rr)
		} else if q.Qtype == dns.TypeAAAA {
			if ip := net.ParseIP(rewriteVal); ip != nil && ip.To4() == nil {
				rr, _ := dns.NewRR(fmt.Sprintf("%s 30 IN AAAA %s", q.Name, rewriteVal))
				msg.Answer = append(msg.Answer, rr)
			}
		}
		h.Cache.Set(key, group, msg, 30*time.Second, false, "Rewritten")
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
		h.Cache.Set(key, group, msg, 30*time.Second, false, "Rewritten")
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

func (h *Handler) matchRuleGroups(domain, groupName string, reqInfo rules.RequestInfo) (*rules.Rule, string) {
	activeRuleGroups := h.getActiveRuleGroups(groupName)
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

func (h *Handler) handleBlock(w dns.ResponseWriter, r *dns.Msg, rule *rules.Rule, groupName, key, deviceGroup string, q dns.Question, logEntry *logging.QueryLog) {
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

	h.Cache.Set(key, deviceGroup, msg, 30*time.Second, false, statusStr)
	w.WriteMsg(msg)

	logEntry.Status = statusStr
	logEntry.Rule = rule.Raw
	logEntry.RuleGroup = groupName
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
		h.Cache.Set(key, group, resp, time.Duration(minTTL)*time.Second, true, "Allowed")
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

func (h *Handler) getUpstreams(domain string, groupName string) []string {
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
		if ups, ok := h.UpstreamRoutes.GroupRoutes[groupName]; ok {
			targetUpstreams = ups
		}
	}
	if len(targetUpstreams) == 0 {
		targetUpstreams = h.Cfg.Upstreams.Default
	}
	return targetUpstreams
}

func (h *Handler) getActiveRuleGroups(groupName string) []string {
	var target []string
	// Find DeviceGroup in Config based on name
	for _, dg := range h.Cfg.DeviceGroups {
		if dg.Name == groupName {
			for _, rg := range dg.RuleGroups {
				active := true
				now := time.Now()
				for _, s := range rg.Schedules {
					if s.IsActive(now) {
						// Exclusion schedule
						// "If current time in schedule, group not effective"
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
	}
	// Fallback to default if group not found?
	return target
}
