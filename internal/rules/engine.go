package rules

import (
	"net"
	"strings"
	"sync"
)

type Engine struct {
	mu         sync.RWMutex
	trie       *Trie
	regexRules []*Rule
	hostsRules map[string]string // domain -> ip
}

func NewEngine() *Engine {
	return &Engine{
		trie:       NewTrie(),
		regexRules: make([]*Rule, 0),
		hostsRules: make(map[string]string),
	}
}

func (e *Engine) AddRule(r *Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()

	switch r.Type {
	case RuleTypeDomain:
		e.trie.Insert(r)
	case RuleTypeHosts:
		e.hostsRules[r.Pattern] = r.IP
	case RuleTypeRegex:
		e.regexRules = append(e.regexRules, r)
	}
}

// matchContext for Trie if needed, currently Engine handles modifiers after Match?
// The Trie only returns the raw Rule match pattern. Engine checks modifiers.
// Wait, if Trie returns a rule but modifiers fail, should we fallback to a less specific rule?
// For correct logic: Yes.
// E.g. ||example.com^$client=1.2.3.4
// Query from 5.6.7.8. Trie matches ||example.com. Modifiers fail.
// Should we return nil? Or check if there is a match on `com`?
// AdGuard logic: If a rule matches pattern but modifiers exclude it, the rule is unresponsive.
// We should continue searching?
//
// Refined Logic (Implemented in next step if necessary, for now keep simple):
// Current Engine.Match returns *Rule.
// We should probably move modifier check INTO the Trie traversal or allow retrieving ALL matches.
// For now, let's keep the Trie logic simple: return Best Match.
// NOTE: This might be a semantic change if we have multiple rules on the path and the specific one fails modifiers.

// RequestInfo context for matching
type RequestInfo struct {
	Domain      string // Queried domain
	ClientIP    string
	ClientMAC   string
	ClientName  string
	DeviceGroup string
	Protocol    string
	QType       string // A, AAAA, etc.
}

// Match returns the matching rule
func (e *Engine) Match(domain string, info RequestInfo) *Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	domain = strings.TrimSuffix(domain, ".")

	// 1. Check Hosts (Exact)
	if ip, ok := e.hostsRules[domain]; ok {
		return &Rule{Type: RuleTypeHosts, Pattern: domain, IP: ip}
	}

	// 2. Collect Candidates
	var candidates []*Rule

	// Trie Matches
	candidates = append(candidates, e.trie.MatchAll(domain)...)

	// Regex Matches
	for _, r := range e.regexRules {
		if r.regex.MatchString(domain) {
			candidates = append(candidates, r)
		}
	}

	// 3. Select Best Rule
	// Priority:
	// 1. Important Block
	// 2. Whitelist
	// 3. Block
	//
	// Tie-breaking:
	// 1. Client Specificity (Exact > CIDR > Generic)
	// 2. Domain Specificity (Implicit by processing order: Child overrides Parent if scores equal)

	var bestImportantBlock *Rule
	var bestImportantScore int

	var bestWhitelist *Rule
	var bestWhitelistScore int

	var bestBlock *Rule
	var bestBlockScore int

	for _, r := range candidates {
		matched, score := e.checkModifiers(r, info)
		if !matched {
			continue
		}

		if r.IsWhitelist {
			// Whitelist Logic
			if bestWhitelist == nil || score >= bestWhitelistScore {
				bestWhitelist = r
				bestWhitelistScore = score
			}
		} else {
			// Block/Rewrite Logic
			isImportant := false
			if _, ok := r.Modifiers["important"]; ok {
				isImportant = true
			}

			if isImportant {
				if bestImportantBlock == nil || score >= bestImportantScore {
					bestImportantBlock = r
					bestImportantScore = score
				}
			} else {
				if bestBlock == nil || score >= bestBlockScore {
					bestBlock = r
					bestBlockScore = score
				}
			}
		}
	}

	// Apply Precedence
	if bestImportantBlock != nil {
		return bestImportantBlock
	}
	if bestWhitelist != nil {
		return bestWhitelist
	}
	return bestBlock
}

// checkModifiers returns matched bool and a specificity score.
// Score:
// 0: Generic match (no client modifier)
// 1000: Exact Client IP/MAC match
// 1-128: CIDR match (Mask size, larger is more specific) (for IPv4 max 32, IPv6 128)
func (e *Engine) checkModifiers(r *Rule, info RequestInfo) (bool, int) {
	if len(r.Modifiers) == 0 {
		return true, 0
	}

	score := 0

	// 1. client
	// client=IP,name,MAC... | ~client (negation)
	if val, ok := r.Modifiers["client"]; ok {
		// Support multiple values separated by |
		parts := strings.Split(val, "|")

		matched := false
		hasPositive := false
		maxPartScore := 0

		for _, p := range parts {
			p = strings.TrimSpace(p)
			negate := strings.HasPrefix(p, "~")
			target := p
			if negate {
				target = target[1:]
			} else {
				hasPositive = true
			}

			// Check match
			var isMatch bool
			var currentScore int

			// 1. Exact match
			if target == info.ClientIP || target == info.ClientMAC || target == info.ClientName {
				isMatch = true
				currentScore = 1000
			} else if strings.Contains(target, "/") {
				// 2. CIDR match
				_, ipNet, err := net.ParseCIDR(target)
				if err == nil {
					clientIP := net.ParseIP(info.ClientIP)
					if clientIP != nil && ipNet.Contains(clientIP) {
						isMatch = true
						ones, _ := ipNet.Mask.Size()
						currentScore = ones
					}
				}
			}

			if isMatch {
				if negate {
					return false, 0 // Explicitly excluded
				}
				matched = true
				if currentScore > maxPartScore {
					maxPartScore = currentScore
				}
			}
		}

		// If we have positive requirements and none matched, return false
		if hasPositive && !matched {
			return false, 0
		}

		// If only negative requirements existed (e.g. ~1.2.3.4), and we didn't return false above,
		// it means we are allowed (implicit allow for others).
		// In that case, we use the accumulated score (which is 0).
		score = maxPartScore
	}

	// 2. denyallow
	// $denyallow=domain1|domain2
	if val, ok := r.Modifiers["denyallow"]; ok {
		parts := strings.Split(val, "|")
		for _, d := range parts {
			d = strings.TrimSpace(d)
			if info.Domain == d || strings.HasSuffix(info.Domain, "."+d) {
				return false, 0
			}
		}
	}

	// 3. dnstype
	// $dnstype=A|AAAA
	if val, ok := r.Modifiers["dnstype"]; ok {
		if !strings.EqualFold(val, info.QType) && !strings.Contains(strings.ToUpper(val), info.QType) {
			return false, 0
		}
	}

	return true, score
}
