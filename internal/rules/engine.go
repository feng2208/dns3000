package rules

import (
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
		// Hosts matches are blocking/rewrite by definition?
		// "Blocks example.com by responding with ..."
		// Usually hosts files are basic blocking or redirections.
		// Lets treat as a basic Block/Rewrite rule.
		// Can they be whitelisted?
		// AdGuard/Hosts usually implies simple static mapping.
		// But in this architecture, we might want to allow whitelisting even hosts?
		// For now, return immediately to be safe/fast, or treat as a candidate?
		// User requirement 1.2.3.4 example.org -> respond with 1.2.3.4
		// 0.0.0.0 example.com -> Block
		// Let's assume high priority for hosts rules, but subject to Whitelist?
		// Currently `hostsRules` is a simple map.
		// Let's keep existing behavior: Hosts wins immediately (or treat as specific block).
		// Given they are "Basic examples", let's return immediately.
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

	// 3. Filter Candidates by Modifiers
	var validRules []*Rule
	for _, r := range candidates {
		if e.checkModifiers(r, info) {
			validRules = append(validRules, r)
		}
	}

	if len(validRules) == 0 {
		return nil
	}

	// 4. Select Best Rule
	// Priority:
	// 1. Important Block (disables whitelist)
	// 2. Whitelist (disables normal block)
	// 3. Block

	var bestImportantBlock *Rule
	var bestWhitelist *Rule
	var bestBlock *Rule

	// Iterate in reverse to find "most specific" first?
	// Trie returns [Root ... Leaf]. Last is most specific.
	// We want the most specific matching rule of each type.
	// So iterating forwards update "bestX" will leave us with the last (most specific).

	for _, r := range validRules {
		if r.IsWhitelist {
			bestWhitelist = r
		} else {
			// Blocking rule
			if _, important := r.Modifiers["important"]; important {
				bestImportantBlock = r
			}
			bestBlock = r
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

func (e *Engine) checkModifiers(r *Rule, info RequestInfo) bool {
	if len(r.Modifiers) == 0 {
		return true
	}

	// 1. client
	// client=IP,name,MAC... | ~client (negation)
	if val, ok := r.Modifiers["client"]; ok {
		// Support multiple values separated by |
		parts := strings.Split(val, "|")

		matched := false
		hasPositive := false

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
			isMatch := (target == info.ClientIP || target == info.ClientMAC || target == info.ClientName)

			if isMatch {
				if negate {
					return false // Explicitly excluded
				}
				matched = true
			}
		}

		// If we have positive requirements and none matched, return false
		if hasPositive && !matched {
			return false
		}
		// If only negative requirements existed (e.g. ~1.2.3.4), and we didn't return false above,
		// it means we are allowed (implicit allow for others).
	}

	// 2. denyallow
	// $denyallow=domain1|domain2
	// If request domain matches any in list, rule does NOT match.
	if val, ok := r.Modifiers["denyallow"]; ok {
		parts := strings.Split(val, "|")
		for _, d := range parts {
			d = strings.TrimSpace(d)
			// Exact match or subdomain?
			// "If a domain matches the rule pattern but is also present in the denyallow list"
			// Usually denyallow implies exact matching of the exclusion?
			// AdGuard docs: "ex: ||example.com^$denyallow=sub.example.com"
			// If query is sub.example.com -> denied by rule? No, ALLOWED by ignore.
			// Matching: domain == d or domain.HasSuffix("."+d) ?
			// Usually it's domain matching logic.
			// Let's assume exact match for simplicity as per common adblock logic usage,
			// potentially suffix if d starts with dot?
			// AdGuard implementation uses similar matching logic to rules.
			// Let's do exact match + check if d is suffix?
			// "sub.example.com" in denyallow matches "sub.example.com".
			if info.Domain == d || strings.HasSuffix(info.Domain, "."+d) {
				return false
			}
		}
	}

	// 3. dnstype
	// $dnstype=A|AAAA
	if val, ok := r.Modifiers["dnstype"]; ok {
		// e.g. A
		// If rule says $dnstype=aaaa, and query is A, skip
		if !strings.EqualFold(val, info.QType) && !strings.Contains(strings.ToUpper(val), info.QType) {
			// Simple string check; Robust would parse `|`
			return false
		}
	}

	// 3. important (handled by priority logic in Handler, usually)
	// But engine just returns Match. Handler decides if Whitelist overrides Block.
	// If this rule is Important Block, it might override Whitelist?
	// AdGuard: Important rules > Whitelist > Block.

	return true
}
