package dns

import (
	"dns3000/internal/config"
	"net"
	"strings"
)

type RewriteEngine struct {
	Rewrites []config.Rewrite
}

func NewRewriteEngine(rewrites []config.Rewrite) *RewriteEngine {
	return &RewriteEngine{Rewrites: rewrites}
}

// Match returns the rewrite rule (value) if found.
// Returns empty string if no match.
func (e *RewriteEngine) Match(domain string) string {
	// Exact match priority? Or first match?
	// "rewrites: - name: example.com"

	// Normalize domain
	domain = strings.TrimSuffix(domain, ".")

	for _, r := range e.Rewrites {
		pattern := r.Name
		if pattern == domain {
			return r.Value
		}

		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[2:] // remove *.
			if strings.HasSuffix(domain, "."+suffix) {
				// e.g. *.example.com matches sub.example.com
				return r.Value
			}
		}
	}
	return ""
}

// IsIP checks if the value is an IP address
func IsIP(v string) bool {
	return net.ParseIP(v) != nil
}
