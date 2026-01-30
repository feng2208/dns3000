package rules

import (
	"fmt"
	"regexp"
	"strings"
)

type RuleType int

const (
	RuleTypeDomain RuleType = iota
	RuleTypeHosts
	RuleTypeRegex
)

type Rule struct {
	Type        RuleType
	Pattern     string
	IsWhitelist bool
	Modifiers   map[string]string
	IP          string // For hosts style
	Raw         string
	regex       *regexp.Regexp
}

func ParseRule(line string) (*Rule, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") {
		return nil, nil // Empty or comment
	}

	rule := &Rule{
		Raw:       line,
		Modifiers: make(map[string]string),
	}

	// 1. Parse Modifiers (at the end, starting with $)
	// Adblock syntax: rule $mod1,mod2=value
	// Handle cases where $ is inside regex?
	// If line starts with /, we check if $ is after the closing /.

	matchPart := line
	if idx := strings.LastIndex(line, "$"); idx != -1 {
		// Validation: Ensure $ is not inside a regex pattern "/.../"
		// Simple check: If it looks like regex, does the regex end before $?
		isRegex := strings.HasPrefix(line, "/")
		validModSeparator := true
		if isRegex {
			lastSlash := strings.LastIndex(line[:idx], "/")
			if lastSlash == 0 {
				// /foo$bar/ -> $ is part of regex
				validModSeparator = false
			}
		}

		if validModSeparator {
			modsStr := line[idx+1:]
			matchPart = strings.TrimSpace(line[:idx])

			parts := strings.Split(modsStr, ",")
			for _, p := range parts {
				kv := strings.SplitN(p, "=", 2)
				key := strings.TrimSpace(kv[0])
				val := ""
				if len(kv) > 1 {
					val = strings.TrimSpace(kv[1])
				}
				rule.Modifiers[key] = val
			}
		}
	}

	// 2. Check Whitelist (Start of match part)
	if strings.HasPrefix(matchPart, "@@") {
		rule.IsWhitelist = true
		matchPart = matchPart[2:]
	}

	// 3. Regex
	if strings.HasPrefix(matchPart, "/") && strings.HasSuffix(matchPart, "/") {
		rule.Type = RuleTypeRegex
		rule.Pattern = matchPart[1 : len(matchPart)-1]
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex: %w", err)
		}
		rule.regex = re
		return rule, nil
	}

	// 4. Hosts style: 1.2.3.4 example.org (Old syntax)
	// "1.2.3.4 example.org: (attention, old /etc/hosts-style syntax)"
	// "Blocks example.org domain but not its subdomains." (Note: Hosts usually exact match)
	// Check if starts with IP
	fields := strings.Fields(matchPart)
	if len(fields) >= 2 && !strings.HasPrefix(matchPart, "||") {
		// Verify first field is IP (simple heuristic)
		// Only if not standard adblock syntax
		// Example: "127.0.0.1 example.org"
		if !strings.Contains(fields[0], "*") && !strings.Contains(fields[0], "/") {
			rule.Type = RuleTypeHosts
			rule.IP = fields[0]
			rule.Pattern = fields[1]
			return rule, nil
		}
	}

	// 5. Check for regex-like patterns:
	//    - |example.org (starts with single |)
	//    - example.org| (ends with |)
	//    - patterns containing wildcard * (e.g., *mple.org, ex*mple.org, ||*example^)
	if (strings.HasPrefix(matchPart, "|") && !strings.HasPrefix(matchPart, "||")) ||
		strings.HasSuffix(matchPart, "|") ||
		strings.Contains(matchPart, "*") {
		rule.Type = RuleTypeRegex
		// Convert to regex pattern
		pattern := matchPart
		isPrefix := strings.HasPrefix(pattern, "|") && !strings.HasPrefix(pattern, "||") && !strings.HasSuffix(pattern, "|")
		isSuffix := strings.HasSuffix(pattern, "|") && !strings.HasPrefix(pattern, "|")
		// Remove leading || or |
		if strings.HasPrefix(pattern, "||") {
			pattern = pattern[2:]
		} else if strings.HasPrefix(pattern, "|") {
			pattern = pattern[1:]
		}
		// Remove trailing | or ^
		pattern = strings.TrimSuffix(pattern, "|")
		pattern = strings.TrimSuffix(pattern, "^")
		// Escape regex special chars except *
		pattern = regexp.QuoteMeta(pattern)
		// Convert * wildcard to regex .*
		pattern = strings.ReplaceAll(pattern, `\*`, ".*")
		// Add anchors based on pattern type
		if isPrefix {
			// |example -> ^example
			rule.Pattern = "^" + pattern
		} else if isSuffix {
			// example| -> example$
			rule.Pattern = pattern + "$"
		} else {
			// ||*example^ -> .*example$
			rule.Pattern = pattern + "$"
		}
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex: %w", err)
		}
		rule.regex = re
		return rule, nil
	}

	// 6. Standard Adblock (||example.org^)
	// "||example.org^: block access to the example.org domain and all its subdomains"
	if strings.HasPrefix(matchPart, "||") {
		rule.Type = RuleTypeDomain
		rule.Pattern = strings.TrimPrefix(matchPart, "||")
		rule.Pattern = strings.TrimSuffix(rule.Pattern, "^")
		return rule, nil
	}

	// 7. Simple domain rule (example.org or example.org^)
	// Treat as hosts style with IP 0.0.0.0
	rule.Type = RuleTypeHosts
	rule.IP = "0.0.0.0"
	rule.Pattern = strings.TrimSuffix(matchPart, "^")

	return rule, nil
}
