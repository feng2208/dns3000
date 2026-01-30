package rules

import (
	"strings"
	"sync"
)

type node struct {
	children map[string]*node
	rules    []*Rule // Support multiple rules at this node
}

func newNode() *node {
	return &node{
		children: make(map[string]*node),
		rules:    make([]*Rule, 0),
	}
}

type Trie struct {
	root *node
	mu   sync.RWMutex
}

func NewTrie() *Trie {
	return &Trie{
		root: newNode(),
	}
}

// Insert adds a rule to the Trie.
func (t *Trie) Insert(rule *Rule) {
	t.mu.Lock()
	defer t.mu.Unlock()

	domain := rule.Pattern
	// Normalize: remove trailing dot if present
	domain = strings.TrimSuffix(domain, ".")

	parts := strings.Split(domain, ".")

	n := t.root
	// Iterate in reverse (com -> example)
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if _, ok := n.children[part]; !ok {
			n.children[part] = newNode()
		}
		n = n.children[part]
	}

	// Append rule to list
	n.rules = append(n.rules, rule)
}

// MatchAll returns ALL rules found along the path from root to the most specific match.
// Logic:
// We traverse based on the domain parts.
// At each node (representing a domain part), we might have rules (e.g., '.com', 'example.com').
// We collect ALL of them.
// High-level priority logic belongs in the caller (Engine).
func (t *Trie) MatchAll(domain string) []*Rule {
	t.mu.RLock()
	defer t.mu.RUnlock()

	domain = strings.TrimSuffix(domain, ".")
	var rulesFound []*Rule

	n := t.root

	// Split parts. "a.b.c" -> ["a", "b", "c"]
	// We matched in reverse during insert.
	// We need to walk the input domain from TLD up.

	// Wait, splitting manually is tedious.
	// Let's use the same logic as Match: iterative from end.

	// 1. Root rules (usually none, or global wildcard?)
	if len(n.rules) > 0 {
		rulesFound = append(rulesFound, n.rules...)
	}

	end := len(domain)
	for end > 0 {
		start := strings.LastIndexByte(domain[:end], '.')
		label := domain[start+1 : end]

		next, ok := n.children[label]
		if !ok {
			break
		}
		n = next

		if len(n.rules) > 0 {
			rulesFound = append(rulesFound, n.rules...)
		}

		end = start
	}

	return rulesFound
}
