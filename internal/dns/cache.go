package dns

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

type CacheEntry struct {
	Msg       *dns.Msg
	ExpiresAt time.Time
	Status    string
}

const maxCacheEntries = 2000

type Cache struct {
	items map[string]CacheEntry
	mu    sync.RWMutex
}

func NewCache() *Cache {
	return &Cache{
		items: make(map[string]CacheEntry),
	}
}

func (c *Cache) Get(key string, group string) (*dns.Msg, string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	fullKey := key + ":" + group
	entry, ok := c.items[fullKey]
	if !ok {
		return nil, "", false
	}

	now := time.Now()
	if now.After(entry.ExpiresAt) {
		// ideally lazily delete?
		return nil, "", false
	}

	// Decrement TTL
	remaining := entry.ExpiresAt.Sub(now)
	msg := entry.Msg.Copy()

	// Update TTLs in records
	updateTTL(msg, remaining)

	return msg, entry.Status, true
}

func updateTTL(msg *dns.Msg, ttl time.Duration) {
	seconds := uint32(ttl.Seconds())
	for _, rr := range msg.Answer {
		rr.Header().Ttl = seconds
	}
	for _, rr := range msg.Ns {
		rr.Header().Ttl = seconds
	}
	for _, rr := range msg.Extra {
		rr.Header().Ttl = seconds
	}
}

// Set stores the message.
// isUpstream: true if from upstream (apply 20s-30m clamp), false if local/blocked (keep provided ttl).
func (c *Cache) Set(key string, group string, msg *dns.Msg, ttl time.Duration, isUpstream bool, status string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	finalTTL := ttl
	if isUpstream {
		// Clamp 20s - 30m
		if finalTTL < 20*time.Second {
			finalTTL = 20 * time.Second
		}
		if finalTTL > 30*time.Minute {
			finalTTL = 30 * time.Minute
		}
	} else {
		// Blocked/Rewritten: usually 30s
		if finalTTL == 0 {
			finalTTL = 30 * time.Second
		}
	}

	fullKey := key + ":" + group

	// Check if key already exists, if not, we might need to evict
	_, exists := c.items[fullKey]
	if !exists && len(c.items) >= maxCacheEntries {
		// Eviction Strategy:
		// 1. Remove all expired entries
		now := time.Now()
		for k, v := range c.items {
			if now.After(v.ExpiresAt) {
				delete(c.items, k)
			}
		}

		// 2. If still full, remove some random entries (approx 10%)
		// Map iteration in Go is random, so this naturally works.
		if len(c.items) >= maxCacheEntries {
			toRemove := maxCacheEntries / 10
			if toRemove == 0 {
				toRemove = 1
			}
			for k := range c.items {
				delete(c.items, k)
				toRemove--
				if toRemove <= 0 {
					break
				}
			}
		}
	}

	c.items[fullKey] = CacheEntry{
		Msg:       msg.Copy(),
		Status:    status,
		ExpiresAt: time.Now().Add(finalTTL),
	}
}
