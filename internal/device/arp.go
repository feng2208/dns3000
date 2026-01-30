package device

import (
	"sync"
	"time"
)

var (
	arpCache   sync.Map // map[string]arpEntry
	arpMu      sync.Mutex
	lastUpdate time.Time
)

type arpEntry struct {
	mac       string
	expiresAt time.Time
}

// GetMAC returns the MAC address for the given IP.
// It uses a local cache which is refreshed periodically (e.g. every 1 minute).
func GetMAC(ip string) (string, error) {
	// 1. Try Cache
	if v, ok := arpCache.Load(ip); ok {
		entry := v.(arpEntry)
		if time.Now().Before(entry.expiresAt) {
			return entry.mac, nil
		}
	}

	// 2. Refresh needed?
	arpMu.Lock()
	defer arpMu.Unlock()

	// Double check
	if v, ok := arpCache.Load(ip); ok {
		entry := v.(arpEntry)
		// If another goroutine refreshed it
		if time.Now().Before(entry.expiresAt) {
			return entry.mac, nil
		}
	}

	// Throttle updates (don't update more than once every 5 seconds even if cache miss)
	// But if we missed, we probably need it.
	// Actually, limit global table refresh to 1 minute as planned?
	// If specific IP is missing, maybe it's not in ARP yet.
	// Let's force update if > 5 seconds passed since last update.
	if time.Since(lastUpdate) > 5*time.Second {
		if err := refreshARPTable(); err != nil {
			return "", err
		}
		lastUpdate = time.Now()
	}

	// 3. Retry Cache
	if v, ok := arpCache.Load(ip); ok {
		entry := v.(arpEntry)
		return entry.mac, nil
	}

	return "", nil
}

// storeARPEntry is used by platform specific code to populate cache
func storeARPEntry(ip, mac string) {
	arpCache.Store(ip, arpEntry{
		mac:       mac,
		expiresAt: time.Now().Add(1 * time.Minute),
	})
}
