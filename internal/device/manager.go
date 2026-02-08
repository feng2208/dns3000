package device

import (
	"dns3000/internal/config"
	"sync"
	"time"
)

type ActiveDevice struct {
	IP         string    `json:"ip"`
	MAC        string    `json:"mac"`
	Name       string    `json:"name"`
	LastSeen   time.Time `json:"last_seen"`
	QueryCount int       `json:"query_count"`
}

type Manager struct {
	cfg           *config.Config
	devices       map[string]*config.Device // keyed by MAC
	devicesByIP   map[string]*config.Device // keyed by IP
	activeDevices map[string]*ActiveDevice  // keyed by IP
	mu            sync.RWMutex
}

func NewManager(cfg *config.Config) *Manager {
	m := &Manager{
		cfg:           cfg,
		devices:       make(map[string]*config.Device),
		devicesByIP:   make(map[string]*config.Device),
		activeDevices: make(map[string]*ActiveDevice),
	}
	for i := range cfg.Devices {
		d := &cfg.Devices[i]
		if d.MAC != "" {
			m.devices[d.MAC] = d
		}
		if d.IP != "" {
			m.devicesByIP[d.IP] = d
		}
	}
	return m
}

func (m *Manager) GetDeviceByMAC(mac string) *config.Device {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.devices[mac]
}

func (m *Manager) GetDeviceByIP(ip string) *config.Device {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.devicesByIP[ip]
}

// RecordActivity records a device's activity for the active devices list
func (m *Manager) RecordActivity(ip, mac, name string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := ip
	if mac != "" {
		key = mac
	}

	if ad, ok := m.activeDevices[key]; ok {
		ad.LastSeen = time.Now()
		ad.QueryCount++
		if mac != "" {
			ad.MAC = mac
		}
		// If entry was keyed by IP but we now have MAC, correct the content if needed?
		// Actually if key == mac, ad.MAC is redundant but fine.
		if name != "" && name != "Unknown" {
			ad.Name = name
		}
		// Update IP if it changed for this MAC
		if ip != "" {
			ad.IP = ip
		}
	} else {
		// Check if we have an old entry by IP that we should migrate or just delete?
		// If we are keying by MAC, we might have an old entry keyed by IP.
		// It's safer to remove the IP-keyed entry to avoid duplicates in the list.
		if mac != "" {
			delete(m.activeDevices, ip)
		}

		m.activeDevices[key] = &ActiveDevice{
			IP:         ip,
			MAC:        mac,
			Name:       name,
			LastSeen:   time.Now(),
			QueryCount: 1,
		}
	}
}

// GetActiveDevices returns all active devices seen in the last 24 hours
func (m *Manager) GetActiveDevices() []ActiveDevice {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cutoff := time.Now().Add(-24 * time.Hour)
	var result []ActiveDevice
	for _, ad := range m.activeDevices {
		if ad.LastSeen.After(cutoff) {
			result = append(result, *ad)
		}
	}
	return result
}

// GetMAC returns the MAC address for an IP, potentially using ARP.
func (m *Manager) GetMAC(ip string) (string, error) {
	return GetMAC(ip)
}

// Reload reloads devices from config
func (m *Manager) Reload(cfg *config.Config) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg = cfg
	m.devices = make(map[string]*config.Device)
	m.devicesByIP = make(map[string]*config.Device)
	for i := range m.cfg.Devices {
		d := &m.cfg.Devices[i]
		if d.MAC != "" {
			m.devices[d.MAC] = d
		}
		if d.IP != "" {
			m.devicesByIP[d.IP] = d
		}
	}

	// Refresh active devices metadata
	for _, ad := range m.activeDevices {
		// Reset name to "Unknown" or verify
		ad.Name = "Unknown"
		var d *config.Device
		if ad.MAC != "" {
			d = m.devices[ad.MAC]
		}
		if d == nil && ad.IP != "" {
			d = m.devicesByIP[ad.IP]
		}
		if d != nil {
			ad.Name = d.Name
		}
	}
}
