package device

import (
	"dns3000/internal/config"
	"sync"
	"time"
)

type ActiveDevice struct {
	IP         string    `json:"ip"`
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	LastSeen   time.Time `json:"last_seen"`
	QueryCount int       `json:"query_count"`
}

type Manager struct {
	cfg           *config.Config
	devices       map[string]*config.Device // keyed by ID
	devicesByIP   map[string]*config.Device // keyed by IP
	activeDevices map[string]*ActiveDevice  // keyed by ID when present, otherwise IP
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
		if d.ID != "" {
			m.devices[d.ID] = d
		}
		if d.IP != "" {
			m.devicesByIP[d.IP] = d
		}
	}
	return m
}

func (m *Manager) GetDeviceByID(id string) *config.Device {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.devices[id]
}

func (m *Manager) GetDeviceByIP(ip string) *config.Device {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.devicesByIP[ip]
}

// RecordActivity records a device's activity for the active devices list
func (m *Manager) RecordActivity(ip, id, name string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := ip
	if id != "" {
		key = id
	}

	if ad, ok := m.activeDevices[key]; ok {
		ad.LastSeen = time.Now()
		ad.QueryCount++
		if id != "" {
			ad.ID = id
		}
		if name != "" && name != "Unknown" {
			ad.Name = name
		}
		if ip != "" {
			ad.IP = ip
		}
	} else {
		if id != "" {
			delete(m.activeDevices, ip)
		}

		m.activeDevices[key] = &ActiveDevice{
			IP:         ip,
			ID:         id,
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

func (m *Manager) Reload(cfg *config.Config) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg = cfg
	m.devices = make(map[string]*config.Device)
	m.devicesByIP = make(map[string]*config.Device)
	for i := range m.cfg.Devices {
		d := &m.cfg.Devices[i]
		if d.ID != "" {
			m.devices[d.ID] = d
		}
		if d.IP != "" {
			m.devicesByIP[d.IP] = d
		}
	}

	// Refresh active device names from the latest config.
	for _, ad := range m.activeDevices {
		ad.Name = "Unknown"
		var d *config.Device
		if ad.ID != "" {
			d = m.devices[ad.ID]
		}
		if d == nil && ad.IP != "" {
			d = m.devicesByIP[ad.IP]
		}
		if d != nil {
			ad.Name = d.Name
		}
	}
}
