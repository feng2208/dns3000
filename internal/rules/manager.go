package rules

import (
	"bufio"
	"dns3000/internal/config"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Manager struct {
	cfg          *config.Config
	dataDir      string
	engines      map[string]*Engine // Map rule group name to Engine
	lastSources  map[string][]config.Source
	lastServices map[string]string // Map service name to content hash or raw content
	client       *http.Client
	mu           sync.RWMutex
}

func NewManager(cfg *config.Config, dataDir string) *Manager {
	return &Manager{
		cfg:          cfg,
		dataDir:      dataDir,
		engines:      make(map[string]*Engine),
		lastSources:  make(map[string][]config.Source),
		lastServices: make(map[string]string),
		client: &http.Client{
			Timeout: 20 * time.Second,
		},
	}
}

func (m *Manager) Init() error {
	for _, rg := range m.cfg.RuleGroups {
		m.lastSources[rg.Name] = rg.Sources
		// Initial Load (forceUpdate=false means prefer cache)
		if err := m.reloadGroup(rg, false); err != nil {
			fmt.Printf("Error initializing rule group %s: %v\n", rg.Name, err)
		}
	}
	for _, svc := range m.cfg.Services {
		m.lastServices[svc.Name] = svc.Content
	}
	m.cleanupCache()
	return nil
}

func (m *Manager) Start() {
	go m.maintainRules()
}

func (m *Manager) maintainRules() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		for _, rg := range m.cfg.RuleGroups {
			m.checkGroupUpdate(rg)
		}
	}
}

func (m *Manager) checkGroupUpdate(rg config.RuleGroup) {
	interval := m.cfg.RuleUpdateInterval
	if interval == 0 {
		interval = 24 * time.Hour
	}

	needsUpdate := false
	ruleDir := filepath.Join(m.dataDir, "rules")

	for _, src := range rg.Sources {
		if src.URL == "" {
			continue
		}
		filename := filepath.Join(ruleDir, sanitizeFilename(src.Name)+".txt")
		info, err := os.Stat(filename)
		// If missing, we need update.
		// If present, check time.
		if os.IsNotExist(err) {
			needsUpdate = true
			break
		}
		if err == nil {
			if time.Since(info.ModTime()) > interval {
				needsUpdate = true
				break
			}
		}
	}

	if needsUpdate {
		// Reload with forceUpdate=true to download fresh
		if err := m.reloadGroup(rg, true); err != nil {
			fmt.Printf("Error updating rule group %s: %v\n", rg.Name, err)
		} else {
			fmt.Printf("Rule group %s updated.\n", rg.Name)
		}
	}
}

func (m *Manager) loadGroup(rg config.RuleGroup, forceUpdate bool) (*Engine, error) {
	engine := NewEngine()

	fmt.Printf("[%s] Loading rule group: %s\n", time.Now().Format("2006-01-02 15:04:05"), rg.Name)

	for _, src := range rg.Sources {
		if src.URL != "" {
			rules, err := m.loadOrFetchRule(src, forceUpdate)
			if err != nil {
				return nil, fmt.Errorf("source %s: %w", src.Name, err)
			}
			for _, r := range rules {
				engine.AddRule(r)
			}
			fmt.Printf("[%s]   Loaded source: %s (%d rules)\n", time.Now().Format("2006-01-02 15:04:05"), src.Name, len(rules))
		}
		if len(src.Services) > 0 {
			for _, svcName := range src.Services {
				var service *config.Service
				m.mu.RLock()
				for i := range m.cfg.Services {
					if m.cfg.Services[i].Name == svcName {
						service = &m.cfg.Services[i]
						break
					}
				}
				m.mu.RUnlock()
				if service != nil {
					rules := m.parseContent(service.Content)
					for _, r := range rules {
						engine.AddRule(r)
					}
					fmt.Printf("[%s]   Loaded service: %s (%d rules)\n", time.Now().Format("2006-01-02 15:04:05"), svcName, len(rules))
				}
			}
		}
	}

	fmt.Printf("\n")
	return engine, nil
}

func (m *Manager) reloadGroup(rg config.RuleGroup, forceUpdate bool) error {
	engine, err := m.loadGroup(rg, forceUpdate)
	if err != nil {
		return err
	}

	m.mu.Lock()
	m.engines[rg.Name] = engine
	m.mu.Unlock()
	return nil
}

func (m *Manager) Reload(cfg *config.Config) {
	m.mu.Lock()
	m.cfg = cfg

	// 1. Identify removed groups and cleanup
	newGroups := make(map[string]bool)
	for _, rg := range cfg.RuleGroups {
		newGroups[rg.Name] = true
	}
	for name := range m.engines {
		if !newGroups[name] {
			delete(m.engines, name)
			delete(m.lastSources, name)
		}
	}

	// Capture rule groups to check while we have the lock
	type groupToReload struct {
		rg         config.RuleGroup
		oldSources []config.Source
		exists     bool
	}

	// Identify changed services
	changedServices := make(map[string]bool)
	for _, svc := range cfg.Services {
		if oldContent, ok := m.lastServices[svc.Name]; !ok || oldContent != svc.Content {
			changedServices[svc.Name] = true
			m.lastServices[svc.Name] = svc.Content
		}
	}
	// Also check for deleted services (though less critical for reload unless used)
	for name := range m.lastServices {
		found := false
		for _, svc := range cfg.Services {
			if svc.Name == name {
				found = true
				break
			}
		}
		if !found {
			delete(m.lastServices, name)
		}
	}

	var reloadQueue []groupToReload
	for _, rg := range cfg.RuleGroups {
		oldSources, exists := m.lastSources[rg.Name]

		// Check if any source uses a changed service
		serviceChanged := false
		for _, src := range rg.Sources {
			for _, svcName := range src.Services {
				if changedServices[svcName] {
					serviceChanged = true
					break
				}
			}
			if serviceChanged {
				break
			}
		}

		if !exists || !m.sourcesEqual(oldSources, rg.Sources) || serviceChanged {
			reloadQueue = append(reloadQueue, groupToReload{rg: rg, oldSources: oldSources, exists: exists})
		}
	}
	m.mu.Unlock()

	// 2. Load rule groups concurrently outside the lock
	var wg sync.WaitGroup
	for _, item := range reloadQueue {
		wg.Add(1)
		go func(item groupToReload) {
			defer wg.Done()
			engine, err := m.loadGroup(item.rg, false)
			if err == nil {
				m.mu.Lock()
				m.engines[item.rg.Name] = engine
				m.lastSources[item.rg.Name] = item.rg.Sources
				m.mu.Unlock()
			} else {
				fmt.Printf("Error reloading rule group %s: %v\n", item.rg.Name, err)
			}
		}(item)
	}
	wg.Wait()

	m.cleanupCache()
}

func (m *Manager) sourcesEqual(a, b []config.Source) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || a[i].URL != b[i].URL {
			return false
		}
		if len(a[i].Services) != len(b[i].Services) {
			return false
		}
		for j := range a[i].Services {
			if a[i].Services[j] != b[i].Services[j] {
				return false
			}
		}
	}
	return true
}

func (m *Manager) cleanupCache() {
	ruleDir := filepath.Join(m.dataDir, "rules")
	files, err := os.ReadDir(ruleDir)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		fmt.Printf("Error reading rules directory for cleanup: %v\n", err)
		return
	}

	// Collect all active source filenames (lowercase for case-insensitive matching on Windows)
	activeFiles := make(map[string]bool)
	m.mu.RLock()
	for _, rg := range m.cfg.RuleGroups {
		for _, src := range rg.Sources {
			if src.URL != "" {
				fileName := sanitizeFilename(src.Name) + ".txt"
				activeFiles[strings.ToLower(fileName)] = true
			}
		}
	}
	m.mu.RUnlock()

	for _, f := range files {
		if f.IsDir() {
			continue
		}
		// Delete any file that is not in the active set.
		// This also cleans up legacy files without .txt extension.
		if !activeFiles[strings.ToLower(f.Name())] {
			filePath := filepath.Join(ruleDir, f.Name())
			if err := os.Remove(filePath); err != nil {
				fmt.Printf("Error deleting unused rule cache file %s: %v\n", f.Name(), err)
			} else {
				fmt.Printf("Deleted unused rule cache file: %s\n", f.Name())
			}
		}
	}
}

func (m *Manager) GetEngine(groupName string) *Engine {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.engines[groupName]
}

func (m *Manager) loadOrFetchRule(src config.Source, forceUpdate bool) ([]*Rule, error) {
	ruleDir := filepath.Join(m.dataDir, "rules")
	os.MkdirAll(ruleDir, 0755)
	filename := filepath.Join(ruleDir, sanitizeFilename(src.Name)+".txt")

	exists := false
	if _, err := os.Stat(filename); err == nil {
		exists = true
	}

	// Startup Logic: If exists and not forceUpdate, Use Cache (Ignore Age).
	// If forceUpdate (from maintainRules), Download.
	// If not exists, Must Download.

	shouldDownload := forceUpdate
	if !exists {
		shouldDownload = true
	}

	if shouldDownload {
		if err := m.downloadFile(src.URL, filename); err != nil {
			if !exists {
				return nil, err
			}
			// If download failed but exists, fallback to cache
			fmt.Printf("Warning: Failed to download %s, using local cache: %v\n", src.Name, err)
		}
	}

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var rules []*Rule
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if r, err := ParseRule(scanner.Text()); err == nil && r != nil {
			rules = append(rules, r)
		}
	}
	return rules, scanner.Err()
}

func (m *Manager) downloadFile(url, filepath string) error {
	fmt.Printf("Downloading rules from %s...\n", url)
	resp, err := m.client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func (m *Manager) parseContent(content string) []*Rule {
	var rules []*Rule
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		if r, err := ParseRule(scanner.Text()); err == nil && r != nil {
			rules = append(rules, r)
		}
	}
	return rules
}

func sanitizeFilename(name string) string {
	invalid := []string{"\\", "/", ":", "*", "?", "\"", "<", ">", "|"}
	res := name
	for _, char := range invalid {
		res = strings.ReplaceAll(res, char, "_")
	}
	return res
}
