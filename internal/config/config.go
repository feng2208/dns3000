package config

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Upstreams          UpstreamsConfig `yaml:"upstreams" json:"upstreams"`
	Devices            []Device        `yaml:"devices" json:"devices"`
	DeviceGroups       []DeviceGroup   `yaml:"device_groups" json:"device_groups"`
	RuleGroups         []RuleGroup     `yaml:"rule_groups" json:"rule_groups"`
	Services           []Service       `yaml:"services" json:"services"`
	Rewrites           []Rewrite       `yaml:"rewrites" json:"rewrites"`
	LogCount           int             `yaml:"log_count" json:"log_count"`
	RuleUpdateInterval time.Duration   `yaml:"rule_update_interval" json:"rule_update_interval"`
	Auth               AuthConfig      `yaml:"auth" json:"auth"`
}

type AuthConfig struct {
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"password"` // SHA256 Hash
}

type UpstreamsConfig struct {
	Default []string `yaml:"default" json:"default"`
	Rules   []string `yaml:"rules" json:"rules"` // Parsed later: [/domain/]upstream or [device-group]upstream
}

type Device struct {
	Name        string `yaml:"name" json:"name"`
	IP          string `yaml:"ip" json:"ip"`
	MAC         string `yaml:"mac" json:"mac"`
	DeviceGroup string `yaml:"device_group" json:"device_group"`
}

type DeviceGroup struct {
	Name       string                 `yaml:"name" json:"name"`
	RuleGroups []DeviceGroupRuleGroup `yaml:"rule_groups" json:"rule_groups"`
}

type DeviceGroupRuleGroup struct {
	Name      string     `yaml:"name" json:"name"`
	Schedules []Schedule `yaml:"schedules" json:"schedules"`
}

type Schedule struct {
	Days   []string `yaml:"days" json:"days"`     // Mon, Tue, ...
	Ranges []string `yaml:"ranges" json:"ranges"` // 10:00-12:30
}

func (s *Schedule) IsActive(t time.Time) bool {
	// Check Day
	weekday := t.Weekday().String() // "Monday", etc.
	dayMatch := false
	if len(s.Days) == 0 {
		dayMatch = true
	} else {
		shortDay := weekday[:3] // "Mon"
		for _, d := range s.Days {
			if d == shortDay {
				dayMatch = true
				break
			}
		}
	}
	if !dayMatch {
		return false
	}

	// Check Time Range
	if len(s.Ranges) == 0 {
		return true
	}

	currentStr := t.Format("15:04")
	for _, r := range s.Ranges {
		parts := strings.Split(r, "-")
		if len(parts) != 2 {
			continue
		}
		start, end := parts[0], parts[1]
		// Simple string comparison works for 24h format
		if currentStr >= start && currentStr <= end {
			return true
		}
	}
	return false
}

type RuleGroup struct {
	Name    string   `yaml:"name" json:"name"`
	Sources []Source `yaml:"sources" json:"sources"`
}

type Source struct {
	Name     string   `yaml:"name" json:"name"`
	URL      string   `yaml:"url,omitempty" json:"url,omitempty"`
	Services []string `yaml:"services,omitempty" json:"services,omitempty"` // Names of services
}

type Service struct {
	Name    string `yaml:"name" json:"name"`
	Type    string `yaml:"type" json:"type"` // e.g., game
	Content string `yaml:"content" json:"content"`
}

type Rewrite struct {
	Name  string `yaml:"name" json:"name"`
	Value string `yaml:"value" json:"value"`
}

func Load(dir string) (*Config, error) {
	configPath := filepath.Join(dir, "config.yaml")
	data, err := os.ReadFile(configPath)
	if os.IsNotExist(err) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	// Set default log count if 0 (though 0 might be valid, requirement says default 5000)
	if cfg.LogCount == 0 {
		cfg.LogCount = 5000
	}
	// Set default rule update interval to 24 hours if not set
	if cfg.RuleUpdateInterval == 0 {
		cfg.RuleUpdateInterval = 24 * time.Hour
	}
	return &cfg, nil
}

func GenerateTemplate(dir string) error {
	configPath := filepath.Join(dir, "config.yaml")

	// Ensure directory exists
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	if _, err := os.Stat(configPath); err == nil {
		return nil // File exists, do not overwrite
	}

	// Requirement 0 Template
	template := `upstreams:
  default:
    # 默认 dns
    - 1.0.0.1 
    - 8.8.8.8

device_groups:
  - name: default
`
	return os.WriteFile(configPath, []byte(template), 0644)
}

func (c *Config) Save(dir string) error {
	configPath := filepath.Join(dir, "config.yaml")
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, data, 0644)
}

type UpstreamRoute struct {
	DomainRoutes map[string][]string
	GroupRoutes  map[string][]string
}

func (c *Config) ParseUpstreamRoutes() *UpstreamRoute {
	routes := &UpstreamRoute{
		DomainRoutes: make(map[string][]string),
		GroupRoutes:  make(map[string][]string),
	}

	for _, rule := range c.Upstreams.Rules {
		rule = strings.TrimSpace(rule)
		if rule == "" {
			continue
		}

		// Domain Rule: [/example.com/]upstream
		if strings.HasPrefix(rule, "[/") {
			endIdx := strings.Index(rule, "/]")
			if endIdx != -1 {
				domain := rule[2:endIdx]
				upstreamPart := strings.TrimSpace(rule[endIdx+2:])
				upstreams := strings.Fields(upstreamPart)
				routes.DomainRoutes[domain] = upstreams
			}
			continue
		}

		// Device Group Rule: [group]upstream
		if strings.HasPrefix(rule, "[") {
			endIdx := strings.Index(rule, "]")
			if endIdx != -1 {
				group := rule[1:endIdx]
				upstreamPart := strings.TrimSpace(rule[endIdx+1:])
				upstreams := strings.Fields(upstreamPart)
				routes.GroupRoutes[group] = upstreams
			}
			continue
		}
	}
	return routes
}
