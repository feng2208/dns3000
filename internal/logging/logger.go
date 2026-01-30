package logging

import (
	"bufio"
	"encoding/json"
	"os"
	"sync"
	"time"
)

type QueryLog struct {
	Time       time.Time `json:"time"`
	Domain     string    `json:"domain"`
	Type       string    `json:"type"`     // A, AAAA, etc
	Protocol   string    `json:"protocol"` // udp, tcp, doh
	Status     string    `json:"status"`   // Blocked, Allowed, Rewritten
	RuleGroup  string    `json:"rule_group,omitempty"`
	Rule       string    `json:"rule,omitempty"`
	DeviceIP   string    `json:"device_ip"`
	DeviceName string    `json:"device_name"`
	DeviceMAC  string    `json:"device_mac"`
	Upstream   string    `json:"upstream,omitempty"`
	Response   string    `json:"response,omitempty"` // Short summary
	LatencyMs  float64   `json:"latency_ms"`
}

type Logger struct {
	mu    sync.RWMutex
	logs  []QueryLog
	limit int
}

func NewLogger(filePath string, limit int) (*Logger, error) {
	l := &Logger{
		logs:  make([]QueryLog, 0, limit),
		limit: limit,
	}

	// Load existing logs
	l.LoadLogs(filePath)

	return l, nil
}

func (l *Logger) LoadLogs(filePath string) {
	f, err := os.Open(filePath)
	if err != nil {
		return // File missing or error, start empty
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var loaded []QueryLog
	for scanner.Scan() {
		var entry QueryLog
		if err := json.Unmarshal(scanner.Bytes(), &entry); err == nil {
			loaded = append(loaded, entry)
		}
	}

	// Prune if too many
	if len(loaded) > l.limit {
		loaded = loaded[len(loaded)-l.limit:]
	}
	l.logs = loaded
}

func (l *Logger) SaveLogs(filePath string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Write all logs to file
	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	for _, entry := range l.logs {
		if err := encoder.Encode(entry); err != nil {
			// log error?
		}
	}
	return nil
}

func (l *Logger) Log(entry QueryLog) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Append to memory only, disk write happens on shutdown
	if len(l.logs) >= l.limit {
		l.logs = l.logs[1:]
	}
	l.logs = append(l.logs, entry)
}

func (l *Logger) GetLogs(offset, count int) []QueryLog {
	l.mu.RLock()
	defer l.mu.RUnlock()

	total := len(l.logs)
	if offset >= total {
		return []QueryLog{}
	}
	end := offset + count
	if end > total {
		end = total
	}

	// Return in reverse order? Usually UI wants newest first.
	// Let's copy and reverse or handle in UI.
	// Returning slice: beware of concurrency if caller modifies?
	// Copying is safer.
	result := make([]QueryLog, end-offset)
	copy(result, l.logs[offset:end])
	return result
}
