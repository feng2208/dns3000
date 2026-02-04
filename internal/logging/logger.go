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

// QueryStats tracks query statistics using atomic counters
type QueryStats struct {
	TotalQueries int64 `json:"total_queries"`
	Blocked      int64 `json:"blocked"`
	Allowed      int64 `json:"allowed"`
	Rewritten    int64 `json:"rewritten"`
}

type Logger struct {
	mu    sync.RWMutex
	logs  []QueryLog
	limit int
	stats QueryStats
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

	// Update stats
	l.stats.TotalQueries++
	switch entry.Status {
	case "Blocked":
		l.stats.Blocked++
	case "Allowed":
		l.stats.Allowed++
	case "Rewritten":
		l.stats.Rewritten++
	}
}

func (l *Logger) GetStats() QueryStats {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.stats
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

	// Return in reverse order for UI (newest first)
	// The logs are stored oldest to newest (append).
	// So we need to fetch from the end.
	// Filter logic in web.go seems to handle its own filtering and paging from the slice returned here?
	// Wait, web.go calls GetLogs(0, 10000) then filters.
	// The existing GetLogs implementation (which I am replacing/modifying above partially) was:
	// result := make([]QueryLog, end-offset)
	// copy(result, l.logs[offset:end])
	//
	// It returned a slice of the internal logs. internal logs are appended (oldest first).
	// web.go iterates `for i := len(allLogs) - 1; i >= 0; i--` which implies it handles reverse order.
	// So I should keep GetLogs returning the slice as is, or maybe just leave it alone if I don't need to change it.
	// I'll keep GetLogs as it was, just ensure my replacement block connects correctly.

	result := make([]QueryLog, end-offset)
	copy(result, l.logs[offset:end])
	return result
}

func (l *Logger) LoadStats(filePath string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	f, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	return json.NewDecoder(f).Decode(&l.stats)
}

func (l *Logger) SaveStats(filePath string) error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	return json.NewEncoder(f).Encode(l.stats)
}
