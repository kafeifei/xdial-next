package daemon

import (
	"bufio"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// The event log, ARCHITECTURE.md 6.5: one JSON line per event, rotated at
// 10 MB with three files kept.
const (
	maxLogSize  = 10 << 20
	keptLogs    = 3
	recentLines = 200
)

// Event is one line of the log. Fields never carry secret values.
type Event struct {
	Time   time.Time      `json:"time"`
	Type   string         `json:"type"`
	Fields map[string]any `json:"fields,omitempty"`
}

type eventLog struct {
	path string
	mu   sync.Mutex
	subs map[chan Event]struct{}
}

func newEventLog(path string) *eventLog {
	return &eventLog{path: path, subs: map[chan Event]struct{}{}}
}

func (l *eventLog) add(typ string, fields map[string]any) {
	e := Event{Time: time.Now().UTC(), Type: typ, Fields: fields}
	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	appendRotating(l.path, append(line, '\n'))
	for ch := range l.subs {
		select {
		case ch <- e:
		default: // a slow reader misses events rather than stall the daemon
		}
	}
}

// recent returns up to n of the latest events.
func (l *eventLog) recent(n int) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.Open(l.path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var all []Event
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		var e Event
		if json.Unmarshal(scanner.Bytes(), &e) == nil {
			all = append(all, e)
			if len(all) > 4*n {
				all = all[len(all)-n:]
			}
		}
	}
	if len(all) > n {
		all = all[len(all)-n:]
	}
	return all
}

func (l *eventLog) subscribe() chan Event {
	ch := make(chan Event, 64)
	l.mu.Lock()
	l.subs[ch] = struct{}{}
	l.mu.Unlock()
	return ch
}

func (l *eventLog) unsubscribe(ch chan Event) {
	l.mu.Lock()
	delete(l.subs, ch)
	l.mu.Unlock()
}

// appendRotating appends to path, rotating path to path.1 … path.N first
// when it would grow past maxLogSize. Files are root-only.
func appendRotating(path string, data []byte) {
	if info, err := os.Stat(path); err == nil && info.Size()+int64(len(data)) > maxLogSize {
		for i := keptLogs - 1; i >= 1; i-- {
			_ = os.Rename(rotated(path, i), rotated(path, i+1))
		}
		_ = os.Rename(path, rotated(path, 1))
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return
	}
	_, _ = f.Write(data)
	_ = f.Close()
}

func rotated(path string, i int) string { return path + "." + string(rune('0'+i)) }
