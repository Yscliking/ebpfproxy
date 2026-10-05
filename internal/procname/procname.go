// Package procname resolves a pid to a human readable program name in
// userspace so the log shows the real executable instead of the kernel thread
// name (e.g. "firefox" instead of "Socket Thread" / "DNS Resolver").
package procname

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const cacheTTL = 30 * time.Second

type entry struct {
	name string
	at   time.Time
}

// Resolver caches pid -> program name lookups.
type Resolver struct {
	mu    sync.Mutex
	cache map[uint32]entry
}

// New returns a new resolver.
func New() *Resolver {
	return &Resolver{cache: make(map[uint32]entry)}
}

// Name returns the executable basename for pid, falling back to the process
// comm, then to "?". The empty string is returned for pid 0.
func (r *Resolver) Name(pid uint32) string {
	if pid == 0 {
		return ""
	}
	r.mu.Lock()
	if e, ok := r.cache[pid]; ok && time.Since(e.at) < cacheTTL {
		r.mu.Unlock()
		return e.name
	}
	r.mu.Unlock()

	name := lookup(pid)

	r.mu.Lock()
	if len(r.cache) > 4096 {
		r.cache = make(map[uint32]entry)
	}
	r.cache[pid] = entry{name: name, at: time.Now()}
	r.mu.Unlock()
	return name
}

func lookup(pid uint32) string {
	base := "/proc/" + strconv.FormatUint(uint64(pid), 10)
	if target, err := os.Readlink(filepath.Join(base, "exe")); err == nil {
		name := filepath.Base(strings.TrimSuffix(target, " (deleted)"))
		if name != "" && name != "." && name != "/" {
			return name
		}
	}
	if b, err := os.ReadFile(filepath.Join(base, "comm")); err == nil {
		name := strings.TrimSpace(string(b))
		if name != "" {
			return name
		}
	}
	return "?"
}
