// Package engine wires the eBPF programs, the SOCKS5 client and the userspace
// relays together.
package engine

import (
	"fmt"
	"sync"

	"ebpfproxy/internal/bpf"
	"ebpfproxy/internal/relay"
	"ebpfproxy/internal/rule"
	"ebpfproxy/internal/socks"
)

// Config configures the engine.
type Config struct {
	CgroupPath    string
	Proxy         socks.Client
	DefaultAction uint8
	TCPRelayPort  uint16
	UDPRelayPort  uint16
	Rules         []rule.Rule
}

// Engine owns the running data path.
type Engine struct {
	cfg    Config
	mgr    *bpf.Manager
	tcp    *relay.TCPRelay
	udp    *relay.UDPRelay
	Events chan relay.Event

	mu      sync.Mutex
	started bool
}

// New creates an engine.
func New(cfg Config) *Engine {
	if cfg.CgroupPath == "" {
		cfg.CgroupPath = "/sys/fs/cgroup"
	}
	return &Engine{cfg: cfg, Events: make(chan relay.Event, 2048)}
}

// Start loads and attaches the eBPF programs and starts the relays.
func (e *Engine) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.started {
		return fmt.Errorf("engine already started")
	}

	mgr, err := bpf.Load(bpf.Config{
		CgroupPath:    e.cfg.CgroupPath,
		DefaultAction: e.cfg.DefaultAction,
		TCPRelayPort:  e.cfg.TCPRelayPort,
		UDPRelayPort:  e.cfg.UDPRelayPort,
	})
	if err != nil {
		return err
	}

	tcp := &relay.TCPRelay{
		Addr:   fmt.Sprintf("127.0.0.1:%d", e.cfg.TCPRelayPort),
		Proxy:  &e.cfg.Proxy,
		Lookup: mgr.LookupRedirTCP,
		Events: e.Events,
	}
	if err := tcp.Start(); err != nil {
		mgr.Close()
		return fmt.Errorf("start tcp relay: %w", err)
	}

	udp := &relay.UDPRelay{
		Addr:   fmt.Sprintf("127.0.0.1:%d", e.cfg.UDPRelayPort),
		Proxy:  &e.cfg.Proxy,
		Peek:   mgr.PeekRedirUDP,
		Events: e.Events,
	}
	if err := udp.Start(); err != nil {
		tcp.Close()
		mgr.Close()
		return fmt.Errorf("start udp relay: %w", err)
	}

	e.mgr = mgr
	e.tcp = tcp
	e.udp = udp
	e.started = true
	return e.applyRulesLocked(e.cfg.Rules)
}

// Stop tears everything down.
func (e *Engine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.started {
		return
	}
	if e.tcp != nil {
		e.tcp.Close()
	}
	if e.udp != nil {
		e.udp.Close()
	}
	if e.mgr != nil {
		e.mgr.Close()
	}
	e.started = false
}

// Running reports whether the data path is active.
func (e *Engine) Running() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.started
}

// ApplyRules installs a new rule set.
func (e *Engine) ApplyRules(rules []rule.Rule) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg.Rules = rules
	if !e.started {
		return nil
	}
	return e.applyRulesLocked(rules)
}

func (e *Engine) applyRulesLocked(rules []rule.Rule) error {
	return e.mgr.SetRules(rule.Expand(rules))
}

// SetDefaultAction changes the fallback action for unmatched traffic.
func (e *Engine) SetDefaultAction(action uint8) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg.DefaultAction = action
	if !e.started {
		return nil
	}
	return e.mgr.SetDefaultAction(action)
}

// Stats returns the kernel counters.
func (e *Engine) Stats() [bpf.StatCount]uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.started {
		return [bpf.StatCount]uint64{}
	}
	return e.mgr.Stats()
}

// Proxy returns a pointer to the configured proxy client.
func (e *Engine) Proxy() *socks.Client { return &e.cfg.Proxy }
