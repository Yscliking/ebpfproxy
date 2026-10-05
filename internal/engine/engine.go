// Package engine wires the eBPF programs, the SOCKS5 client and the userspace
// relays together.
package engine

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"ebpfproxy/internal/bpf"
	"ebpfproxy/internal/procname"
	"ebpfproxy/internal/relay"
	"ebpfproxy/internal/rule"
	"ebpfproxy/internal/socks"
)

// Proxy is a named SOCKS5 endpoint.
type Proxy struct {
	Name   string
	Client socks.Client
}

// Config configures the engine.
type Config struct {
	CgroupPath    string
	Proxies       []Proxy
	DefaultProxy  string
	DefaultAction uint8
	TCPRelayPort  uint16
	UDPRelayPort  uint16
	LogLevel      uint32
	Rules         []rule.Rule
}

// Engine owns the running data path.
type Engine struct {
	cfg      Config
	mgr      *bpf.Manager
	tcp      *relay.TCPRelay
	udp      *relay.UDPRelay
	resolver *procname.Resolver
	reader   *ringbuf.Reader
	Events   chan relay.Event

	proxyMu        sync.RWMutex
	proxies        []Proxy
	proxyIDs       map[string]uint32
	defaultProxyID uint32

	mu      sync.Mutex
	started bool
}

// New creates an engine.
func New(cfg Config) *Engine {
	if cfg.CgroupPath == "" {
		cfg.CgroupPath = "/sys/fs/cgroup"
	}
	e := &Engine{
		cfg:      cfg,
		resolver: procname.New(),
		Events:   make(chan relay.Event, 4096),
	}
	e.SetProxies(cfg.Proxies, cfg.DefaultProxy)
	return e
}

// SetProxies replaces the proxy list and default proxy.
func (e *Engine) SetProxies(proxies []Proxy, defaultName string) {
	ids := make(map[string]uint32, len(proxies))
	for i, p := range proxies {
		if _, ok := ids[p.Name]; !ok {
			ids[p.Name] = uint32(i)
		}
	}
	var def uint32
	if id, ok := ids[defaultName]; ok {
		def = id
	}
	e.proxyMu.Lock()
	e.proxies = proxies
	e.proxyIDs = ids
	e.defaultProxyID = def
	e.proxyMu.Unlock()
}

// Proxies returns a copy of the configured proxies.
func (e *Engine) Proxies() []Proxy {
	e.proxyMu.RLock()
	defer e.proxyMu.RUnlock()
	return append([]Proxy(nil), e.proxies...)
}

// ProxyFor returns the client for a proxy id (falling back to the default).
func (e *Engine) ProxyFor(id uint32) *socks.Client {
	e.proxyMu.RLock()
	defer e.proxyMu.RUnlock()
	if len(e.proxies) == 0 {
		return nil
	}
	if int(id) >= len(e.proxies) {
		id = e.defaultProxyID
	}
	return &e.proxies[id].Client
}

// ProxyName returns the name for a proxy id.
func (e *Engine) ProxyName(id uint32) string {
	e.proxyMu.RLock()
	defer e.proxyMu.RUnlock()
	if int(id) >= len(e.proxies) {
		return ""
	}
	return e.proxies[id].Name
}

// proxyID resolves a proxy name ("" = default) to its id.
func (e *Engine) proxyID(name string) (uint32, bool) {
	e.proxyMu.RLock()
	defer e.proxyMu.RUnlock()
	if name == "" {
		return e.defaultProxyID, true
	}
	id, ok := e.proxyIDs[name]
	return id, ok
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
		LogLevel:      e.cfg.LogLevel,
	})
	if err != nil {
		return err
	}

	tcp := &relay.TCPRelay{
		Addr:     fmt.Sprintf("127.0.0.1:%d", e.cfg.TCPRelayPort),
		ProxyFor: e.ProxyFor,
		Lookup:   mgr.LookupRedirTCP,
		Resolve:  e.resolver.Name,
		Events:   e.Events,
	}
	if err := tcp.Start(); err != nil {
		mgr.Close()
		return fmt.Errorf("start tcp relay: %w", err)
	}

	udp := &relay.UDPRelay{
		Addr:     fmt.Sprintf("127.0.0.1:%d", e.cfg.UDPRelayPort),
		ProxyFor: e.ProxyFor,
		Peek:     mgr.PeekRedirUDP,
		Resolve:  e.resolver.Name,
		Events:   e.Events,
	}
	if err := udp.Start(); err != nil {
		tcp.Close()
		mgr.Close()
		return fmt.Errorf("start udp relay: %w", err)
	}

	rd, err := ringbuf.NewReader(mgr.EventsMap())
	if err != nil {
		udp.Close()
		tcp.Close()
		mgr.Close()
		return fmt.Errorf("open event ring buffer: %w", err)
	}

	e.mgr = mgr
	e.tcp = tcp
	e.udp = udp
	e.reader = rd
	e.started = true
	go e.readEvents(rd)
	return e.applyRulesLocked(e.cfg.Rules)
}

// Stop tears everything down.
func (e *Engine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.started {
		return
	}
	if e.reader != nil {
		e.reader.Close()
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
	kernel, err := rule.Expand(rules, e.proxyID)
	if err != nil {
		return err
	}
	return e.mgr.SetRules(kernel)
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

// SetLogLevel changes how much traffic is logged (0 off .. 3 all).
func (e *Engine) SetLogLevel(level uint32) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg.LogLevel = level
	if !e.started {
		return nil
	}
	return e.mgr.SetLogLevel(level)
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

// readEvents converts kernel decision events into UI events.
func (e *Engine) readEvents(rd *ringbuf.Reader) {
	for {
		rec, err := rd.Read()
		if err != nil {
			return
		}
		ev, err := bpf.ParseEvent(rec.RawSample)
		if err != nil {
			continue
		}
		proc := commStr(ev.Comm[:])
		if proc == "" {
			proc = e.resolver.Name(ev.Pid)
		}
		var proxyName string
		if ev.Action == bpf.ActionProxy {
			proxyName = e.ProxyName(ev.ProxyID)
		}
		e.push(relay.Event{
			Time:    time.Now(),
			Proto:   protoName(ev.Proto),
			Action:  actionName(ev.Action),
			Rule:    ev.RuleOrd,
			Proxy:   proxyName,
			Pid:     ev.Pid,
			Process: proc,
			Dst:     dstString(ev.Ip, ev.Port),
		})
	}
}

func (e *Engine) push(ev relay.Event) {
	select {
	case e.Events <- ev:
	default:
	}
}

func actionName(a uint8) string {
	switch a {
	case bpf.ActionProxy:
		return "PROXY"
	case bpf.ActionBlock:
		return "BLOCK"
	default:
		return "DIRECT"
	}
}

func protoName(p uint8) string {
	if p == bpf.ProtoUDP {
		return "UDP"
	}
	return "TCP"
}

func dstString(ip uint32, port uint16) string {
	b := []byte{byte(ip), byte(ip >> 8), byte(ip >> 16), byte(ip >> 24)}
	return net.JoinHostPort(net.IP(b).String(), fmt.Sprint(port))
}

func commStr(comm []uint8) string {
	n := 0
	for n < len(comm) && comm[n] != 0 {
		n++
	}
	return string(comm[:n])
}
