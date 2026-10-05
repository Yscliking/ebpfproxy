package bpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// MaxRules mirrors MAX_RULES in proxy.bpf.c.
const MaxRules = 256

// NameLen mirrors NAME_LEN in proxy.bpf.c (TASK_COMM_LEN).
const NameLen = 16

// RuleNameMax mirrors RULE_NAME_MAX in proxy.bpf.c (max process prefix).
const RuleNameMax = 64

// Rule actions.
const (
	ActionProxy  uint8 = 0
	ActionDirect uint8 = 1
	ActionBlock  uint8 = 2
)

// Protocol bits.
const (
	ProtoTCP uint8 = 1
	ProtoUDP uint8 = 2
)

// Statistic indices, mirroring the STAT_* enum in proxy.bpf.c.
const (
	StatAllow = iota
	StatProxy
	StatBlock
	StatTCP
	StatUDP
	StatLoop
	StatCount
)

// Rule is the kernel-side rule representation.
type Rule = proxyRule

// DstInfo describes an intercepted flow.
type DstInfo = proxyDstinfo

// Event is a decision event pushed by the eBPF program (struct event in
// proxy.bpf.c) for PROXY / DIRECT / BLOCK decisions.
type Event struct {
	Ts      uint64
	Pid     uint32
	Ip      uint32
	Port    uint16
	Proto   uint8
	Action  uint8
	RuleOrd uint32
	ProxyID uint32
	Comm    [NameLen]uint8
}

// ParseEvent decodes a ring-buffer sample.
func ParseEvent(raw []byte) (Event, error) {
	var ev Event
	if len(raw) < binary.Size(ev) {
		return ev, io.ErrUnexpectedEOF
	}
	err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev)
	return ev, err
}

// Config configures the eBPF manager.
type Config struct {
	CgroupPath    string
	DefaultAction uint8
	TCPRelayPort  uint16
	UDPRelayPort  uint16
	LogLevel      uint32
}

// Log levels (mirror the cfg_map log_level semantics).
const (
	LogOff    uint32 = 0
	LogBlock  uint32 = 1
	LogProxy  uint32 = 2
	LogDirect uint32 = 3
)

// Manager owns the loaded eBPF objects and their attachments.
type Manager struct {
	objs  proxyObjects
	links []link.Link
}

// Load loads the eBPF collection and attaches all hooks.
func Load(cfg Config) (*Manager, error) {
	m := &Manager{}
	if err := loadProxyObjects(&m.objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}

	attachments := []struct {
		attach ebpf.AttachType
		prog   *ebpf.Program
	}{
		{ebpf.AttachCGroupInet4Connect, m.objs.Connect4Prog},
		{ebpf.AttachCGroupUDP4Sendmsg, m.objs.Sendmsg4Prog},
		{ebpf.AttachCGroupSockOps, m.objs.SockopsProg},
	}
	for _, a := range attachments {
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cfg.CgroupPath,
			Attach:  a.attach,
			Program: a.prog,
		})
		if err != nil {
			m.Close()
			return nil, fmt.Errorf("attach cgroup program %s: %w", a.prog.String(), err)
		}
		m.links = append(m.links, l)
	}

	lt, err := link.AttachTracing(link.TracingOptions{Program: m.objs.UdpSendmsgProg})
	if err != nil {
		m.Close()
		return nil, fmt.Errorf("attach fentry/udp_sendmsg: %w", err)
	}
	m.links = append(m.links, lt)

	if err := m.setConfig(cfg); err != nil {
		m.Close()
		return nil, err
	}
	return m, nil
}

func (m *Manager) setConfig(cfg Config) error {
	c := proxyCfg{
		DefaultAction: uint32(cfg.DefaultAction),
		TcpRelayPort:  uint32(cfg.TCPRelayPort),
		UdpRelayPort:  uint32(cfg.UDPRelayPort),
		LogLevel:      cfg.LogLevel,
	}
	var cur proxyCfg
	if err := m.objs.CfgMap.Lookup(uint32(0), &cur); err == nil {
		c.RuleCount = cur.RuleCount
	}
	if err := m.objs.CfgMap.Update(uint32(0), &c, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update cfg: %w", err)
	}
	return nil
}

// SetDefaultAction changes the fallback action for unmatched traffic.
func (m *Manager) SetDefaultAction(action uint8) error {
	var c proxyCfg
	if err := m.objs.CfgMap.Lookup(uint32(0), &c); err != nil {
		return err
	}
	c.DefaultAction = uint32(action)
	return m.objs.CfgMap.Update(uint32(0), &c, ebpf.UpdateAny)
}

// SetLogLevel changes how much traffic is pushed to the event ring buffer.
func (m *Manager) SetLogLevel(level uint32) error {
	var c proxyCfg
	if err := m.objs.CfgMap.Lookup(uint32(0), &c); err != nil {
		return err
	}
	c.LogLevel = level
	return m.objs.CfgMap.Update(uint32(0), &c, ebpf.UpdateAny)
}

// EventsMap returns the decision-event ring buffer.
func (m *Manager) EventsMap() *ebpf.Map { return m.objs.Events }

// SetRules replaces the complete rule table.
func (m *Manager) SetRules(rules []Rule) error {
	if len(rules) > MaxRules {
		return fmt.Errorf("too many rules: %d (max %d)", len(rules), MaxRules)
	}
	for i := range rules {
		r := rules[i]
		if err := m.objs.Rules.Update(uint32(i), &r, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update rule %d: %w", i, err)
		}
	}
	empty := Rule{}
	for i := len(rules); i < MaxRules; i++ {
		if err := m.objs.Rules.Update(uint32(i), &empty, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("clear rule %d: %w", i, err)
		}
	}
	var c proxyCfg
	if err := m.objs.CfgMap.Lookup(uint32(0), &c); err != nil {
		return err
	}
	c.RuleCount = uint32(len(rules))
	return m.objs.CfgMap.Update(uint32(0), &c, ebpf.UpdateAny)
}

// LookupRedirTCP atomically fetches and removes a TCP redirect entry.
func (m *Manager) LookupRedirTCP(port uint32) (DstInfo, bool) {
	var v DstInfo
	if err := m.objs.RedirsTcp.LookupAndDelete(&port, &v); err != nil {
		return DstInfo{}, false
	}
	return v, true
}

// LookupRedirUDP atomically fetches and removes a UDP redirect entry.
func (m *Manager) LookupRedirUDP(port uint32) (DstInfo, bool) {
	var v DstInfo
	if err := m.objs.RedirsUdp.LookupAndDelete(&port, &v); err != nil {
		return DstInfo{}, false
	}
	return v, true
}

// PeekRedirUDP reads a UDP redirect without removing it (useful for flows that
// send several datagrams).
func (m *Manager) PeekRedirUDP(port uint32) (DstInfo, bool) {
	var v DstInfo
	if err := m.objs.RedirsUdp.Lookup(&port, &v); err != nil {
		return DstInfo{}, false
	}
	return v, true
}

// Stats returns aggregated counters for each STAT_* index.
func (m *Manager) Stats() [StatCount]uint64 {
	var out [StatCount]uint64
	for i := uint32(0); i < StatCount; i++ {
		var perCPU []uint64
		if err := m.objs.Stats.Lookup(&i, &perCPU); err != nil {
			continue
		}
		for _, v := range perCPU {
			out[i] += v
		}
	}
	return out
}

// Close detaches all programs and releases all resources.
func (m *Manager) Close() error {
	var firstErr error
	for _, l := range m.links {
		if err := l.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	m.links = nil
	if err := m.objs.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}
