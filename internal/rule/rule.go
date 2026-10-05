// Package rule implements the user-facing rule model, its textual syntax and
// expansion into the compact representation consumed by the eBPF program.
package rule

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"

	"ebpfproxy/internal/bpf"
)

// Rule is a user-facing traffic rule.
//
// The textual form is:  process:hosts:ports:protocol:action
//
//	process  - one or more process name prefixes, e.g. curl, cur*, *,
//	           curl;wget  (';' or ',' separated)
//	hosts    - one or more IPv4 addresses / CIDRs / hostnames, or *,
//	           e.g. *.example.com, 1.2.3.4, 10.0.0.0/8
//	ports    - one or more ports or ranges, e.g. 80, 80;443, 8000-8100, *
//	protocol - TCP, UDP or BOTH
//	action   - PROXY, DIRECT or BLOCK
type Rule struct {
	ID       int    `json:"id"`
	Process  string `json:"process"`
	Hosts    string `json:"hosts"`
	Ports    string `json:"ports"`
	Protocol string `json:"protocol"`
	Action   string `json:"action"`
	Enabled  bool   `json:"enabled"`
}

// Action constants (mirror bpf.Action*).
const (
	ActionProxy  = bpf.ActionProxy
	ActionDirect = bpf.ActionDirect
	ActionBlock  = bpf.ActionBlock
)

var actionNames = map[string]uint8{
	"PROXY":  ActionProxy,
	"DIRECT": ActionDirect,
	"BLOCK":  ActionBlock,
}

// ParseAction converts a textual action to its numeric value.
func ParseAction(s string) (uint8, error) {
	a, ok := actionNames[strings.ToUpper(strings.TrimSpace(s))]
	if !ok {
		return 0, fmt.Errorf("invalid action %q (want PROXY, DIRECT or BLOCK)", s)
	}
	return a, nil
}

// ActionName returns the textual name of a numeric action.
func ActionName(a uint8) string {
	switch a {
	case ActionProxy:
		return "PROXY"
	case ActionDirect:
		return "DIRECT"
	case ActionBlock:
		return "BLOCK"
	}
	return "?"
}

func protoBits(s string) (uint8, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "TCP":
		return bpf.ProtoTCP, nil
	case "UDP":
		return bpf.ProtoUDP, nil
	case "BOTH", "":
		return bpf.ProtoTCP | bpf.ProtoUDP, nil
	}
	return 0, fmt.Errorf("invalid protocol %q (want TCP, UDP or BOTH)", s)
}

// Parse parses the colon separated rule syntax.
func Parse(s string, id int) (Rule, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 5 {
		return Rule{}, fmt.Errorf("invalid rule %q: want process:hosts:ports:protocol:action", s)
	}
	r := Rule{
		ID:       id,
		Process:  strings.TrimSpace(parts[0]),
		Hosts:    strings.TrimSpace(parts[1]),
		Ports:    strings.TrimSpace(parts[2]),
		Protocol: strings.ToUpper(strings.TrimSpace(parts[3])),
		Action:   strings.ToUpper(strings.TrimSpace(parts[4])),
		Enabled:  true,
	}
	if _, err := protoBits(r.Protocol); err != nil {
		return Rule{}, err
	}
	if _, err := ParseAction(r.Action); err != nil {
		return Rule{}, err
	}
	return r, nil
}

// String renders the rule back to its textual form.
func (r Rule) String() string {
	return fmt.Sprintf("%s:%s:%s:%s:%s", r.Process, r.Hosts, r.Ports, r.Protocol, r.Action)
}

func splitList(s string) []string {
	f := func(r rune) bool { return r == ';' || r == ',' }
	var out []string
	for _, p := range strings.FieldsFunc(s, f) {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// processPattern turns a process pattern into (name, length, wildcard):
//
//	"*"    -> ("",        0, true)   match any
//	"git*" -> ("git",     3, true)   prefix match
//	"git"  -> ("git",     3, false)  exact match
//
// A '*' anywhere truncates the pattern and makes it a prefix match.
func processPattern(p string) (string, int, bool) {
	p = strings.TrimSpace(p)
	if p == "" || p == "*" {
		return "", 0, true
	}
	wildcard := false
	if i := strings.IndexByte(p, '*'); i >= 0 {
		p = p[:i]
		wildcard = true
	}
	if len(p) > bpf.RuleNameMax-1 {
		p = p[:bpf.RuleNameMax-1]
	}
	return p, len(p), wildcard
}

type ipnet struct {
	ip   uint32
	mask uint32
}

// resolveHosts turns a host list into address/mask pairs.
func resolveHosts(hosts string) ([]ipnet, error) {
	if strings.TrimSpace(hosts) == "" || strings.TrimSpace(hosts) == "*" {
		return []ipnet{{ip: 0, mask: 0}}, nil
	}
	var out []ipnet
	for _, h := range splitList(hosts) {
		if h == "*" {
			return []ipnet{{ip: 0, mask: 0}}, nil
		}
		if strings.Contains(h, "/") {
			_, n, err := net.ParseCIDR(h)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", h, err)
			}
			ip4 := n.IP.To4()
			if ip4 == nil {
				return nil, fmt.Errorf("only IPv4 is supported: %q", h)
			}
			ip := binary.LittleEndian.Uint32(ip4)
			mask := binary.LittleEndian.Uint32(n.Mask)
			out = append(out, ipnet{ip: ip & mask, mask: mask})
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			ip4 := ip.To4()
			if ip4 == nil {
				return nil, fmt.Errorf("only IPv4 is supported: %q", h)
			}
			ipn := binary.LittleEndian.Uint32(ip4)
			out = append(out, ipnet{ip: ipn, mask: 0xffffffff})
			continue
		}
		// hostname
		ips, err := net.LookupIP(h)
		if err != nil {
			return nil, fmt.Errorf("cannot resolve %q: %w", h, err)
		}
		found := false
		for _, ip := range ips {
			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			ipn := binary.LittleEndian.Uint32(ip4)
			out = append(out, ipnet{ip: ipn, mask: 0xffffffff})
			found = true
		}
		if !found {
			return nil, fmt.Errorf("no IPv4 address for %q", h)
		}
	}
	return out, nil
}

type portRange struct{ lo, hi uint16 }

func resolvePorts(ports string) ([]portRange, error) {
	if strings.TrimSpace(ports) == "" || strings.TrimSpace(ports) == "*" {
		return []portRange{{0, 65535}}, nil
	}
	var out []portRange
	for _, p := range splitList(ports) {
		if p == "*" {
			return []portRange{{0, 65535}}, nil
		}
		if strings.Contains(p, "-") {
			lo, hi, err := parseRange(p)
			if err != nil {
				return nil, err
			}
			out = append(out, portRange{lo, hi})
			continue
		}
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q", p)
		}
		out = append(out, portRange{uint16(n), uint16(n)})
	}
	return out, nil
}

func parseRange(s string) (uint16, uint16, error) {
	p := strings.SplitN(s, "-", 2)
	lo, err := strconv.ParseUint(strings.TrimSpace(p[0]), 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid port range %q", s)
	}
	hi, err := strconv.ParseUint(strings.TrimSpace(p[1]), 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid port range %q", s)
	}
	if hi < lo {
		lo, hi = hi, lo
	}
	return uint16(lo), uint16(hi), nil
}

// Expand flattens the user rules into the kernel table in list order. Rules
// are evaluated top to bottom and the first match wins. Each kernel entry
// carries the 1-based order of the user rule it came from so the hit can be
// reported. Expansion stops when the kernel table is full.
func Expand(rules []Rule) []bpf.Rule {
	var out []bpf.Rule
	add := func(order uint32, r Rule) {
		if len(out) >= bpf.MaxRules {
			return
		}
		if !r.Enabled {
			return
		}
		action, err := ParseAction(r.Action)
		if err != nil {
			return
		}
		proto, err := protoBits(r.Protocol)
		if err != nil {
			return
		}
		hosts, err := resolveHosts(r.Hosts)
		if err != nil {
			return
		}
		ports, err := resolvePorts(r.Ports)
		if err != nil {
			return
		}
		procs := splitList(r.Process)
		if len(procs) == 0 {
			procs = []string{"*"}
		}
		for _, pr := range procs {
			name, nlen, wildcard := processPattern(pr)
			for _, h := range hosts {
				for _, p := range ports {
					if len(out) >= bpf.MaxRules {
						return
					}
					kr := bpf.Rule{
						Ip:      h.ip,
						Mask:    h.mask,
						PortLo:  p.lo,
						PortHi:  p.hi,
						Ord:     order,
						NameLen: uint8(nlen),
						Proto:   proto,
						Action:  action,
						Enabled: 1,
					}
					if wildcard {
						kr.Wildcard = 1
					}
					copy(kr.Name[:], name)
					out = append(out, kr)
				}
			}
		}
	}

	for i, r := range rules {
		add(uint32(i+1), r)
	}
	return out
}
