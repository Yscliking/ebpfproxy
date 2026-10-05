package relay

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// Event is a single traffic event emitted by the relays.
type Event struct {
	Time    time.Time
	Proto   string
	Action  string
	Rule    uint32 // user rule order (1-based) that matched, 0 if none
	Proxy   string // proxy name for PROXY flows
	Pid     uint32
	Process string
	Dst     string
	Err     string
}

// String renders an event for logs.
func (e Event) String() string {
	rule := "rule -"
	if e.Rule > 0 {
		rule = fmt.Sprintf("rule #%d", e.Rule)
	}
	via := ""
	if e.Proxy != "" {
		via = " via " + e.Proxy
	}
	s := fmt.Sprintf("[%s] %-3s %-6s %-8s pid=%-6d %-16s -> %s%s",
		e.Time.Format("15:04:05"), e.Proto, e.Action, rule, e.Pid, e.Process, e.Dst, via)
	if e.Err != "" {
		s += "  (" + e.Err + ")"
	}
	return s
}

// waitTimeout waits for wg up to d, then returns regardless. Used so shutdown
// never blocks on in-flight work.
func waitTimeout(wg *sync.WaitGroup, d time.Duration) {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
	}
}

// dstInfoIP converts the kernel's network-order-as-u32 IPv4 representation to
// a net.IP.
func dstInfoIP(v uint32) net.IP {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return net.IP(b)
}

func commString(comm []uint8) string {
	n := 0
	for n < len(comm) && comm[n] != 0 {
		n++
	}
	return string(comm[:n])
}
