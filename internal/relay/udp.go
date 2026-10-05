package relay

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"ebpfproxy/internal/bpf"
	"ebpfproxy/internal/socks"
)

const (
	udpFlowIdle     = 120 * time.Second
	udpJanitorEvery = 30 * time.Second
)

var debugUDP = os.Getenv("EBPFPROXY_DEBUG") != ""

// UDPRelay receives datagrams redirected by eBPF and relays them through a
// SOCKS5 UDP association. A single association is shared by all flows and the
// SOCKS5 remote source address is used to route replies back to clients.
// Replies to unconnected sockets are sent with the original remote address
// spoofed as the source so proxy-unaware applications keep working.
type UDPRelay struct {
	Addr   string
	Proxy  *socks.Client
	Peek   func(port uint32) (bpf.DstInfo, bool)
	Events chan<- Event

	conn *net.UDPConn

	mu            sync.Mutex
	flows         map[string]*udpFlow
	remoteClients map[string]map[*udpFlow]struct{}
	spoofs        map[string]*net.UDPConn
	closing       bool

	assocMu sync.Mutex
	assoc   *socks.UDPAssoc

	done chan struct{}
	wg   sync.WaitGroup

	errMu   sync.Mutex
	errSeen map[string]time.Time
}

type udpFlow struct {
	relay     *UDPRelay
	key       string
	client    *net.UDPAddr
	dst       *net.UDPAddr
	connected bool

	mu       sync.Mutex
	lastUsed time.Time
	closed   bool
}

// Start binds the relay socket and begins serving.
func (r *UDPRelay) Start() error {
	addr, err := net.ResolveUDPAddr("udp4", r.Addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return err
	}
	r.conn = conn
	r.flows = make(map[string]*udpFlow)
	r.remoteClients = make(map[string]map[*udpFlow]struct{})
	r.spoofs = make(map[string]*net.UDPConn)
	r.done = make(chan struct{})
	r.errSeen = make(map[string]time.Time)

	r.wg.Add(2)
	go r.readLoop()
	go r.janitor()
	return nil
}

func (r *UDPRelay) readLoop() {
	defer r.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, client, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			r.mu.Lock()
			closing := r.closing
			r.mu.Unlock()
			if closing {
				return
			}
			continue
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		r.dispatch(client, data)
	}
}

func (r *UDPRelay) dispatch(client *net.UDPAddr, data []byte) {
	di, ok := r.Peek(uint32(client.Port))
	if !ok {
		return
	}
	dst := &net.UDPAddr{IP: dstInfoIP(di.Ip), Port: int(di.Port)}
	connected := di.Connected == 1
	key := client.String() + "|" + dst.String()

	r.mu.Lock()
	flow, exists := r.flows[key]
	if !exists {
		flow = &udpFlow{
			relay:     r,
			key:       key,
			client:    cloneUDPAddr(client),
			dst:       cloneUDPAddr(dst),
			connected: connected,
			lastUsed:  time.Now(),
		}
		r.flows[key] = flow
		rc := r.remoteClients[dst.String()]
		if rc == nil {
			rc = make(map[*udpFlow]struct{})
			r.remoteClients[dst.String()] = rc
		}
		rc[flow] = struct{}{}
	}
	r.mu.Unlock()

	if !exists {
		r.emit(Event{Time: time.Now(), Proto: "UDP", Action: "PROXY", Rule: di.RuleOrd,
			Pid: di.Pid, Process: commString(di.Comm[:]), Dst: dst.String()})
	}

	assoc, err := r.ensureAssoc()
	if err != nil {
		r.emitErr(di, dst.String(), err)
		return
	}

	flow.touch()
	if err := assoc.Send(dst, data); err != nil {
		if debugUDP {
			fmt.Fprintf(os.Stderr, "udp: send to proxy failed flow=%s: %v\n", key, err)
		}
		r.dropAssoc(assoc)
		flow.close()
	}
}

func (r *UDPRelay) ensureAssoc() (*socks.UDPAssoc, error) {
	r.assocMu.Lock()
	defer r.assocMu.Unlock()
	if r.assoc != nil {
		return r.assoc, nil
	}
	a, err := r.Proxy.AssociateUDP()
	if err != nil {
		return nil, err
	}
	r.assoc = a
	r.wg.Add(1)
	go r.assocReadLoop(a)
	return a, nil
}

func (r *UDPRelay) dropAssoc(a *socks.UDPAssoc) {
	r.assocMu.Lock()
	if r.assoc == a {
		r.assoc = nil
	}
	r.assocMu.Unlock()
	a.Close()
}

func (r *UDPRelay) assocReadLoop(a *socks.UDPAssoc) {
	defer r.wg.Done()
	for {
		src, payload, err := a.Receive()
		if err != nil {
			r.dropAssoc(a)
			return
		}
		r.dispatchReply(src, payload)
	}
}

func (r *UDPRelay) dispatchReply(src *net.UDPAddr, payload []byte) {
	r.mu.Lock()
	rc := r.remoteClients[src.String()]
	flows := make([]*udpFlow, 0, len(rc))
	for f := range rc {
		flows = append(flows, f)
	}
	r.mu.Unlock()

	if debugUDP {
		fmt.Fprintf(os.Stderr, "udp: reply from %s -> %d flow(s), len=%d\n", src, len(flows), len(payload))
	}
	for _, f := range flows {
		f.deliver(src, payload)
	}
}

func (f *udpFlow) touch() {
	f.mu.Lock()
	f.lastUsed = time.Now()
	f.mu.Unlock()
}

func (f *udpFlow) deliver(src *net.UDPAddr, payload []byte) {
	if f.connected {
		// The client socket is connected to the relay address, so replies must
		// originate from the relay socket.
		if _, err := f.relay.conn.WriteToUDP(payload, f.client); err != nil && debugUDP {
			fmt.Fprintf(os.Stderr, "udp: connected reply failed: %v\n", err)
		}
		return
	}
	// Unconnected socket: spoof the original remote address as the source.
	conn, err := f.relay.spoofConn(src)
	if err != nil {
		return
	}
	conn.WriteToUDP(payload, f.client)
}

func (r *UDPRelay) spoofConn(src *net.UDPAddr) (*net.UDPConn, error) {
	key := src.String()
	r.mu.Lock()
	if c, ok := r.spoofs[key]; ok {
		r.mu.Unlock()
		return c, nil
	}
	r.mu.Unlock()

	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
		}); err != nil {
			return err
		}
		return serr
	}}
	pc, err := lc.ListenPacket(context.Background(), "udp4", key)
	if err != nil {
		return nil, err
	}
	conn := pc.(*net.UDPConn)

	r.mu.Lock()
	r.spoofs[key] = conn
	r.mu.Unlock()
	return conn, nil
}

func (f *udpFlow) close() {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.closed = true
	f.mu.Unlock()

	f.relay.mu.Lock()
	delete(f.relay.flows, f.key)
	if rc := f.relay.remoteClients[f.dst.String()]; rc != nil {
		delete(rc, f)
		if len(rc) == 0 {
			delete(f.relay.remoteClients, f.dst.String())
		}
	}
	f.relay.mu.Unlock()
}

func (r *UDPRelay) janitor() {
	defer r.wg.Done()
	t := time.NewTicker(udpJanitorEvery)
	defer t.Stop()
	for {
		select {
		case <-r.done:
			return
		case <-t.C:
		}
		var stale []*udpFlow
		r.mu.Lock()
		for _, f := range r.flows {
			f.mu.Lock()
			idle := time.Since(f.lastUsed) > udpFlowIdle
			f.mu.Unlock()
			if idle {
				stale = append(stale, f)
			}
		}
		r.mu.Unlock()
		for _, f := range stale {
			f.close()
		}
	}
}

func (r *UDPRelay) emit(e Event) {
	if r.Events == nil {
		return
	}
	select {
	case r.Events <- e:
	default:
	}
}

// emitErr reports a proxy failure at most once per 30s per (process, dst,
// error) so a broken flow does not flood the log.
func (r *UDPRelay) emitErr(di bpf.DstInfo, dst string, err error) {
	key := commString(di.Comm[:]) + "|" + dst + "|" + err.Error()
	r.errMu.Lock()
	if t, ok := r.errSeen[key]; ok && time.Since(t) < 30*time.Second {
		r.errMu.Unlock()
		return
	}
	if len(r.errSeen) > 512 {
		r.errSeen = make(map[string]time.Time)
	}
	r.errSeen[key] = time.Now()
	r.errMu.Unlock()

	r.emit(Event{Time: time.Now(), Proto: "UDP", Action: "PROXY", Rule: di.RuleOrd,
		Pid: di.Pid, Process: commString(di.Comm[:]), Dst: dst, Err: err.Error()})
}

// Close stops the relay and tears down all flows.
func (r *UDPRelay) Close() {
	r.mu.Lock()
	if r.closing {
		r.mu.Unlock()
		return
	}
	r.closing = true
	if r.done != nil {
		close(r.done)
	}
	flows := make([]*udpFlow, 0, len(r.flows))
	for _, f := range r.flows {
		flows = append(flows, f)
	}
	r.mu.Unlock()

	if r.conn != nil {
		r.conn.Close()
	}
	for _, f := range flows {
		f.close()
	}

	r.assocMu.Lock()
	a := r.assoc
	r.assoc = nil
	r.assocMu.Unlock()
	if a != nil {
		a.Close()
	}
	waitTimeout(&r.wg, 2*time.Second)

	r.mu.Lock()
	for _, c := range r.spoofs {
		c.Close()
	}
	r.spoofs = nil
	r.mu.Unlock()
}

func cloneUDPAddr(a *net.UDPAddr) *net.UDPAddr {
	ip := make(net.IP, len(a.IP))
	copy(ip, a.IP)
	return &net.UDPAddr{IP: ip, Port: a.Port, Zone: a.Zone}
}
