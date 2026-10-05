package relay

import (
	"io"
	"net"
	"sync"
	"time"

	"ebpfproxy/internal/bpf"
	"ebpfproxy/internal/socks"
)

// TCPRelay accepts connections that eBPF redirected to the local relay port
// and forwards them to the original destination through SOCKS5.
type TCPRelay struct {
	Addr   string
	Proxy  *socks.Client
	Lookup func(port uint32) (bpf.DstInfo, bool)
	Events chan<- Event
	Logf   func(string, ...any)

	ln      net.Listener
	mu      sync.Mutex
	closing bool
	conns   map[net.Conn]struct{}
	wg      sync.WaitGroup // accept loop only
}

// Start begins listening.
func (r *TCPRelay) Start() error {
	ln, err := net.Listen("tcp4", r.Addr)
	if err != nil {
		return err
	}
	r.ln = ln
	r.conns = make(map[net.Conn]struct{})
	r.wg.Add(1)
	go r.acceptLoop()
	return nil
}

func (r *TCPRelay) acceptLoop() {
	defer r.wg.Done()
	for {
		conn, err := r.ln.Accept()
		if err != nil {
			r.mu.Lock()
			closing := r.closing
			r.mu.Unlock()
			if closing {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		go r.handle(conn)
	}
}

func (r *TCPRelay) track(c net.Conn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing {
		return false
	}
	r.conns[c] = struct{}{}
	return true
}

func (r *TCPRelay) untrack(c net.Conn) {
	r.mu.Lock()
	delete(r.conns, c)
	r.mu.Unlock()
}

func (r *TCPRelay) handle(client net.Conn) {
	if !r.track(client) {
		client.Close()
		return
	}
	defer func() {
		r.untrack(client)
		client.Close()
	}()

	peer, ok := client.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return
	}
	di, found := r.Lookup(uint32(peer.Port))
	if !found {
		return
	}

	dstAddr := &net.TCPAddr{IP: dstInfoIP(di.Ip), Port: int(di.Port)}
	dst := dstAddr.String()

	up, err := r.Proxy.DialTCP(dst)
	if err != nil {
		r.emit(Event{
			Time: time.Now(), Proto: "TCP", Action: "PROXY", Rule: di.RuleOrd,
			Pid: di.Pid, Process: commString(di.Comm[:]), Dst: dst, Err: err.Error(),
		})
		return
	}
	if !r.track(up) {
		up.Close()
		return
	}
	defer func() {
		r.untrack(up)
		up.Close()
	}()
	r.emit(Event{
		Time: time.Now(), Proto: "TCP", Action: "PROXY", Rule: di.RuleOrd,
		Pid: di.Pid, Process: commString(di.Comm[:]), Dst: dst,
	})

	relayBidirectional(client, up)
}

func (r *TCPRelay) emit(e Event) {
	if r.Events == nil {
		return
	}
	select {
	case r.Events <- e:
	default:
	}
}

// Close stops the relay immediately: it stops accepting and force-closes every
// in-flight connection so shutdown never waits for the proxied application.
func (r *TCPRelay) Close() {
	r.mu.Lock()
	if r.closing {
		r.mu.Unlock()
		return
	}
	r.closing = true
	conns := make([]net.Conn, 0, len(r.conns))
	for c := range r.conns {
		conns = append(conns, c)
	}
	r.mu.Unlock()

	if r.ln != nil {
		r.ln.Close()
	}
	for _, c := range conns {
		c.Close()
	}
	waitTimeout(&r.wg, time.Second)
}

func relayBidirectional(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	copyOne := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			c.CloseWrite()
		} else {
			dst.Close()
		}
	}
	go copyOne(a, b)
	go copyOne(b, a)
	wg.Wait()
}
