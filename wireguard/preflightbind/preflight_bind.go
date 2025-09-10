package preflightbind

import (
	"encoding/hex"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

// Bind wraps a conn.Bind and fires a QUIC-like preflight when WG sends a handshake initiation.
type Bind struct {
	inner    conn.Bind
	port443  int            // usually 443
	payload  []byte         // I1 bytes
	mu       sync.Mutex
	lastSent map[netip.Addr]time.Time // rate-limit per dst IP
	interval time.Duration            // e.g., 1s to avoid duplicate bursts
}

func New(inner conn.Bind, hexPayload string, port int, minInterval time.Duration) (*Bind, error) {
	// hexPayload may start with "0x..."
	h := hexPayload
	if len(h) >= 2 && (h[:2] == "0x" || h[:2] == "0X") {
		h = h[2:]
	}
	p, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	return &Bind{
		inner:    inner,
		port443:  port,
		payload:  p,
		lastSent: make(map[netip.Addr]time.Time),
		interval: minInterval,
	}, nil
}

func (b *Bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) { return b.inner.Open(port) }
func (b *Bind) Close() error                                        { return b.inner.Close() }
func (b *Bind) SetMark(m uint32) error                              { return b.inner.SetMark(m) }
func (b *Bind) ParseEndpoint(s string) (conn.Endpoint, error)       { return b.inner.ParseEndpoint(s) }
func (b *Bind) BatchSize() int                                      { return b.inner.BatchSize() }

// handshakeInitiation reports whether buf looks like a WG handshake initiation.
// Per spec: first byte == 1 (init), next 3 bytes are reserved = 0. Size is 148 for init.
// (We check both the header bytes and the size to be strict.)
func handshakeInitiation(buf []byte) bool {
	if len(buf) < device.MessageInitiationSize {
		return false
	}
	// Heuristic used by Wireshark dissector: type in first byte, next 3 zero. 
	// Then confirm expected full length for initiation.
	return buf[0] == byte(device.MessageInitiationType) && buf[1] == 0 && buf[2] == 0 && buf[3] == 0 &&
		len(buf) >= device.MessageInitiationSize
}

func (b *Bind) maybePreflight(ep conn.Endpoint, bufs [][]byte) {
	dst := ep.DstIP()
	var seenInit bool
	for _, buf := range bufs {
		if handshakeInitiation(buf) {
			seenInit = true
			break
		}
	}
	if !seenInit {
		return
	}
	now := time.Now()
	b.mu.Lock()
	last := b.lastSent[dst]
	if now.Sub(last) < b.interval {
		b.mu.Unlock()
		return
	}
	b.lastSent[dst] = now
	b.mu.Unlock()

	// Fire-and-forget best-effort UDP/443 send to the same host as the WG endpoint.
	go func(ip netip.Addr) {
		host := ip.String()
		conn, err := net.DialTimeout("udp", net.JoinHostPort(host, strconv.Itoa(b.port443)), 400*time.Millisecond)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
		_, _ = conn.Write(b.payload)
	}(dst)
}

func (b *Bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.maybePreflight(ep, bufs)
	return b.inner.Send(bufs, ep)
}
