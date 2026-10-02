package resolver

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type dnsDialFunc func(context.Context, string, string) (net.Conn, error)
type lookupStage func(context.Context, string) (net.IP, error)

type dnsRetryPolicy struct {
	udpTimeout, tcpTimeout    time.Duration
	baseCooldown, maxCooldown time.Duration
}

var defaultDNSRetryPolicy = dnsRetryPolicy{
	udpTimeout:   1500 * time.Millisecond,
	tcpTimeout:   3 * time.Second,
	baseCooldown: 30 * time.Second,
	maxCooldown:  5 * time.Minute,
}

// dnsPool keeps transport failures separate from negative DNS answers. State
// lives only in this Resolver and is discarded when its routing scope changes.
type dnsPool struct {
	mu      sync.Mutex
	scope   string
	servers map[string]*dnsServerHealth
	flights map[string]*dnsLookupCall
	now     func() time.Time
	policy  dnsRetryPolicy
}

type dnsServerHealth struct {
	udpHealthy, udpProbe, serverProbe bool
	udpFailures, serverFailures       int
	udpRetryAt, serverRetryAt         time.Time
	udpGeneration, serverGeneration   uint64
}

type dnsCandidate struct {
	server string
	health *dnsServerHealth
	due    bool
}

func newDNSPool() *dnsPool {
	return &dnsPool{servers: make(map[string]*dnsServerHealth), flights: make(map[string]*dnsLookupCall), now: time.Now, policy: defaultDNSRetryPolicy}
}

func (p *dnsPool) candidates(scope string, servers []string) []dnsCandidate {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.scope != scope {
		p.scope = scope
		p.servers = make(map[string]*dnsServerHealth)
	}
	seen := make(map[string]bool)
	var out []dnsCandidate
	now := p.now()
	for _, server := range servers {
		if seen[server] {
			continue
		}
		seen[server] = true
		h := p.servers[server]
		if h == nil {
			h = &dnsServerHealth{udpHealthy: true}
			p.servers[server] = h
		}
		if h.serverProbe || now.Before(h.serverRetryAt) {
			continue
		}
		out = append(out, dnsCandidate{server: server, health: h, due: !h.serverRetryAt.IsZero()})
	}
	// A previously unavailable server gets a bounded recovery probe once due,
	// even if a later server keeps answering. Preserve configured order otherwise.
	sort.SliceStable(out, func(i, j int) bool { return out[i].due && !out[j].due })
	return out
}

func (p *dnsPool) beginServer(h *dnsServerHealth) (uint64, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if h.serverProbe || p.now().Before(h.serverRetryAt) {
		return 0, false
	}
	if !h.serverRetryAt.IsZero() {
		h.serverProbe = true
	}
	return h.serverGeneration, true
}

func (p *dnsPool) finishServer(h *dnsServerHealth, generation uint64, reply bool, canceled bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if reply {
		h.serverFailures = 0
		h.serverRetryAt = time.Time{}
		h.serverProbe = false
		h.serverGeneration++
	} else if h.serverGeneration == generation {
		h.serverProbe = false
		if !canceled {
			h.serverFailures++
			h.serverRetryAt = p.now().Add(p.cooldown(h.serverFailures))
			h.serverGeneration++
		}
	}
}

func (p *dnsPool) beginUDP(h *dnsServerHealth) (uint64, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if h.udpProbe || p.now().Before(h.udpRetryAt) {
		return 0, false
	}
	if !h.udpHealthy {
		h.udpProbe = true
	}
	return h.udpGeneration, true
}

func (p *dnsPool) finishUDP(h *dnsServerHealth, generation uint64, reply, canceled bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if h.udpGeneration != generation {
		return
	}
	h.udpProbe = false
	if canceled {
		return
	}
	if reply {
		if !h.udpHealthy {
			h.udpGeneration++
		}
		h.udpHealthy = true
		h.udpFailures = 0
		h.udpRetryAt = time.Time{}
	} else {
		h.udpHealthy = false
		h.udpFailures++
		h.udpRetryAt = p.now().Add(p.cooldown(h.udpFailures))
		h.udpGeneration++
	}
}

func (p *dnsPool) cooldown(failures int) time.Duration {
	delay := p.policy.baseCooldown
	for i := 1; i < failures && delay < p.policy.maxCooldown; i++ {
		if delay > p.policy.maxCooldown/2 {
			return p.policy.maxCooldown
		}
		delay *= 2
	}
	if delay > p.policy.maxCooldown {
		return p.policy.maxCooldown
	}
	return delay
}

var errDNSCoolingDown = errors.New("DNS servers are temporarily unavailable")
var errDNSNeedsTCP = errors.New("truncated DNS response requires TCP")

type dnsLookupCall struct {
	done     chan struct{}
	cancel   context.CancelFunc
	waiters  int
	finished bool
	ip       net.IP
	err      error
}

// Share identical lookups without letting one caller's cancellation cancel
// other callers. The transport budgets still apply to the shared operation.
func (p *dnsPool) lookup(ctx context.Context, host, scope string, servers []string, dial dnsDialFunc) (net.IP, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := scope + "\x00" + strings.ToLower(host) + "\x00" + strings.Join(servers, "\x00")
	p.mu.Lock()
	call := p.flights[key]
	if call == nil {
		sharedCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
		call = &dnsLookupCall{done: make(chan struct{}), cancel: cancel}
		p.flights[key] = call
		go func() {
			ip, err := p.lookupPool(sharedCtx, host, scope, servers, dial)
			p.mu.Lock()
			call.ip, call.err, call.finished = ip, err, true
			if p.flights[key] == call {
				delete(p.flights, key)
			}
			close(call.done)
			p.mu.Unlock()
			cancel()
		}()
	}
	call.waiters++
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		call.waiters--
		if call.waiters == 0 && !call.finished {
			if p.flights[key] == call {
				delete(p.flights, key)
			}
			call.cancel()
		}
		p.mu.Unlock()
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-call.done:
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return append(net.IP(nil), call.ip...), call.err
	}
}

func (p *dnsPool) lookupPool(ctx context.Context, host, scope string, servers []string, dial dnsDialFunc) (net.IP, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	lastErr := error(errDNSCoolingDown)
	for _, candidate := range p.candidates(scope, servers) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		generation, ok := p.beginServer(candidate.health)
		if !ok {
			continue
		}
		ip, err, attempt := p.lookupServer(ctx, host, candidate.server, candidate.health, dial)
		p.finishServer(candidate.health, generation, attempt.reply, ctx.Err() != nil || !attempt.started)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err == nil {
			return ip, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

type dnsAttempt struct {
	started bool // The resolver invoked the transport dialer.
	reply   bool // A matching DNS reply was received from the transport.
}

func (p *dnsPool) lookupServer(ctx context.Context, host, server string, h *dnsServerHealth, dial dnsDialFunc) (net.IP, error, dnsAttempt) {
	var attempt dnsAttempt
	if generation, ok := p.beginUDP(h); ok {
		ip, err, udp := lookupDNSAttempt(ctx, host, server, "udp", p.policy.udpTimeout, dial)
		p.finishUDP(h, generation, udp.reply, ctx.Err() != nil || !udp.started)
		attempt = udp
		if ctx.Err() != nil {
			return nil, ctx.Err(), attempt
		}
		var dnsErr *net.DNSError
		if !udp.started || err == nil || errors.Is(err, errNoIPv4Answer) || (errors.As(err, &dnsErr) && dnsErr.IsNotFound) {
			return ip, err, attempt
		}
	}
	ip, err, tcp := lookupDNSAttempt(ctx, host, server, "tcp", p.policy.tcpTimeout, dial)
	return ip, err, dnsAttempt{started: attempt.started || tcp.started, reply: attempt.reply || tcp.reply}
}

// Each transport gets one total budget, including authorization, dialing and
// resolver retries. A truncated UDP response receives a fresh TCP budget.
func lookupDNSAttempt(ctx context.Context, host, server, transport string, timeout time.Duration, dial dnsDialFunc) (net.IP, error, dnsAttempt) {
	attemptCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var reply atomic.Bool
	var started atomic.Bool
	resolver := &net.Resolver{PreferGo: true, Dial: func(_ context.Context, network, _ string) (net.Conn, error) {
		if transport == "udp" && (network == "tcp" || network == "tcp4" || network == "tcp6") {
			return nil, errDNSNeedsTCP
		}
		if err := attemptCtx.Err(); err != nil {
			return nil, err
		}
		started.Store(true)
		conn, err := dial(attemptCtx, transport, net.JoinHostPort(server, "53"))
		if err != nil {
			return nil, err
		}
		watched := &dnsObservedConn{Conn: conn, reply: &reply, stream: transport == "tcp"}
		watched.stop = context.AfterFunc(attemptCtx, func() { _ = conn.Close() })
		if pc, ok := conn.(net.PacketConn); ok && transport == "udp" {
			return &dnsObservedPacketConn{dnsObservedConn: watched, packet: pc}, nil
		}
		return watched, nil
	}}
	ip, err := lookupIPv4With(attemptCtx, resolver, host)
	return ip, err, dnsAttempt{started: started.Load(), reply: reply.Load()}
}

// Preserve PacketConn on UDP sockets: net.Resolver uses it to select datagram
// DNS rather than the length-prefixed TCP wire format.
type dnsObservedConn struct {
	net.Conn
	reply        *atomic.Bool
	stream       bool
	stop         func() bool
	mu           sync.Mutex
	id           uint16
	question     dnsmessage.Question
	haveQuestion bool
	input        []byte
}

func (c *dnsObservedConn) Write(b []byte) (int, error) {
	query := b
	if c.stream && len(query) >= 2 {
		query = query[2:]
	}
	var parser dnsmessage.Parser
	h, err := parser.Start(query)
	if err == nil {
		q, e := parser.Question()
		if e == nil {
			c.mu.Lock()
			c.id = h.ID
			c.question = q
			c.haveQuestion = true
			c.input = nil
			c.mu.Unlock()
		}
	}
	return c.Conn.Write(b)
}

func (c *dnsObservedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.observe(b[:n])
	}
	return n, err
}

func (c *dnsObservedConn) observe(b []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.haveQuestion {
		return
	}
	if c.stream {
		if len(c.input)+len(b) > 65537 {
			return
		}
		c.input = append(c.input, b...)
		if len(c.input) < 2 {
			return
		}
		size := int(binary.BigEndian.Uint16(c.input[:2]))
		if len(c.input) < size+2 {
			return
		}
		b = c.input[2 : size+2]
	}
	var parser dnsmessage.Parser
	h, err := parser.Start(b)
	if err != nil || !h.Response || h.ID != c.id {
		return
	}
	q, err := parser.Question()
	if err == nil && q.Type == c.question.Type && q.Class == c.question.Class && strings.EqualFold(q.Name.String(), c.question.Name.String()) {
		c.reply.Store(true)
	}
}

func (c *dnsObservedConn) Close() error {
	if c.stop != nil {
		c.stop()
	}
	return c.Conn.Close()
}

type dnsObservedPacketConn struct {
	*dnsObservedConn
	packet net.PacketConn
}

func (c *dnsObservedPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.packet.ReadFrom(b)
	if n > 0 {
		c.observe(b[:n])
	}
	return n, addr, err
}
func (c *dnsObservedPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return c.packet.WriteTo(b, addr)
}
