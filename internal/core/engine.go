// Package core is the implementation behind the C ABI in docs/ABI.md: it owns
// the session the app handed over, the tunnel stack built from it and the
// local proxy listeners, and exposes them as the few operations the ABI has.
//
// Nothing here authenticates, refreshes or persists a session — that is the
// app's control plane. This package consumes the session and the routing
// policy as data and reports what the data plane is doing.
package core

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"geektrust/internal/config"
	"geektrust/internal/inbound"
	"geektrust/internal/l3"
	"geektrust/internal/resolver"
	"geektrust/internal/session"
	"geektrust/internal/tunnel"
)

const (
	// supervisorFloor/supervisorCeiling bound the wait between tunnel
	// re-establishment attempts once a credential exists again.
	supervisorFloor   = time.Second
	supervisorCeiling = 30 * time.Second
	// proxyShutdownWait bounds waiting for the listeners to release their
	// ports; it only matters while connections are still unwinding.
	proxyShutdownWait = 5 * time.Second
)

// logger is the library's only diagnostic channel: the ABI has no log
// callback, so tunnel reconnects and session rejections go to stderr (hilog on
// OpenHarmony, logcat on Android).
var logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

// ErrNotInitialized is returned by the calls that need a session before
// geektrust_init has provided one.
var ErrNotInitialized = errors.New("geektrust_init has not been called yet: pass session_json and policy_json first")

// Engine is one library instance: the session, the tunnel stack built from it
// and the proxy listeners. All of it is safe to use before Init (the calls
// either report no session or do nothing).
type Engine struct {
	mu     sync.Mutex
	prov   *provider
	stack  *stack
	server string // gateway certificate identity the stack was built for
	proxy  proxySet

	dials atomic.Uint64

	tunMu sync.Mutex
	tun   *tunnel.Tunnel

	// attachMu serializes attachments (building a device is not instant), and
	// tunDevMu guards the installed one so a replacement and a teardown cannot
	// race.
	attachMu sync.Mutex
	tunDevMu sync.Mutex
	tunDev   *inbound.TunDevice
}

// stack is everything built from one session: the tunnel manager, the l3
// Dialer and the resolver. A session that points at another controller
// replaces it; the same one is reused and swapped in place.
type stack struct {
	ctx     context.Context
	cancel  context.CancelFunc
	manager *tunnel.Manager
	dialer  *l3.Dialer
	res     *resolver.Resolver

	supervising bool
}

// proxySet is the running proxy listeners.
type proxySet struct {
	cancel context.CancelFunc
	done   chan struct{}
	socks  string
	http   string
}

// running reports whether the listeners are still serving (or were never
// started).
func (p proxySet) running() bool {
	if p.cancel == nil {
		return false
	}
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

// stop cancels the listeners and waits, bounded, for Run to release the ports.
func (p proxySet) stop() {
	if p.cancel == nil {
		return
	}
	p.cancel()
	if p.done == nil {
		return
	}
	select {
	case <-p.done:
	case <-time.After(proxyShutdownWait):
		logger.Warn("proxy listeners did not stop in time", "socks", p.socks, "http", p.http)
	}
}

// New builds an engine with no session.
func New() *Engine { return &Engine{prov: &provider{}} }

// Init installs (or replaces) the session and brings the tunnel up.
//
// It returns as soon as the payloads are validated: the tunnel is established
// in the background, repeatedly, so a gateway that is briefly unreachable does
// not fail the call — liveness is reported by Status, and a session the
// controller rejects leaves the engine waiting for the next Init.
func (e *Engine) Init(sessionJSON, policyJSON string) error {
	cred, payload, err := parseSession(sessionJSON, policyJSON)
	if err != nil {
		return err
	}
	server := controllerServerName(payload.BaseURL)

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stack != nil && e.server == server {
		// Same controller: keep the stack (and any live tunnel) and swap the
		// session in. The manager reconnects when the sid changes, which is
		// what "a second call replaces the session" means here.
		e.prov.set(cred)
		e.ensureSupervisor(e.stack)
		return nil
	}

	st := e.newStack(server)
	old := e.stack
	e.stack = st
	e.server = server
	e.prov.set(cred)
	e.ensureSupervisor(st)
	if old != nil {
		old.cancel()
		old.manager.Close()
	}
	logger.Info("session installed", "device_id", cred.DeviceID, "gateways", cred.Gateways, "dns", cred.DNS)
	return nil
}

// newStack wires the data plane for one gateway certificate identity.
func (e *Engine) newStack(server string) *stack {
	ctx, cancel := context.WithCancel(context.Background())
	manager := tunnel.NewManager(e.prov, logger)
	manager.GatewayTLSConfig = &tls.Config{ServerName: server}
	dialer := &l3.Dialer{Manager: manager, Provider: e.prov, Logger: logger}
	return &stack{
		ctx:     ctx,
		cancel:  cancel,
		manager: manager,
		dialer:  dialer,
		res:     resolver.New(e.prov, dialer),
	}
}

// ensureSupervisor starts the stack's tunnel supervisor if it is not running.
// The caller must hold e.mu.
func (e *Engine) ensureSupervisor(st *stack) {
	if st.supervising {
		return
	}
	st.supervising = true
	go e.runSupervisor(st)
}

// runSupervisor holds st.supervising for as long as the tunnel is worth
// supervising, so a supervisor that gave up on a rejected session and a
// geektrust_init that arrived at the same moment cannot leave the stack with
// none.
func (e *Engine) runSupervisor(st *stack) {
	for {
		e.supervise(st)

		e.mu.Lock()
		// Restart only while this is still the installed stack, the app has
		// not closed it, and a session came back; otherwise the next Init
		// starts a supervisor.
		restart := e.stack == st && st.ctx.Err() == nil && e.prov.live()
		st.supervising = restart
		e.mu.Unlock()
		if !restart {
			return
		}
	}
}

// supervise keeps a tunnel up for the stack's lifetime: it records the live
// tunnel (Status reads it) and re-establishes it after a drop, so a session
// that stays valid recovers without waiting for the next proxied connection.
// It exits when the stack is replaced or closed, and when there is no usable
// session left — nothing can be retried until the app calls Init again.
func (e *Engine) supervise(st *stack) {
	backoff := supervisorFloor
	for {
		if st.ctx.Err() != nil {
			return
		}
		tun, err := st.manager.Tunnel(st.ctx)
		if err != nil {
			if st.ctx.Err() != nil || !e.prov.live() {
				return
			}
			logger.Warn("tunnel unavailable", "err", err, "retry_in", backoff)
			if !sleep(st.ctx, backoff) {
				return
			}
			if backoff *= 2; backoff > supervisorCeiling {
				backoff = supervisorCeiling
			}
			continue
		}
		backoff = supervisorFloor
		e.noteTunnel(tun)
		select {
		case <-tun.Dead():
		case <-st.ctx.Done():
			return
		}
	}
}

func (e *Engine) noteTunnel(tun *tunnel.Tunnel) {
	e.tunMu.Lock()
	e.tun = tun
	e.tunMu.Unlock()
}

func (e *Engine) lastTunnel() *tunnel.Tunnel {
	e.tunMu.Lock()
	defer e.tunMu.Unlock()
	return e.tun
}

func (e *Engine) currentStack() *stack {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stack
}

// StartProxies serves SOCKS5 and/or HTTP CONNECT on the given addresses; an
// empty address disables that listener. Calling it again replaces the running
// pair (calling it with the same pair is a no-op).
func (e *Engine) StartProxies(socksAddr, httpAddr string) error {
	socksAddr = strings.TrimSpace(socksAddr)
	httpAddr = strings.TrimSpace(httpAddr)
	if socksAddr == "" && httpAddr == "" {
		return errors.New("no proxy listeners requested: pass a SOCKS5 and/or an HTTP listen address")
	}

	e.mu.Lock()
	if e.stack == nil {
		e.mu.Unlock()
		return ErrNotInitialized
	}
	previous := e.proxy
	if previous.running() && previous.socks == socksAddr && previous.http == httpAddr {
		e.mu.Unlock()
		return nil
	}
	e.mu.Unlock()

	// Replace: release the previous pair before binding the new one, so a
	// reconfiguration cannot collide with our own listeners.
	previous.stop()
	for _, addr := range []string{socksAddr, httpAddr} {
		if addr == "" {
			continue
		}
		if err := probeListen(addr); err != nil {
			return err
		}
	}

	cfg := config.Inbound{
		SOCKS5: config.Listener{Enabled: socksAddr != "", Listen: socksAddr},
		HTTP:   config.Listener{Enabled: httpAddr != "", Listen: httpAddr},
	}
	server := inbound.New(cfg, e, e, logger)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	runErr := make(chan error, 1)

	e.mu.Lock()
	e.proxy = proxySet{cancel: cancel, done: done, socks: socksAddr, http: httpAddr}
	e.mu.Unlock()

	go func() {
		err := server.Run(ctx)
		runErr <- err
		if err != nil && ctx.Err() == nil {
			// A bind failure the probe missed (another process won the port in
			// between); there is no caller left to tell.
			logger.Error("proxy listeners stopped", "err", err)
		}
		close(done)
	}()

	// Run binds the listeners in its own goroutine, so returning here without
	// waiting would hand the app a proxy that refuses connections for a moment.
	if err := awaitListeners(ctx, runErr, []string{socksAddr, httpAddr}, listenTimeout); err != nil {
		cancel()
		e.mu.Lock()
		e.proxy = proxySet{}
		e.mu.Unlock()
		return fmt.Errorf("proxy listeners: %w", err)
	}
	return nil
}

// listenTimeout bounds how long StartProxies waits for the listeners to accept
// connections. Loopback binds and connects are immediate; this only elapses
// when the ports are held by something that never accepts.
const listenTimeout = 3 * time.Second

// awaitListeners waits until every requested address accepts connections, so
// that a success from StartProxies means the proxies are usable. An address
// with port 0 has no known port to probe and is left to the server.
func awaitListeners(ctx context.Context, runErr <-chan error, addrs []string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for _, addr := range addrs {
		if addr == "" || portIsZero(addr) {
			continue
		}
		for {
			conn, err := net.DialTimeout("tcp", addr, 250*time.Millisecond)
			if err == nil {
				conn.Close()
				break
			}
			select {
			case err := <-runErr:
				if err != nil {
					return err
				}
				return errors.New("the proxy server stopped before its listeners came up")
			default:
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("listener %q did not come up: %w", addr, err)
			}
			if !sleep(ctx, 10*time.Millisecond) {
				return ctx.Err()
			}
		}
	}
	return nil
}

func portIsZero(addr string) bool {
	_, port, err := net.SplitHostPort(addr)
	return err == nil && port == "0"
}

// probeListen binds and releases addr so a bad address or a taken port is
// reported to the caller instead of failing silently in the serve goroutine.
// The window between the probe and the real bind only decides which process
// wins a fresh race for the port.
func probeListen(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", addr, err)
	}
	if host == "" {
		return fmt.Errorf("listen address %q needs an explicit host", addr)
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		logger.Warn("proxy listener is not on loopback; the proxies have no authentication", "addr", addr)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("cannot listen on %q: %w", addr, err)
	}
	return ln.Close()
}

// AttachTunFD is the system-VPN shape (OHOS VpnConnection.create, Android
// VpnService): the platform created the interface and hands its file
// descriptor over, and the library carries what the device sends through the
// same tunnel and the same per-connection authorization the proxies use.
//
// Calling it again replaces the running attachment; a failed call leaves the
// previous one running. Close tears it down (and never closes the caller's
// descriptor).
//
// It needs a live tunnel: the tunnel's address (the VIP) is what the device's
// own address is expected to be, and without a session there is nothing to
// forward to. Wait for geektrust_status to report "alive": true before
// attaching, and re-attach after a session change that moves the VIP.
func (e *Engine) AttachTunFD(fd int) error {
	e.attachMu.Lock()
	defer e.attachMu.Unlock()

	if e.currentStack() == nil {
		return ErrNotInitialized
	}
	tun := e.lastTunnel()
	if tun == nil || !tun.Alive() {
		return fmt.Errorf("geektrust_attach_tun_fd: no live tunnel yet, so its address (vip) is unknown: wait for geektrust_status to report \"alive\": true, then attach fd %d", fd)
	}
	vip := tun.VIP()
	if vip == nil || vip.To4() == nil {
		return fmt.Errorf("geektrust_attach_tun_fd: the tunnel has no IPv4 address to answer for (fd %d)", fd)
	}

	// Build before replacing: a failure here must leave the previous
	// attachment untouched.
	device, err := inbound.NewTunDevice(fd, vip, e, e, logger)
	if err != nil {
		return fmt.Errorf("geektrust_attach_tun_fd: %w", err)
	}
	e.tunDevMu.Lock()
	previous := e.tunDev
	e.tunDev = device
	e.tunDevMu.Unlock()
	if previous != nil {
		previous.Close()
	}
	logger.Info("tun-fd inbound attached", "vip", vip.String(), "fd", fd)
	return nil
}

// statusSnapshot is docs/ABI.md's geektrust_status object. Field order is the
// documented one; the app parses it by name.
type statusSnapshot struct {
	Alive        bool     `json:"alive"`
	ABI          int      `json:"abi"`
	VIP          string   `json:"vip,omitempty"`
	Gateway      string   `json:"gateway,omitempty"`
	DeviceID     string   `json:"device_id"`
	Username     string   `json:"username"`
	Gateways     []string `json:"gateways"`
	DialAttempts uint64   `json:"dial_attempts"`
	// Tun is the running attachment's own account of what it carried, and it
	// is absent while nothing is attached. On a platform with no log channel
	// this is the only way to tell a device that sends nothing apart from one
	// whose every flow was refused.
	Tun *inbound.TunStats `json:"tun,omitempty"`
}

// currentTunDevice is the attachment in place right now, or nil.
func (e *Engine) currentTunDevice() *inbound.TunDevice {
	e.tunDevMu.Lock()
	defer e.tunDevMu.Unlock()
	return e.tunDev
}

// Status is a cheap snapshot: it never connects, so it is safe to poll.
func (e *Engine) Status() ([]byte, error) {
	snapshot := statusSnapshot{
		ABI:          ABI,
		Gateways:     []string{},
		DialAttempts: e.dials.Load(),
	}
	if cred := e.prov.current(); cred != nil {
		snapshot.DeviceID = cred.DeviceID
		snapshot.Username = cred.Username
		snapshot.Gateways = append(snapshot.Gateways, cred.Gateways...)
	}
	// alive is the tunnel's own liveness, and vip/gateway only describe a
	// tunnel that is still up — a dead one must not look connected.
	if tun := e.lastTunnel(); tun != nil && tun.Alive() {
		snapshot.Alive = true
		if vip := tun.VIP(); vip != nil {
			snapshot.VIP = vip.String()
		}
		snapshot.Gateway = tun.Addr()
	}
	if device := e.currentTunDevice(); device != nil {
		stats := device.Stats()
		snapshot.Tun = &stats
	}
	return json.Marshal(snapshot)
}

// Close tears the tunnel, the tun attachment and the listeners down. It is
// safe before Init and after a previous Close. The descriptor a caller handed
// to AttachTunFD is left open.
func (e *Engine) Close() {
	// Take the attachment lock so a Close that races an in-flight
	// geektrust_attach_tun_fd tears down what that call installed, instead of
	// letting it install a device nothing will ever stop.
	e.attachMu.Lock()
	defer e.attachMu.Unlock()

	e.mu.Lock()
	st := e.stack
	e.stack = nil
	e.server = ""
	proxies := e.proxy
	e.proxy = proxySet{}
	e.mu.Unlock()

	e.tunDevMu.Lock()
	device := e.tunDev
	e.tunDev = nil
	e.tunDevMu.Unlock()
	if device != nil {
		device.Close()
	}
	if st != nil {
		st.cancel()
		st.manager.Close()
	}
	proxies.stop()
	e.noteTunnel(nil)
	e.prov.set(nil)
}

// Dial implements inbound.Dialer: the inbound proxies and the resolver reach
// the tunnel through the engine, so replacing the session's stack does not
// touch a running listener.
func (e *Engine) Dial(ctx context.Context, ip string, port int, appID, domain string) (net.Conn, error) {
	st := e.currentStack()
	if st == nil {
		return nil, ErrNotInitialized
	}
	e.dials.Add(1)
	return st.dialer.Dial(ctx, ip, port, appID, domain)
}

// DialUDP implements inbound.Dialer's connected-UDP half.
func (e *Engine) DialUDP(ctx context.Context, ip string, port int, appID, domain string) (net.Conn, error) {
	st := e.currentStack()
	if st == nil {
		return nil, ErrNotInitialized
	}
	e.dials.Add(1)
	return st.dialer.DialUDP(ctx, ip, port, appID, domain)
}

// Resolve implements inbound.Resolver.
func (e *Engine) Resolve(ctx context.Context, host string, port int) (resolver.Resolution, error) {
	st := e.currentStack()
	if st == nil {
		return resolver.Resolution{}, ErrNotInitialized
	}
	return st.res.Resolve(ctx, host, port)
}

// ResolveUDP implements inbound.Resolver's UDP half.
func (e *Engine) ResolveUDP(ctx context.Context, host string, port int) (resolver.Resolution, error) {
	st := e.currentStack()
	if st == nil {
		return resolver.Resolution{}, ErrNotInitialized
	}
	return st.res.ResolveUDP(ctx, host, port)
}

func sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

var _ session.CredentialProvider = (*provider)(nil)
