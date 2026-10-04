package inbound

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
	"github.com/metacubex/gvisor/pkg/waiter"
)

const (
	// tunNICID is the tun stack's single NIC.
	tunNICID tcpip.NICID = 1
	// tunMTU matches the aTrust tunnel MTU, so a packet the stack emits toward
	// the device is never larger than what the relay can carry back.
	tunMTU = 1400
	// maxTunPacket is the largest IPv4 packet one read may return.
	maxTunPacket = 65535
	// tunOutboundQueue bounds the packets queued from the stack to the device.
	tunOutboundQueue = 1024
	// tunReadInterval bounds one read: a read deadline is how the reader
	// notices Close (and a replacement attachment) without waiting for the
	// platform to close the descriptor.
	tunReadInterval = 250 * time.Millisecond
	// tunWriteTimeout bounds one outbound write so a wedged descriptor cannot
	// stall the stack's uplink forever.
	tunWriteTimeout = 30 * time.Second
	// tunShutdownWait bounds Close waiting for in-flight relays to unwind.
	tunShutdownWait = 5 * time.Second
	// tunPendingHandshakes bounds the forwarded TCP connections waiting to be
	// accepted.
	tunPendingHandshakes = 1024
	// tunDialTimeout bounds resolving and authorizing one forwarded flow.
	tunDialTimeout = 30 * time.Second
)

// TunDevice carries IPv4 packets between a platform tun file descriptor (OHOS
// VpnConnection.create, Android VpnService) and the tunnel.
//
// It owns a gVisor stack addressed by the tunnel VIP: packets read from the
// descriptor are delivered into it, the packets it emits are written back to
// the descriptor, and the TCP and UDP flows it terminates are relayed through
// the same Dialer and Resolver the proxy inbounds use — so authorization,
// gateway selection and policy are identical in both shapes.
//
// A descriptor is a packet device: one read yields one IPv4 packet and one
// write sends one. The device never seeks and never closes the descriptor it
// was handed; it works on a private duplicate it opens and closes itself.
type TunDevice struct {
	file     *os.File
	stack    *stack.Stack
	endpoint *channel.Endpoint
	resolver Resolver
	dialer   Dialer
	logger   *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc

	reads  sync.WaitGroup
	writes sync.WaitGroup

	flowMu sync.Mutex
	flows  sync.WaitGroup
	closed bool
}

// NewTunDevice starts carrying traffic across fd. vip is the tunnel address the
// stack answers for (an ICMP echo to it is answered by the stack itself); all
// other destinations are terminated here and forwarded through dialer.
//
// The returned device is already running. A failure leaves nothing behind: it
// never touches any device that is already attached, so the caller can replace
// an attachment only after the new one was built.
func NewTunDevice(fd int, vip net.IP, resolver Resolver, dialer Dialer, logger *slog.Logger) (*TunDevice, error) {
	if resolver == nil || dialer == nil {
		return nil, errors.New("tun: a resolver and a dialer are required")
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	v4 := vip.To4()
	if v4 == nil {
		return nil, fmt.Errorf("tun: %v is not an IPv4 tunnel address", vip)
	}
	if fd < 0 {
		return nil, fmt.Errorf("tun: invalid file descriptor %d", fd)
	}

	// Work on a private duplicate: teardown stops the reader by expiring its
	// read deadline and closes only this copy, so the descriptor the platform
	// owns stays open and usable.
	dupFD, err := syscall.Dup(fd)
	if err != nil {
		return nil, fmt.Errorf("tun: cannot duplicate fd %d: %w", fd, err)
	}
	// Non-blocking before wrapping it: os.File only registers a descriptor it
	// can poll, and a pollable descriptor is what makes the read deadline (and
	// therefore Close) work.
	if err := syscall.SetNonblock(dupFD, true); err != nil {
		syscall.Close(dupFD)
		return nil, fmt.Errorf("tun: cannot put fd %d in non-blocking mode: %w", fd, err)
	}
	file := os.NewFile(uintptr(dupFD), "geektrust-tun")
	if file == nil {
		syscall.Close(dupFD)
		return nil, fmt.Errorf("tun: fd %d is not usable as a file", fd)
	}
	// A descriptor that cannot carry a deadline cannot be interrupted, so the
	// reader could never be stopped or replaced; refuse it instead of leaking
	// a goroutine per attachment.
	if err := file.SetReadDeadline(time.Time{}); err != nil {
		file.Close()
		return nil, fmt.Errorf("tun: fd %d is not pollable, so the inbound could not be stopped or replaced: %w", fd, err)
	}

	device, err := newTunStack(file, v4, resolver, dialer, logger)
	if err != nil {
		file.Close()
		return nil, err
	}
	return device, nil
}

// newTunStack builds the stack facing the descriptor and starts its two loops:
// device to stack and stack to device. Relays start per flow. It takes
// ownership of file.
func newTunStack(file *os.File, vip net.IP, resolver Resolver, dialer Dialer, logger *slog.Logger) (*TunDevice, error) {
	endpoint := channel.New(tunOutboundQueue, tunMTU, "")
	gstack := stack.New(stack.Options{
		// The stack terminates the device's flows, so a packet addressed to
		// the stack's own tun address must not loop back inside it: the reply
		// has to leave through the descriptor.
		HandleLocal:        false,
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	if err := gstack.CreateNICWithOptions(tunNICID, endpoint, stack.NICOptions{}); err != nil {
		gstack.Destroy()
		return nil, fmt.Errorf("tun: create IP stack NIC: %s", err)
	}
	// Every packet the device sends is addressed to an address this stack does
	// not own — that is what a VPN interface is for. Promiscuous mode makes
	// each such destination a temporary local address, which is what routes
	// the packet to the TCP/UDP forwarders below instead of dropping it as
	// unrouteable (with forwarding off) or handing it straight back to the
	// device (with forwarding on).
	if err := gstack.SetPromiscuousMode(tunNICID, true); err != nil {
		gstack.Destroy()
		return nil, fmt.Errorf("tun: enable promiscuous mode: %s", err)
	}
	// Promiscuous mode accepts any destination; spoofing is what lets the
	// replies be routed back out of the same temporary address (the route
	// lookup for an outbound packet consults the NIC's spoofing flag, not its
	// promiscuous one). Both are required for a transparent forwarder.
	if err := gstack.SetSpoofing(tunNICID, true); err != nil {
		gstack.Destroy()
		return nil, fmt.Errorf("tun: enable address spoofing: %s", err)
	}
	protoAddr := tcpip.ProtocolAddress{
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFromSlice(vip), PrefixLen: 32},
		Protocol:          ipv4.ProtocolNumber,
	}
	if err := gstack.AddProtocolAddress(tunNICID, protoAddr, stack.AddressProperties{}); err != nil {
		gstack.Destroy()
		return nil, fmt.Errorf("tun: add tunnel address: %s", err)
	}
	gstack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: tunNICID})
	// Same TCP tuning as the tunnel-facing stack: SACK and a modern congestion
	// control keep the device-facing half honest about what the tunnel can
	// carry. A rejected option is a toolchain difference, not a failure.
	sack := tcpip.TCPSACKEnabled(true)
	_ = gstack.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
	congestionControl := tcpip.CongestionControlOption("cubic")
	_ = gstack.SetTransportProtocolOption(tcp.ProtocolNumber, &congestionControl)

	ctx, cancel := context.WithCancel(context.Background())
	device := &TunDevice{
		file:     file,
		stack:    gstack,
		endpoint: endpoint,
		resolver: resolver,
		dialer:   dialer,
		logger:   logger,
		ctx:      ctx,
		cancel:   cancel,
	}
	// TCP and UDP get forwarders; ICMP deliberately does not. An echo
	// addressed to the tunnel VIP is answered by the ipv4 protocol itself, and
	// an echo to any other address has no per-connection authorization path in
	// the tunnel — so it is dropped here rather than reflected back out of the
	// tun, which would loop it straight back into the device.
	tcpForwarder := tcp.NewForwarder(gstack, 0, tunPendingHandshakes, device.handleTCP)
	gstack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	udpForwarder := udp.NewForwarder(gstack, device.handleUDP)
	gstack.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	device.reads.Add(1)
	go device.readLoop()
	device.writes.Add(1)
	go device.writeLoop()
	return device, nil
}

// Close stops the reader and the writer, unwinds the in-flight relays, tears
// the stack down and closes the private duplicate of the descriptor. The
// descriptor the caller handed over is left open. Close is idempotent.
func (d *TunDevice) Close() {
	d.flowMu.Lock()
	if d.closed {
		d.flowMu.Unlock()
		return
	}
	d.closed = true
	d.flowMu.Unlock()

	// Wake the blocked read and stop anything the relays are still dialing.
	d.cancel()
	_ = d.file.SetReadDeadline(time.Now())
	d.reads.Wait()
	// The stack owns the device-facing connections the relays are reading;
	// destroying it is what unblocks them.
	d.stack.Destroy()
	// Release the outbound queue's read side (idempotent if Destroy already
	// closed it) so a writer parked on it cannot outlive the device.
	d.endpoint.Close()
	d.writes.Wait()
	waitBounded(&d.flows, tunShutdownWait, func() {
		d.logger.Warn("tun flows did not unwind in time", "wait", tunShutdownWait)
	})
	_ = d.file.Close()
}

// waitBounded waits for wg, or reports a timeout instead of blocking forever.
func waitBounded(wg *sync.WaitGroup, limit time.Duration, onTimeout func()) {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		onTimeout()
	}
}

// startFlow runs one relay unless the device is closing, so Close never races
// a WaitGroup that is still being added to.
func (d *TunDevice) startFlow(run func()) bool {
	d.flowMu.Lock()
	if d.closed {
		d.flowMu.Unlock()
		return false
	}
	d.flows.Add(1)
	d.flowMu.Unlock()
	go func() {
		defer d.flows.Done()
		run()
	}()
	return true
}

// readLoop delivers every packet the descriptor produces into the stack.
func (d *TunDevice) readLoop() {
	defer d.reads.Done()
	packet := make([]byte, maxTunPacket)
	for {
		if d.ctx.Err() != nil {
			return
		}
		// A deadline is how this loop learns that Close ran; a packet that
		// arrives sooner returns immediately, so it costs no latency.
		if err := d.file.SetReadDeadline(time.Now().Add(tunReadInterval)); err != nil {
			d.logger.Debug("tun read deadline unavailable", "err", err)
		}
		n, err := d.file.Read(packet)
		if err != nil {
			if d.ctx.Err() != nil {
				return
			}
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			d.logger.Warn("tun descriptor read failed; stopping", "err", err)
			// A hard read error means the device is gone; stop the writer and
			// the relays too instead of leaving half of it running.
			d.cancel()
			return
		}
		if n <= 0 {
			continue
		}
		// Only IPv4 is carried; anything else is not a packet this stack can
		// make sense of.
		if packet[0]>>4 != 4 {
			d.logger.Debug("tun packet dropped: not IPv4", "version", packet[0]>>4)
			continue
		}
		// The stack takes ownership of the payload, so hand it its own copy.
		data := make([]byte, n)
		copy(data, packet[:n])
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
		d.endpoint.InjectInbound(ipv4.ProtocolNumber, pkt)
		pkt.DecRef()
	}
}

// writeLoop sends every packet the stack emits to the descriptor.
func (d *TunDevice) writeLoop() {
	defer d.writes.Done()
	for {
		pkt := d.endpoint.ReadContext(d.ctx)
		if pkt == nil {
			return
		}
		// packetBytes may reference the packet's own buffer, so the write
		// happens before the last reference is dropped.
		data := packetBytes(pkt)
		if len(data) > 0 {
			if err := d.file.SetWriteDeadline(time.Now().Add(tunWriteTimeout)); err != nil {
				d.logger.Debug("tun write deadline unavailable", "err", err)
			}
			n, err := d.file.Write(data)
			if err != nil {
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					pkt.DecRef()
					d.logger.Warn("tun descriptor write failed; stopping", "err", err)
					// A hard write error means the device is gone; stop the
					// reader and the relays too.
					d.cancel()
					return
				}
				// The descriptor is full and did not drain; the stack will
				// retransmit what matters.
				d.logger.Debug("tun write timed out; packet dropped", "bytes", len(data))
			} else if n != len(data) {
				// A packet device writes a whole packet or none of it.
				d.logger.Debug("tun write truncated", "wrote", n, "want", len(data))
			}
		}
		pkt.DecRef()
	}
}

// packetBytes flattens a packet's backing buffers into one contiguous slice.
// A single-view packet — the common case for an IPv4 packet this stack built —
// needs no copy at all.
func packetBytes(pkt *stack.PacketBuffer) []byte {
	views, offset := pkt.AsViewList()
	first := views.Front()
	if first == nil {
		return nil
	}
	if first.Next() == nil {
		data := first.AsSlice()
		if offset > len(data) {
			return nil
		}
		return data[offset:]
	}
	data := make([]byte, pkt.Size())
	written := 0
	for view := first; view != nil; view = view.Next() {
		part := view.AsSlice()
		if offset >= len(part) {
			offset -= len(part)
			continue
		}
		part = part[offset:]
		offset = 0
		written += copy(data[written:], part)
	}
	return data[:written]
}

// handleTCP terminates one device-side TCP connection and relays it through
// the tunnel dialer. The destination comes from the packet itself: the device
// resolved the name, we only carry the flow.
func (d *TunDevice) handleTCP(request *tcp.ForwarderRequest) {
	target := request.ID()
	var wq waiter.Queue
	ep, err := request.CreateEndpoint(&wq)
	if err != nil {
		request.Complete(true)
		return
	}
	request.Complete(false)
	conn := gonet.NewTCPConn(&wq, ep)
	if !d.startFlow(func() { d.relayTCP(conn, target) }) {
		conn.Close()
	}
}

func (d *TunDevice) relayTCP(conn net.Conn, target stack.TransportEndpointID) {
	defer conn.Close()
	dstIP := net.IP(target.LocalAddress.AsSlice())
	dstPort := int(target.LocalPort)

	ctx, cancel := context.WithTimeout(d.ctx, tunDialTimeout)
	resolution, err := d.resolver.Resolve(ctx, dstIP.String(), dstPort)
	if err != nil {
		cancel()
		d.logger.Debug("tun TCP flow refused", "ip", dstIP.String(), "port", dstPort, "err", err)
		return
	}
	upstream, err := d.dialer.Dial(ctx, resolution.IP, dstPort, resolution.AppID, resolution.Domain)
	cancel()
	if err != nil {
		d.logger.Debug("tun TCP flow not carried", "ip", resolution.IP, "port", dstPort, "err", err)
		return
	}
	relayPair(conn, upstream)
}

// handleUDP terminates one device-side UDP flow and relays its datagrams
// through the tunnel dialer. Datagrams for the flow after the first arrive at
// the endpoint, not here.
func (d *TunDevice) handleUDP(request *udp.ForwarderRequest) bool {
	target := request.ID()
	var wq waiter.Queue
	ep, err := request.CreateEndpoint(&wq)
	if err != nil {
		return true
	}
	conn := gonet.NewUDPConn(&wq, ep)
	if !d.startFlow(func() { d.relayUDP(conn, target) }) {
		conn.Close()
	}
	return true
}

func (d *TunDevice) relayUDP(conn *gonet.UDPConn, target stack.TransportEndpointID) {
	defer conn.Close()
	dstIP := net.IP(target.LocalAddress.AsSlice())
	dstPort := int(target.LocalPort)

	ctx, cancel := context.WithTimeout(d.ctx, tunDialTimeout)
	resolution, err := d.resolver.ResolveUDP(ctx, dstIP.String(), dstPort)
	if err != nil {
		cancel()
		d.logger.Debug("tun UDP flow refused", "ip", dstIP.String(), "port", dstPort, "err", err)
		return
	}
	upstream, err := d.dialer.DialUDP(ctx, resolution.IP, dstPort, resolution.AppID, resolution.Domain)
	cancel()
	if err != nil {
		d.logger.Debug("tun UDP flow not carried", "ip", resolution.IP, "port", dstPort, "err", err)
		return
	}
	defer upstream.Close()

	downstreamDone := make(chan struct{})
	go func() {
		defer close(downstreamDone)
		buf := make([]byte, maxTunPacket)
		for {
			_ = upstream.SetReadDeadline(time.Now().Add(udpFlowIdle))
			n, err := upstream.Read(buf)
			if err != nil {
				return
			}
			if n == 0 {
				continue
			}
			if n > maxUDPPayload {
				// Answering with a fragment the device never asked for would
				// be worse than not answering.
				d.logger.Debug("tunnel UDP datagram exceeds the tun MTU; dropped", "bytes", n)
				continue
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	buf := make([]byte, maxTunPacket)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(udpFlowIdle))
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		if n == 0 {
			continue
		}
		if n > maxUDPPayload {
			// Larger than the tunnel can carry in one datagram; dropping it is
			// honest, fragmenting it here is not.
			d.logger.Debug("tun UDP datagram exceeds the tunnel MTU; dropped", "bytes", n)
			continue
		}
		if _, err := upstream.Write(buf[:n]); err != nil {
			break
		}
	}
	// Unblock the downstream copy (a read deadline of its own is already
	// running, but closing is immediate and unambiguous).
	upstream.Close()
	conn.Close()
	<-downstreamDone
}
