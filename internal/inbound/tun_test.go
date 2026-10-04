package inbound

import (
	"bytes"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"geektrust/internal/resolver"
)

// The tun-fd inbound is proven offline with a datagram socketpair standing in
// for the platform's tun device: the test holds one end and writes one IPv4
// packet per write, exactly as a packet device does, and the inbound gets the
// other end. No tunnel and no network namespace are involved.

const (
	icmpProtocol = 1
	tcpProtocol  = 6
	udpProtocol  = 17
	tcpSyn       = 0x02
	tcpPsh       = 0x08
	tcpAck       = 0x10
)

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// testTunPair returns the device end of a datagram socketpair plus a file for
// the peer the test drives. The device works on a duplicate; the raw fd passed
// here is what a platform VPN shell would own.
func testTunPair(t *testing.T) (*os.File, int) {
	t.Helper()
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	if err := syscall.SetNonblock(pair[0], true); err != nil {
		syscall.Close(pair[0])
		syscall.Close(pair[1])
		t.Fatalf("set non-blocking on test end: %v", err)
	}
	peer := os.NewFile(uintptr(pair[0]), "tun-test-peer")
	if peer == nil {
		syscall.Close(pair[0])
		syscall.Close(pair[1])
		t.Fatal("os.NewFile failed for the test end")
	}
	t.Cleanup(func() { peer.Close() })
	return peer, pair[1]
}

// newTestTunDevice attaches a device to fd and closes the fd the test handed
// over, so only the device's private duplicate keeps the pair alive.
func newTestTunDevice(t *testing.T, fd int, vip net.IP, res Resolver, dial Dialer) *TunDevice {
	t.Helper()
	device, err := NewTunDevice(fd, vip, res, dial, testLogger())
	syscall.Close(fd)
	if err != nil {
		t.Fatalf("NewTunDevice: %v", err)
	}
	t.Cleanup(device.Close)
	return device
}

func readTunPacket(t *testing.T, peer *os.File, timeout time.Duration) []byte {
	t.Helper()
	if err := peer.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 65535)
	n, err := peer.Read(buf)
	if err != nil {
		t.Fatalf("read packet from the device: %v", err)
	}
	return buf[:n]
}

// drainPeer consumes anything already queued so a later phase cannot read a
// stale packet.
func drainPeer(peer *os.File) {
	for {
		if err := peer.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
			return
		}
		buf := make([]byte, 65535)
		if _, err := peer.Read(buf); err != nil {
			return
		}
	}
}

func testIPv4(src, dst net.IP, protocol byte, transport []byte) []byte {
	packet := make([]byte, 20+len(transport))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = protocol
	copy(packet[12:16], src.To4())
	copy(packet[16:20], dst.To4())
	binary.BigEndian.PutUint16(packet[10:12], internetChecksum(packet[:20]))
	copy(packet[20:], transport)
	return packet
}

func icmpEchoRequest(src, dst net.IP, id, seq uint16, payload []byte) []byte {
	message := make([]byte, 8+len(payload))
	message[0] = 8 // echo request
	binary.BigEndian.PutUint16(message[4:6], id)
	binary.BigEndian.PutUint16(message[6:8], seq)
	copy(message[8:], payload)
	binary.BigEndian.PutUint16(message[2:4], internetChecksum(message))
	return testIPv4(src, dst, icmpProtocol, message)
}

func udpDatagram(src, dst net.IP, sport, dport uint16, payload []byte) []byte {
	segment := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(segment[0:2], sport)
	binary.BigEndian.PutUint16(segment[2:4], dport)
	binary.BigEndian.PutUint16(segment[4:6], uint16(len(segment)))
	copy(segment[8:], payload)
	binary.BigEndian.PutUint16(segment[6:8], transportChecksum(src, dst, udpProtocol, segment))
	return testIPv4(src, dst, udpProtocol, segment)
}

func tcpSegment(src, dst net.IP, sport, dport uint16, seq, ack uint32, flags byte, payload []byte) []byte {
	segment := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(segment[0:2], sport)
	binary.BigEndian.PutUint16(segment[2:4], dport)
	binary.BigEndian.PutUint32(segment[4:8], seq)
	binary.BigEndian.PutUint32(segment[8:12], ack)
	segment[12] = 5 << 4 // data offset: no options
	segment[13] = flags
	binary.BigEndian.PutUint16(segment[14:16], 65535)
	copy(segment[20:], payload)
	binary.BigEndian.PutUint16(segment[16:18], transportChecksum(src, dst, tcpProtocol, segment))
	return testIPv4(src, dst, tcpProtocol, segment)
}

func transportChecksum(src, dst net.IP, protocol byte, segment []byte) uint16 {
	pseudo := make([]byte, 12+len(segment))
	copy(pseudo[0:4], src.To4())
	copy(pseudo[4:8], dst.To4())
	pseudo[9] = protocol
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(segment)))
	copy(pseudo[12:], segment)
	return internetChecksum(pseudo)
}

func internetChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + sum>>16
	}
	return ^uint16(sum)
}

// readTCPSegment returns the first packet whose TCP flags contain want.
func readTCPSegment(t *testing.T, peer *os.File, want byte, timeout time.Duration) []byte {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			t.Fatalf("no TCP packet with flags %#x arrived", want)
		}
		packet := readTunPacket(t, peer, remaining)
		if len(packet) < 40 || packet[9] != tcpProtocol {
			continue
		}
		ihl := int(packet[0]&0x0f) * 4
		if packet[ihl+13]&want == want {
			return packet
		}
	}
}

func tcpPayload(packet []byte) []byte {
	ihl := int(packet[0]&0x0f) * 4
	tcpLen := int(packet[ihl+12]>>4) * 4
	return packet[ihl+tcpLen:]
}

// TestTunDeviceAnswersICMPEchoToItsTunnelAddress is the offline proof that
// packets cross the descriptor in both directions: one echo request written to
// the device end comes back as the stack's own echo reply, with the source and
// destination swapped. No tunnel, gateway or session is involved.
func TestTunDeviceAnswersICMPEchoToItsTunnelAddress(t *testing.T) {
	vip := net.IPv4(10, 20, 205, 16)
	deviceAddr := net.IPv4(10, 20, 205, 17)
	peer, fd := testTunPair(t)
	newTestTunDevice(t, fd, vip, &mockResolver{}, &mockDialer{})

	const id, seq = 0x4242, 7
	payload := []byte("geektrust")
	if _, err := peer.Write(icmpEchoRequest(deviceAddr, vip, id, seq, payload)); err != nil {
		t.Fatalf("write echo request: %v", err)
	}

	reply := readTunPacket(t, peer, 3*time.Second)
	if len(reply) != 20+8+len(payload) {
		t.Fatalf("reply is %d bytes, want %d: %x", len(reply), 20+8+len(payload), reply)
	}
	if reply[0]>>4 != 4 || reply[9] != icmpProtocol {
		t.Fatalf("reply is not an IPv4 ICMP packet: %x", reply)
	}
	if !net.IP(reply[12:16]).Equal(vip) || !net.IP(reply[16:20]).Equal(deviceAddr) {
		t.Fatalf("reply addresses = %v -> %v, want %v -> %v",
			net.IP(reply[12:16]), net.IP(reply[16:20]), vip, deviceAddr)
	}
	if reply[20] != 0 { // echo reply
		t.Fatalf("ICMP type = %d, want 0 (echo reply)", reply[20])
	}
	if got := binary.BigEndian.Uint16(reply[24:26]); got != id {
		t.Fatalf("ICMP id = %#x, want %#x", got, id)
	}
	if got := binary.BigEndian.Uint16(reply[26:28]); got != seq {
		t.Fatalf("ICMP sequence = %d, want %d", got, seq)
	}
	if !bytes.Equal(reply[28:], payload) {
		t.Fatalf("ICMP payload = %q, want %q", reply[28:], payload)
	}
	if got := internetChecksum(reply[20:]); got != 0 {
		t.Fatalf("ICMP checksum does not verify (sum %#x)", got)
	}
	if got := internetChecksum(reply[:20]); got != 0 {
		t.Fatalf("IPv4 header checksum does not verify (sum %#x)", got)
	}
}

// TestTunDeviceCarriesUDPFlowThroughTheTunnelDialer proves a datagram sent by
// the device reaches the same tunnel dialer the proxy shape uses — with the
// resolved application and domain — and that the answer returns to the
// descriptor.
func TestTunDeviceCarriesUDPFlowThroughTheTunnelDialer(t *testing.T) {
	vip := net.IPv4(10, 20, 205, 16)
	deviceAddr := net.IPv4(10, 20, 205, 17)
	target := net.IPv4(203, 0, 113, 9)
	peer, fd := testTunPair(t)
	dialer := &mockDialer{calls: make(chan dialCall, 1)}
	res := &mockResolver{result: &resolver.Resolution{IP: target.String(), AppID: "dns-app", Domain: "dns.example"}}
	newTestTunDevice(t, fd, vip, res, dialer)

	payload := []byte("dns query")
	if _, err := peer.Write(udpDatagram(deviceAddr, target, 40000, 53, payload)); err != nil {
		t.Fatalf("write UDP datagram: %v", err)
	}

	select {
	case call := <-dialer.calls:
		if call.ip != target.String() || call.port != 53 || call.appID != "dns-app" || call.domain != "dns.example" {
			t.Fatalf("dial call = %+v, want %s:53 app dns-app (dns.example)", call, target)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the UDP flow never reached the tunnel dialer")
	}

	reply := readTunPacket(t, peer, 3*time.Second)
	if reply[9] != udpProtocol || !net.IP(reply[12:16]).Equal(target) || !net.IP(reply[16:20]).Equal(deviceAddr) {
		t.Fatalf("UDP reply = %v -> %v proto %d", net.IP(reply[12:16]), net.IP(reply[16:20]), reply[9])
	}
	if sport, dport := binary.BigEndian.Uint16(reply[20:22]), binary.BigEndian.Uint16(reply[22:24]); sport != 53 || dport != 40000 {
		t.Fatalf("UDP reply ports = %d -> %d, want 53 -> 40000", sport, dport)
	}
	if !bytes.Equal(reply[28:], payload) {
		t.Fatalf("UDP reply payload = %q, want %q", reply[28:], payload)
	}
}

// TestTunDeviceCarriesTCPFlowThroughTheTunnelDialer drives a real handshake and
// a data exchange across the descriptor: the stack terminates the device's TCP
// connection, the tunnel dialer provides the upstream, and the echo comes back
// as TCP segments.
func TestTunDeviceCarriesTCPFlowThroughTheTunnelDialer(t *testing.T) {
	vip := net.IPv4(10, 20, 205, 16)
	deviceAddr := net.IPv4(10, 20, 205, 17)
	target := net.IPv4(198, 51, 100, 7)
	peer, fd := testTunPair(t)
	dialer := &mockDialer{calls: make(chan dialCall, 1)}
	res := &mockResolver{result: &resolver.Resolution{IP: target.String(), AppID: "web-app"}}
	device := newTestTunDevice(t, fd, vip, res, dialer)

	const clientPort = 50000
	const serverPort = 443
	const clientISN = 1000

	if _, err := peer.Write(tcpSegment(deviceAddr, target, clientPort, serverPort, clientISN, 0, tcpSyn, nil)); err != nil {
		t.Fatalf("write SYN: %v", err)
	}
	synAck := readTCPSegment(t, peer, tcpSyn|tcpAck, 3*time.Second)
	ihl := int(synAck[0]&0x0f) * 4
	if !net.IP(synAck[12:16]).Equal(target) || !net.IP(synAck[16:20]).Equal(deviceAddr) {
		t.Fatalf("SYN-ACK addresses = %v -> %v", net.IP(synAck[12:16]), net.IP(synAck[16:20]))
	}
	if ack := binary.BigEndian.Uint32(synAck[ihl+8 : ihl+12]); ack != clientISN+1 {
		t.Fatalf("SYN-ACK ack = %d, want %d", ack, clientISN+1)
	}
	serverISN := binary.BigEndian.Uint32(synAck[ihl+4 : ihl+8])

	// Complete the handshake: the forwarder only opens the tunnel flow once
	// the device-side connection is established.
	if _, err := peer.Write(tcpSegment(deviceAddr, target, clientPort, serverPort, clientISN+1, serverISN+1, tcpAck, nil)); err != nil {
		t.Fatalf("write ACK: %v", err)
	}

	select {
	case call := <-dialer.calls:
		if call.ip != target.String() || call.port != serverPort || call.appID != "web-app" {
			t.Fatalf("dial call = %+v, want %s:443 app web-app", call, target)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the TCP flow never reached the tunnel dialer")
	}

	// A payload sent by the device must come back as the mock's echo.
	echo := []byte("hello tun")
	if _, err := peer.Write(tcpSegment(deviceAddr, target, clientPort, serverPort, clientISN+1, serverISN+1, tcpAck|tcpPsh, echo)); err != nil {
		t.Fatalf("write data: %v", err)
	}

	for {
		segment := readTCPSegment(t, peer, tcpAck, 3*time.Second)
		if payload := tcpPayload(segment); len(payload) != 0 {
			if !bytes.Equal(payload, echo) {
				t.Fatalf("echoed payload = %q, want %q", payload, echo)
			}
			break
		}
	}

	// The attachment's own count is the only account of the data plane a
	// platform with no log channel has, so a carried flow must show up in it.
	stats := device.Stats()
	if stats.PacketsIn == 0 || stats.PacketsOut == 0 || stats.TCPFlows != 1 {
		t.Fatalf("tun stats after one carried flow = %+v, want packets both ways and one TCP flow", stats)
	}
	if stats.RefusedFlows != 0 || stats.FailedFlows != 0 {
		t.Fatalf("tun stats after one carried flow = %+v, want no refusal and no failure", stats)
	}
}

// TestTunDeviceCountsARefusedFlow proves the attachment records a flow it
// refused, and that the refusal never reaches the dialer. That count is what a
// device log cannot supply on OHOS: a resolver refusing every flow (an
// unauthorized destination) used to look exactly like a device that never sent
// a packet, because the refusal was one Debug line and the default level is
// Info.
func TestTunDeviceCountsARefusedFlow(t *testing.T) {
	vip := net.IPv4(10, 20, 205, 16)
	deviceAddr := net.IPv4(10, 20, 205, 17)
	target := net.IPv4(198, 51, 100, 7)
	peer, fd := testTunPair(t)
	dialer := &mockDialer{calls: make(chan dialCall, 1)}
	device := newTestTunDevice(t, fd, vip, &mockResolver{failAll: true}, dialer)

	const clientPort = 50000
	const serverPort = 443
	const clientISN = 1000
	if _, err := peer.Write(tcpSegment(deviceAddr, target, clientPort, serverPort, clientISN, 0, tcpSyn, nil)); err != nil {
		t.Fatalf("write SYN: %v", err)
	}

	// The forwarder only runs the relay once the device-side connection is
	// established, so the handshake has to complete before the refusal can be
	// observed at all.
	synAck := readTCPSegment(t, peer, tcpSyn|tcpAck, 3*time.Second)
	ihl := int(synAck[0]&0x0f) * 4
	serverISN := binary.BigEndian.Uint32(synAck[ihl+4 : ihl+8])
	if _, err := peer.Write(tcpSegment(deviceAddr, target, clientPort, serverPort, clientISN+1, serverISN+1, tcpAck, nil)); err != nil {
		t.Fatalf("write ACK: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		stats := device.Stats()
		if stats.RefusedFlows == 1 {
			if stats.TCPFlows != 1 {
				t.Fatalf("tun stats = %+v, want exactly one terminated TCP flow", stats)
			}
			if stats.FailedFlows != 0 {
				t.Fatalf("tun stats = %+v, want no dial failure", stats)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("tun stats = %+v, want the refused flow counted", stats)
		}
		time.Sleep(10 * time.Millisecond)
	}

	select {
	case call := <-dialer.calls:
		t.Fatalf("a refused flow reached the dialer: %+v", call)
	case <-time.After(100 * time.Millisecond):
	}
}

// TestTunDeviceNeverClosesThePlatformDescriptorAndCanBeReattached proves the
// teardown contract: Close stops the inbound but leaves the descriptor the
// caller owns open, and the same descriptor can be attached again.
func TestTunDeviceNeverClosesThePlatformDescriptorAndCanBeReattached(t *testing.T) {
	vip := net.IPv4(10, 20, 205, 16)
	deviceAddr := net.IPv4(10, 20, 205, 17)
	peer, fd := testTunPair(t)

	first, err := NewTunDevice(fd, vip, &mockResolver{}, &mockDialer{}, testLogger())
	if err != nil {
		t.Fatalf("first attach: %v", err)
	}
	if _, err := peer.Write(icmpEchoRequest(deviceAddr, vip, 1, 1, nil)); err != nil {
		t.Fatalf("write echo request: %v", err)
	}
	if reply := readTunPacket(t, peer, 3*time.Second); reply[20] != 0 {
		t.Fatalf("first attachment did not answer the echo: %x", reply)
	}
	first.Close()
	first.Close() // idempotent

	// The platform's descriptor is still open: a stat on it must not say EBADF.
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		t.Fatalf("the platform descriptor was closed by the inbound: %v", err)
	}
	drainPeer(peer)

	second, err := NewTunDevice(fd, vip, &mockResolver{}, &mockDialer{}, testLogger())
	if err != nil {
		t.Fatalf("re-attach: %v", err)
	}
	defer second.Close()
	if _, err := peer.Write(icmpEchoRequest(deviceAddr, vip, 2, 2, nil)); err != nil {
		t.Fatalf("write echo request after re-attach: %v", err)
	}
	if reply := readTunPacket(t, peer, 3*time.Second); reply[20] != 0 {
		t.Fatalf("the replacement attachment did not answer the echo: %x", reply)
	}
	syscall.Close(fd)
}
