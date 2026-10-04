package core

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"testing"

	"geektrust/internal/session"
)

// quietLogs silences the library logger for the duration of a test: the tests
// deliberately point the engine at a dead gateway, and its retry diagnostics
// are not what is under test.
func quietLogs(t *testing.T) {
	t.Helper()
	previous := logger
	logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Cleanup(func() { logger = previous })
}

// samplePolicy is a clientResource `data` object with the shape the controller
// returns: one catch-all app, one node group whose second line needs the
// controller host, and one pushed DNS server.
const samplePolicy = `{
  "appList": {"data": {
    "appInfo": [{"apps": [{
      "id": "app-all", "name": "外网资源",
      "addressList": [{"protocol": "tcp", "port": "1-65535", "host": "0.0.0.0/0"}]
    }]}],
    "config": {"nodeGroupConf": {
      "majorNodeGroup": {"id": "grp"},
      "nodeGroupList": [{"id": "grp", "addressInfo": [
        {"address": "127.0.0.1:1"},
        {"address": "{{sdpcHost}}:441"}
      ]}]
    }}
  }},
  "sdpPolicy": {"data": {"clientOption": {"dnsOption": {"firstDNS": "10.15.44.11"}}}}
}`

const sampleSession = `{
  "sid": "sid-1",
  "device_id": "E8483C84D8C0BFA3450C98945BD8E7FF",
  "username": "2023533189",
  "base_url": "https://vpn.example.edu",
  "gateways": ["119.78.254.241:441"],
  "dns": ["10.15.44.11"],
  "connection_id": "abc-1"
}`

func TestParseSessionFromPayload(t *testing.T) {
	cred, payload, err := parseSession(sampleSession, samplePolicy)
	if err != nil {
		t.Fatalf("parseSession: %v", err)
	}
	if payload.Username != "2023533189" {
		t.Fatalf("payload username = %q", payload.Username)
	}
	if cred.SID != "sid-1" || cred.DeviceID != "E8483C84D8C0BFA3450C98945BD8E7FF" {
		t.Fatalf("credentials = %+v", cred)
	}
	if cred.Username != "2023533189" || cred.ConnectionID != "abc-1" {
		t.Fatalf("credentials = %+v", cred)
	}
	// The session's list wins over the policy's lines, and GatewayOverride
	// keeps the tunnel inside it while still honouring per-app node groups.
	if len(cred.Gateways) != 1 || cred.Gateways[0] != "119.78.254.241:441" {
		t.Fatalf("gateways = %v", cred.Gateways)
	}
	if !cred.GatewayOverride {
		t.Fatal("GatewayOverride must be set when session_json supplies gateways")
	}
	if cred.LegacyRouting {
		t.Fatal("LegacyRouting is for the ShanghaiTech controller only")
	}
	if len(cred.DNS) != 1 || cred.DNS[0] != "10.15.44.11" {
		t.Fatalf("dns = %v", cred.DNS)
	}
	if cred.Policy == nil || len(cred.Policy.IPRules) == 0 {
		t.Fatalf("policy = %+v", cred.Policy)
	}
}

func TestParseSessionFallsBackToPolicy(t *testing.T) {
	payload := `{"sid": "s", "device_id": "D", "base_url": "https://vpn.shanghaitech.edu.cn/"}`
	cred, _, err := parseSession(payload, samplePolicy)
	if err != nil {
		t.Fatalf("parseSession: %v", err)
	}
	// No session gateways: the policy's lines are used, with {{sdpcHost}}
	// expanded from base_url, and the controller's DNS server is the fallback.
	want := []string{"127.0.0.1:1", "vpn.shanghaitech.edu.cn:441"}
	if strings.Join(cred.Gateways, ",") != strings.Join(want, ",") {
		t.Fatalf("gateways = %v, want %v", cred.Gateways, want)
	}
	if cred.GatewayOverride {
		t.Fatal("GatewayOverride must be clear when session_json supplies no gateways")
	}
	if !cred.LegacyRouting {
		t.Fatal("the ShanghaiTech controller keeps the flattened-gateway fallback")
	}
	if len(cred.DNS) != 1 || cred.DNS[0] != "10.15.44.11" {
		t.Fatalf("dns = %v", cred.DNS)
	}
}

func TestParseSessionRejects(t *testing.T) {
	cases := []struct {
		name    string
		session string
		policy  string
		want    string
	}{
		{"bad session json", `{`, "{}", "session_json"},
		{"missing sid", `{"device_id": "D"}`, "{}", "sid is required"},
		{"missing device id", `{"sid": "s"}`, "{}", "device_id is required"},
		{"bad base url", `{"sid": "s", "device_id": "D", "base_url": "vpn.example.edu"}`, "{}", "http(s)"},
		{"bad policy json", `{"sid": "s", "device_id": "D"}`, `{`, "policy_json"},
		{"no gateways", `{"sid": "s", "device_id": "D"}`, "{}", "no gateway addresses"},
		{"bad gateway", `{"sid": "s", "device_id": "D", "gateways": ["1.2.3.4:0"]}`, "{}", "invalid port"},
		{"bad dns", `{"sid": "s", "device_id": "D", "gateways": ["1.2.3.4:441"], "dns": ["resolver"]}`, "{}", "not an IP address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := parseSession(tc.session, tc.policy)
			if err == nil {
				t.Fatal("want an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestStatusBeforeInit(t *testing.T) {
	engine := New()
	out, err := engine.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	var snapshot struct {
		Alive        bool     `json:"alive"`
		ABI          int      `json:"abi"`
		DeviceID     string   `json:"device_id"`
		Gateways     []string `json:"gateways"`
		DialAttempts uint64   `json:"dial_attempts"`
	}
	if err := json.Unmarshal(out, &snapshot); err != nil {
		t.Fatalf("status is not JSON (%s): %v", out, err)
	}
	if snapshot.Alive {
		t.Fatal("alive must be false before init")
	}
	if snapshot.ABI != ABI {
		t.Fatalf("abi = %d, want %d", snapshot.ABI, ABI)
	}
	if snapshot.Gateways == nil {
		t.Fatalf("gateways must be a list, got %s", out)
	}
	if snapshot.DeviceID != "" || snapshot.DialAttempts != 0 {
		t.Fatalf("status = %s", out)
	}
}

func TestCloseIsSafeBeforeInitAndRepeated(t *testing.T) {
	engine := New()
	engine.Close()
	engine.Close()
	if _, err := engine.Status(); err != nil {
		t.Fatalf("Status after close: %v", err)
	}
	if _, err := engine.Dial(context.Background(), "10.0.0.1", 443, "app", ""); err == nil {
		t.Fatal("Dial must fail while no session is installed")
	}
}

func TestStartProxiesNeedsSession(t *testing.T) {
	engine := New()
	if err := engine.StartProxies("127.0.0.1:0", ""); err != ErrNotInitialized {
		t.Fatalf("StartProxies before init = %v, want ErrNotInitialized", err)
	}
	engine.Close()
}

func TestAttachTunFDSaysItIsNotImplemented(t *testing.T) {
	engine := New()
	err := engine.AttachTunFD(-1)
	if err == nil {
		t.Fatal("the tun-fd inbound is not implemented; it must not report success")
	}
	if !strings.Contains(err.Error(), "not implemented") {
		t.Fatalf("error = %q, want it to say the inbound is not implemented", err)
	}
}

func TestInitInstallsSessionAndFailedInitKeepsIt(t *testing.T) {
	quietLogs(t)
	engine := New()
	defer engine.Close()
	if err := engine.Init(sampleSession, samplePolicy); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := engine.Init(`{"sid": "s", "device_id": "D"}`, `{}`); err == nil {
		t.Fatal("a payload with no gateway must fail")
	}
	out, err := engine.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	// A failed init must leave the working session alone: the app retries with
	// payloads it just fetched, and the tunnel it already has keeps running.
	var snapshot struct {
		DeviceID string   `json:"device_id"`
		Username string   `json:"username"`
		Gateways []string `json:"gateways"`
	}
	if err := json.Unmarshal(out, &snapshot); err != nil {
		t.Fatalf("status is not JSON (%s): %v", out, err)
	}
	if snapshot.DeviceID != "E8483C84D8C0BFA3450C98945BD8E7FF" || snapshot.Username != "2023533189" {
		t.Fatalf("status = %s", out)
	}
	if strings.Join(snapshot.Gateways, ",") != "119.78.254.241:441" {
		t.Fatalf("status = %s", out)
	}
}

func TestInitReplacesSessionOnTheSameController(t *testing.T) {
	quietLogs(t)
	engine := New()
	defer engine.Close()
	if err := engine.Init(sampleSession, samplePolicy); err != nil {
		t.Fatalf("Init: %v", err)
	}
	first := engine.stack

	updated := strings.Replace(sampleSession, "sid-1", "sid-2", 1)
	if err := engine.Init(updated, samplePolicy); err != nil {
		t.Fatalf("re-Init: %v", err)
	}
	if engine.stack != first {
		t.Fatal("the same controller must keep its stack; only the session changes")
	}

	moved := strings.Replace(sampleSession, "vpn.example.edu", "vpn.other.edu", 1)
	if err := engine.Init(moved, samplePolicy); err != nil {
		t.Fatalf("re-Init on another controller: %v", err)
	}
	if engine.stack == first {
		t.Fatal("another controller must get a stack built for its certificates")
	}
}

func TestProxiesServeAndCloseReleasesTheirs(t *testing.T) {
	quietLogs(t)
	engine := New()
	if err := engine.Init(sampleSession, samplePolicy); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer engine.Close()

	addr := freeAddr(t)
	if err := engine.StartProxies(addr, ""); err != nil {
		t.Fatalf("StartProxies: %v", err)
	}
	if err := engine.StartProxies(addr, ""); err != nil {
		t.Fatalf("repeated StartProxies with the same pair must be a no-op: %v", err)
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial the SOCKS5 listener: %v", err)
	}
	defer conn.Close()
	// RFC 1928 greeting: version 5, one method, no authentication.
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read greeting reply: %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("greeting reply = %v, want [5 0]", reply)
	}

	engine.Close()
	engine.Close() // double close is a no-op
	if _, err := net.Dial("tcp", addr); err == nil {
		t.Fatal("close must release the proxy ports")
	}
}

func TestProviderInvalidateOnlyDropsTheCurrentSession(t *testing.T) {
	p := &provider{}
	if _, err := p.Credential(context.Background()); err != ErrNoSession {
		t.Fatalf("Credential with no session = %v", err)
	}
	current := &session.Credential{SID: "a"}
	other := &session.Credential{SID: "b"}
	p.set(current)
	if p.InvalidateIfCurrent(other) {
		t.Fatal("a stale rejection must not drop a newer session")
	}
	if !p.InvalidateIfCurrent(current) {
		t.Fatal("the current session must be dropped")
	}
	if p.InvalidateIfCurrent(current) {
		t.Fatal("dropping twice must report nothing to do")
	}
	cred, err := p.Credential(context.Background())
	if err == nil || cred != nil {
		t.Fatalf("Credential after invalidation = %v, %v", cred, err)
	}
	if p.current() != current {
		t.Fatal("the rejected session stays readable for status")
	}
	p.set(other)
	if !p.live() {
		t.Fatal("a new session must make the provider live again")
	}
}

func TestProvenanceCarriesTheMarker(t *testing.T) {
	if !strings.HasPrefix(Provenance(), markerPrefix) {
		t.Fatalf("provenance %q must start with %q", Provenance(), markerPrefix)
	}
	parts := strings.Split(strings.TrimPrefix(Provenance(), markerPrefix), ":")
	if len(parts) != 3 {
		t.Fatalf("provenance %q must be <abi>:<version>:<digest>", Provenance())
	}
	if parts[0] != strconv.Itoa(ABI) {
		t.Fatalf("provenance abi %q must match ABI %d", parts[0], ABI)
	}
}

// freeAddr picks an ephemeral loopback port. The listener is closed before the
// address is returned, which is enough for a test that binds it immediately.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}
