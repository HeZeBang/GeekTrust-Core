package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"geektrust/internal/sdpc"
	"geektrust/internal/session"
)

// defaultGatewayPort is the aTrust gateway access port used when a gateway
// address carries no port (docs/TECHNICAL.md §5.1).
const defaultGatewayPort = "441"

// sessionPayload is docs/ABI.md's session_json. Unknown fields are ignored on
// purpose: the app may extend the payload, and the data plane must not care.
type sessionPayload struct {
	SID          string   `json:"sid"`
	DeviceID     string   `json:"device_id"`
	Username     string   `json:"username"`
	BaseURL      string   `json:"base_url"`
	Gateways     []string `json:"gateways"`
	DNS          []string `json:"dns"`
	ConnectionID string   `json:"connection_id"`
}

// parseSession turns the two JSON payloads into the credential the data plane
// consumes. It is a translation, not a login: authentication, session
// persistence and refresh all belong to the app.
//
// controllerHost is base_url's hostname, which is what "{{sdpcHost}}" in the
// policy's gateway lines expands to.
func parseSession(sessionJSON, policyJSON string) (*session.Credential, sessionPayload, error) {
	var payload sessionPayload
	if err := json.Unmarshal([]byte(sessionJSON), &payload); err != nil {
		return nil, payload, fmt.Errorf("session_json: %w", err)
	}
	if payload.SID == "" {
		return nil, payload, errors.New("session_json: sid is required")
	}
	if payload.DeviceID == "" {
		return nil, payload, errors.New("session_json: device_id is required")
	}

	controllerHost := ""
	if payload.BaseURL != "" {
		u, err := url.Parse(payload.BaseURL)
		if err != nil {
			return nil, payload, fmt.Errorf("session_json: base_url %q: %w", payload.BaseURL, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return nil, payload, fmt.Errorf("session_json: base_url %q must be an http(s) URL", payload.BaseURL)
		}
		if u.Hostname() == "" {
			return nil, payload, fmt.Errorf("session_json: base_url %q has no host", payload.BaseURL)
		}
		controllerHost = u.Hostname()
	}

	// The policy is parsed in exactly one place: the same function the control
	// plane would have used, so route matching cannot drift between the two.
	policy, err := sdpc.ParseResource([]byte(policyJSON), controllerHost)
	if err != nil {
		return nil, payload, fmt.Errorf("policy_json: %w", err)
	}

	// The session's list is what the app configured; the policy's lines are
	// the fallback. GatewayOverride then makes the tunnel prefer the policy's
	// per-app node group while staying inside what the session allows.
	sessionGateways, err := normalizeGateways(payload.Gateways)
	if err != nil {
		return nil, payload, fmt.Errorf("session_json: %w", err)
	}
	gateways := sessionGateways
	if len(gateways) == 0 {
		gateways = normalizeGatewayList(policy.Gateways)
	}
	if len(gateways) == 0 {
		return nil, payload, errors.New("no gateway addresses: policy_json supplied none and session_json.gateways is empty")
	}

	dnsList, err := normalizeDNS(payload.DNS)
	if err != nil {
		return nil, payload, fmt.Errorf("session_json: %w", err)
	}
	if len(dnsList) == 0 {
		// The controller's servers are the fallback, as docs/ABI.md says.
		// sdpc already accepted only real addresses from the policy.
		dnsList, _ = normalizeDNS(policy.DNS)
	}

	cred := &session.Credential{
		// No AppID: this repository has no legacy default, so unmatched
		// destinations are only authorized by the policy's catch-all apps.
		LegacyRouting:   isShanghaiTech(controllerHost),
		GatewayOverride: len(sessionGateways) > 0,
		SID:             payload.SID,
		DeviceID:        payload.DeviceID,
		Username:        payload.Username,
		ConnectionID:    payload.ConnectionID,
		Gateways:        gateways,
		DNS:             dnsList,
		Policy:          policy,
	}
	return cred, payload, nil
}

// controllerServerName is the name gateway certificates are verified against.
// The gateways are usually IP-addressed, so the identity to check is the
// controller the session came from; an IP or absent controller host leaves it
// empty and every line verifies against its own address.
func controllerServerName(baseURL string) string {
	if baseURL == "" {
		return ""
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	if host == "" || net.ParseIP(host) != nil {
		return ""
	}
	return host
}

// isShanghaiTech limits the legacy flattened-gateway fallback to the
// controller it exists for, exactly as the control plane did before the split.
func isShanghaiTech(controllerHost string) bool {
	return strings.EqualFold(controllerHost, "vpn.shanghaitech.edu.cn")
}

// normalizeGateways validates and canonicalizes session_json's gateway list:
// every entry is host:port with a default port, as the IP-addressed policy
// lines already are.
func normalizeGateways(list []string) ([]string, error) {
	out := make([]string, 0, len(list))
	for _, entry := range list {
		addr, err := normalizeGateway(entry)
		if err != nil {
			return nil, fmt.Errorf("gateway %q: %w", entry, err)
		}
		if addr == "" {
			continue
		}
		out = append(out, addr)
	}
	return dedupe(out), nil
}

// normalizeGatewayList canonicalizes addresses that sdpc already validated.
func normalizeGatewayList(list []string) []string {
	out := make([]string, 0, len(list))
	for _, entry := range list {
		if addr, err := normalizeGateway(entry); err == nil && addr != "" {
			out = append(out, addr)
		}
	}
	return dedupe(out)
}

func normalizeGateway(entry string) (string, error) {
	addr := strings.TrimSpace(entry)
	if addr == "" {
		return "", nil
	}
	if !strings.Contains(addr, ":") {
		return net.JoinHostPort(addr, defaultGatewayPort), nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	if host == "" {
		return "", errors.New("missing host")
	}
	if port == "" {
		port = defaultGatewayPort
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("invalid port %q", port)
	}
	return net.JoinHostPort(host, port), nil
}

// normalizeDNS validates the session's resolver addresses; a non-address here
// would only surface later as a confusing lookup failure.
func normalizeDNS(list []string) ([]string, error) {
	out := make([]string, 0, len(list))
	for _, entry := range list {
		server := strings.TrimSpace(entry)
		if server == "" {
			continue
		}
		ip := net.ParseIP(server)
		if ip == nil {
			return nil, fmt.Errorf("dns entry %q is not an IP address", entry)
		}
		out = append(out, ip.String())
	}
	return dedupe(out), nil
}

func dedupe(list []string) []string {
	seen := make(map[string]bool, len(list))
	out := make([]string, 0, len(list))
	for _, entry := range list {
		if seen[entry] {
			continue
		}
		seen[entry] = true
		out = append(out, entry)
	}
	return out
}
