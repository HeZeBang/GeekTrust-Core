package sdpc

import (
	"encoding/json"
	"testing"
)

func TestTransportPolicyAndDomainOnlyResource(t *testing.T) {
	var wire clientResource
	if err := json.Unmarshal([]byte(`{"appList":{"data":{"appInfo":[{"apps":[{"id":"app","nodeGroupId":"private","enableTCPPrefL3":true,"addressList":[{"host":"inside.example","port":"443","protocol":"tcp"}]}]}]}}}`), &wire); err != nil {
		t.Fatal(err)
	}
	r := (&Client{}).parseResource(&wire)
	if !r.AppTCPPreferL3["app"] || r.AppNodeGroups["app"] != "private" {
		t.Fatal("application transport policy lost")
	}
	rule, ok := r.MatchDomain("inside.example", 443)
	if !ok || rule.IP != "" || rule.AppID != "app" {
		t.Fatal("domain-only resource lost")
	}
	if len(r.GatewaysForApp("app")) != 0 {
		t.Fatal("missing group must not use other gateways")
	}
}

func TestGatewayAddressFamilies(t *testing.T) {
	for input, want := range map[string]string{
		"gateway.example":   "gateway.example:441",
		"192.0.2.1":         "192.0.2.1:441",
		"2001:db8::1":       "[2001:db8::1]:441",
		"[2001:db8::1]":     "[2001:db8::1]:441",
		"[2001:db8::1]:443": "[2001:db8::1]:443",
	} {
		if got, ok := gatewayAddress(input); !ok || got != want {
			t.Errorf("%s: %s, %t", input, got, ok)
		}
	}
	for _, input := range []string{"gateway:0", "gateway:65536", "gateway:bad", "https://gateway/"} {
		if _, ok := gatewayAddress(input); ok {
			t.Errorf("accepted %s", input)
		}
	}
}

func TestInvalidPortsNeverWidenPolicy(t *testing.T) {
	for _, value := range []string{"junk", "-1", "65536", "100-10", "1-junk"} {
		r := parsePortRange(value)
		for _, port := range []int{0, 1, 53, 443, 65535} {
			if r.Contains(port) {
				t.Errorf("invalid %q authorized %d", value, port)
			}
		}
	}
}
