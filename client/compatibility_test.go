package client

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"geektrust/internal/config"
)

type compatibilityStore string

func (s compatibilityStore) Load(context.Context) ([]byte, error) { return []byte(s), nil }
func (s compatibilityStore) Save(context.Context, []byte) error   { return nil }

type compatibilityTransport struct{}

func (compatibilityTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	body := `{"code":0,"data":{}}`
	switch r.URL.Path {
	case "/passport/v1/user/onlineInfo":
		body = `{"code":0,"data":{"isOnline":true}}`
	case "/controller/v1/user/clientResource":
	default:
		return nil, errors.New("unexpected controller request")
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
}

func TestShanghaiTechOptionsPreserveLegacyConfig(t *testing.T) {
	template := &tls.Config{}
	options := Options{
		ControllerURL: config.DefaultBaseURL,
		DeviceID:      "0123456789ABCDEF0123456789ABCDEF",
		Gateways:      []string{"override:441"}, DNS: []string{"10.0.0.53"},
		GatewayTLSConfig: template, Transport: compatibilityTransport{},
		SessionStore:  compatibilityStore(`{"sid":"synthetic-session","device_id":"0123456789ABCDEF0123456789ABCDEF","client_type":"browser","cookies":[{"name":"sid","value":"synthetic-session"}]}`),
		Authenticator: AuthenticatorFunc(func(context.Context, *http.Client) (string, error) { return "", errors.New("unexpected full login") }),
	}
	c, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	options.Gateways[0] = "mutated"
	info, err := c.Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Gateways) != 1 || info.Gateways[0] != "override:441" || len(info.DNS) != 1 || info.DNS[0] != "10.0.0.53" {
		t.Fatal("configured routing overrides lost")
	}
	target, err := c.resolver.Resolve(context.Background(), "192.0.2.1", 443)
	if err != nil || target.AppID != config.DefaultAppID {
		t.Fatal("legacy application fallback lost")
	}
	if c.provider.ActiveSDPC().LoginDomain != config.DefaultLoginDomain {
		t.Fatal("legacy CAS domain lost")
	}
	if c.manager.GatewayTLSConfig.ServerName != "vpn.shanghaitech.edu.cn" || template.ServerName != "" {
		t.Fatal("gateway certificate identity missing or caller TLS config mutated")
	}
}

func TestAuthenticationUsesCallerDeadline(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	want, _ := parent.Deadline()
	called := false
	c, err := New(Options{ControllerURL: config.DefaultBaseURL, DeviceID: "0123456789ABCDEF0123456789ABCDEF", Authenticator: AuthenticatorFunc(func(ctx context.Context, _ *http.Client) (string, error) {
		called = true
		got, ok := ctx.Deadline()
		if !ok || !got.Equal(want) {
			t.Errorf("authentication deadline shortened: %v", got)
		}
		return "", errors.New("synthetic stop before network login")
	})})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Connect(parent); err == nil || !called {
		t.Fatal("authentication fixture not exercised")
	}
}
