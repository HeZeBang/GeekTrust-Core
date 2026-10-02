package resolver

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDNSInvalidNameDoesNotCoolUncontactedServer(t *testing.T) {
	f := newDNSFixture(t)
	p := testDNSPool()
	servers := []string{"10.0.0.53"}
	if _, err := p.lookup(context.Background(), "bad name.", "test", servers, f.dial); err == nil {
		t.Fatal("invalid name resolved")
	}
	if f.udpCalls.Load() != 0 || f.tcpCalls.Load() != 0 {
		t.Fatal("invalid name used DNS transport")
	}
	ip, err := p.lookup(context.Background(), "valid.example.", "test", servers, f.dial)
	if err != nil || ip.String() != "10.20.30.40" {
		t.Fatalf("valid query after invalid name: %v %v", ip, err)
	}
	if f.udpCalls.Load() != 1 || f.tcpCalls.Load() != 0 {
		t.Fatal("invalid name changed transport health")
	}
}

func TestDNSLocalResultDoesNotCoolUncontactedServer(t *testing.T) {
	f := newDNSFixture(t)
	p := testDNSPool()
	servers := []string{"10.0.0.53"}
	_, err := p.lookup(context.Background(), "localhost", "test", servers, f.dial)
	if f.udpCalls.Load() != 0 || f.tcpCalls.Load() != 0 {
		t.Skip("localhost uses transport on this host")
	}
	if err != nil && !errors.Is(err, errNoIPv4Answer) {
		t.Fatal(err)
	}
	ip, err := p.lookup(context.Background(), "valid.example.", "test", servers, f.dial)
	if err != nil || ip.String() != "10.20.30.40" {
		t.Fatalf("valid query after local result: %v %v", ip, err)
	}
}

func TestDNSLocalResultReleasesExpiredRecoveryProbe(t *testing.T) {
	f := newDNSFixture(t)
	p := testDNSPool()
	servers := []string{"10.0.0.53"}
	p.candidates("test", servers)
	p.mu.Lock()
	h := p.servers[servers[0]]
	h.udpHealthy = false
	h.udpRetryAt = time.Now().Add(-time.Second)
	h.serverRetryAt = time.Now().Add(-time.Second)
	p.mu.Unlock()
	_, _ = p.lookup(context.Background(), "bad name.", "test", servers, f.dial)
	p.mu.Lock()
	held := h.udpProbe || h.serverProbe
	failures := h.udpFailures + h.serverFailures
	p.mu.Unlock()
	if held || failures != 0 {
		t.Fatal("local rejection held a recovery probe or added a failure")
	}
	if _, err := p.lookup(context.Background(), "valid.example.", "test", servers, f.dial); err != nil {
		t.Fatal(err)
	}
	if f.udpCalls.Load() != 1 {
		t.Fatal("recovery probe did not retry UDP")
	}
}
