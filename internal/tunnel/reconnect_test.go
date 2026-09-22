package tunnel

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nanakusa-electronics/geektrust/internal/session"
)

type managerTestProvider struct{}

func (managerTestProvider) Credential(ctx context.Context) (*session.Credential, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &session.Credential{SID: "test-session", Gateways: []string{"gateway.example:441"}}, nil
}
func (managerTestProvider) InvalidateIfCurrent(*session.Credential) bool { return false }

func TestManagerCloseCancelsConnect(t *testing.T) {
	m := NewManager(managerTestProvider{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.MaxAttempts = 1
	started := make(chan struct{})
	var once sync.Once
	m.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		once.Do(func() { close(started) })
		<-ctx.Done()
		return nil, ctx.Err()
	}
	result := make(chan error, 1)
	go func() { _, err := m.Tunnel(context.Background()); result <- err }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("connect did not start")
	}
	m.Close()
	m.Close()
	select {
	case err := <-result:
		if !errors.Is(err, ErrTunnelDead) {
			t.Fatalf("close result: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("close did not cancel connect")
	}
	if _, err := m.Tunnel(context.Background()); !errors.Is(err, ErrTunnelDead) {
		t.Fatal("closed manager reconnected")
	}
}
