package core

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"geektrust/internal/session"
)

// ErrNoSession means the data plane has no session to connect with: either the
// app has not called geektrust_init yet, or the controller rejected the session
// it handed over and the library dropped it.
var ErrNoSession = errors.New("no live session: authenticate in the app and call geektrust_init again")

// provider is the session.CredentialProvider the tunnel, the resolver and l3
// consume. The app owns the session — this provider only holds what it was
// handed and forwards what the data plane needs, so no part of this repository
// re-authenticates or refreshes anything.
type provider struct {
	mu    sync.Mutex
	cred  *session.Credential
	stale bool
}

// Credential returns the installed session, or ErrNoSession when there is none
// left to use.
func (p *provider) Credential(ctx context.Context) (*session.Credential, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cred == nil {
		return nil, ErrNoSession
	}
	if p.stale {
		return nil, fmt.Errorf("%w: the controller rejected it", ErrNoSession)
	}
	return p.cred, nil
}

// InvalidateIfCurrent drops the session only when expected is still the one in
// use: the tunnel calls it after every line rejected the session, and a
// concurrent geektrust_init may already have replaced it with a working one.
// The credential itself is kept for diagnostics — it is only marked unusable.
func (p *provider) InvalidateIfCurrent(expected *session.Credential) bool {
	if expected == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cred != expected || p.stale {
		return false
	}
	p.stale = true
	return true
}

// set installs the session geektrust_init just handed over.
func (p *provider) set(cred *session.Credential) {
	p.mu.Lock()
	p.cred = cred
	p.stale = false
	p.mu.Unlock()
}

// current returns the installed session even when it is stale, for status
// output. A nil result means the app never handed one over (or closed).
func (p *provider) current() *session.Credential {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cred
}

// live reports whether the data plane may still connect with the session.
func (p *provider) live() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cred != nil && !p.stale
}
