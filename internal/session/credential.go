// Package session carries the credential the data plane consumes. There is no
// provider here: the control plane authenticates, this repo is handed the
// result.
package session

import (
	"context"
	"net/http"

	"geektrust/internal/sdpc"
)

// Credential is everything the tunnel and resolver need from a live session.
type Credential struct {
	// AppID is the legacy fallback; matched resource rules always take priority.
	AppID           string
	LegacyRouting   bool
	GatewayOverride bool
	Original        *Credential
	SID             string
	DeviceID        string
	Username        string
	ConnectionID    string
	CsrfToken       string
	Cookies         []*http.Cookie
	Gateways        []string
	DNS             []string
	// Policy is the full routing policy (domain/IP/CIDR × port → appId).
	Policy *sdpc.Resource
}

// CredentialProvider is the contract between whoever owns the credential
// (the FFI shell) and its consumers (tunnel, resolver, l3).
type CredentialProvider interface {
	// Credential returns current valid credentials.
	Credential(ctx context.Context) (*Credential, error)
	// InvalidateIfCurrent drops a cached credential only when expected is
	// still current, so a stale rejection cannot erase a newer one.
	InvalidateIfCurrent(expected *Credential) bool
}
