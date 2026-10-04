// Package config holds the proxy listener settings. Everything that describes a
// controller, a keystore or a config file belongs to the control plane, which
// lives in the Flutter app — this repo is handed a session and a policy.
package config

// Inbound holds the proxy listener configuration.
type Inbound struct {
	SOCKS5 Listener `toml:"socks5"`
	HTTP   Listener `toml:"http"`
}

// Listener is a single proxy listener.
type Listener struct {
	Enabled bool   `toml:"enabled"`
	Listen  string `toml:"listen"`
}
