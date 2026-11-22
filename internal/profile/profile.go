// Package profile holds the user's tunnel profile. It is the single shared
// data contract between the provider, engine, service and CLI packages.
//
// The profile contains a WireGuard private key, so it must only ever be
// written with paths.WriteSecureFile (SYSTEM + Administrators only).
package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

const CurrentVersion = 1

// Provider identifiers.
const (
	ProviderWARP      = "warp"      // Cloudflare WARP (free)
	ProviderProton    = "proton"    // Proton VPN WireGuard config (Free or Plus)
	ProviderWireGuard = "wireguard" // any other standard WireGuard .conf
)

// WireGuard is a provider-neutral WireGuard peer configuration.
type WireGuard struct {
	PrivateKey    string   `json:"private_key"`             // base64, 32 bytes
	Addresses     []string `json:"addresses"`               // CIDR, e.g. "10.2.0.2/32"
	DNS           []string `json:"dns,omitempty"`           // IP addresses only
	PeerPublicKey string   `json:"peer_public_key"`         // base64, 32 bytes
	PresharedKey  string   `json:"preshared_key,omitempty"` // base64, optional
	Endpoint      string   `json:"endpoint"`                // host:port
	Reserved      []byte   `json:"reserved,omitempty"`      // WARP client_id (3 bytes), optional
	MTU           int      `json:"mtu,omitempty"`           // 0 = engine default
}

// Profile is persisted as JSON in %ProgramData%\AuraSplitTR\profile.json.
type Profile struct {
	Version   int       `json:"version"`
	Provider  string    `json:"provider"`
	WireGuard WireGuard `json:"wireguard"`

	// TunnelBrowserDiscord is kept for compatibility with existing profiles
	// and is ignored: the Discord domains are always tunnelled from every
	// process, browsers included.
	TunnelBrowserDiscord bool `json:"tunnel_browser_discord"`

	// ExtraProcessNames are additional executable names (e.g. "Vesktop.exe")
	// whose traffic is tunnelled.
	ExtraProcessNames []string `json:"extra_process_names,omitempty"`
}

// Validate performs structural validation. It never logs secret values.
func (p *Profile) Validate() error {
	if p == nil {
		return errors.New("profile is nil")
	}
	switch p.Provider {
	case ProviderWARP, ProviderProton, ProviderWireGuard:
	default:
		return fmt.Errorf("unknown provider %q", p.Provider)
	}
	wg := p.WireGuard
	if err := validateKey(wg.PrivateKey); err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	if err := validateKey(wg.PeerPublicKey); err != nil {
		return fmt.Errorf("peer public key: %w", err)
	}
	if wg.PresharedKey != "" {
		if err := validateKey(wg.PresharedKey); err != nil {
			return fmt.Errorf("preshared key: %w", err)
		}
	}
	if len(wg.Addresses) == 0 {
		return errors.New("no interface address")
	}
	for _, a := range wg.Addresses {
		if _, err := netip.ParsePrefix(a); err != nil {
			return fmt.Errorf("bad address %q: %w", a, err)
		}
	}
	for _, d := range wg.DNS {
		if _, err := netip.ParseAddr(d); err != nil {
			return fmt.Errorf("bad dns %q: %w", d, err)
		}
	}
	if wg.Endpoint == "" || !strings.Contains(wg.Endpoint, ":") {
		return errors.New("endpoint must be host:port")
	}
	if len(wg.Reserved) != 0 && len(wg.Reserved) != 3 {
		return errors.New("reserved must be 3 bytes")
	}
	if wg.MTU != 0 && (wg.MTU < 1280 || wg.MTU > 1500) {
		return errors.New("mtu out of range (1280-1500)")
	}
	for _, n := range p.ExtraProcessNames {
		if n == "" || strings.ContainsAny(n, `\/:*?"<>|`) || !strings.HasSuffix(strings.ToLower(n), ".exe") {
			return fmt.Errorf("bad process name %q", n)
		}
	}
	return nil
}

func validateKey(k string) error {
	b, err := decodeKey(k)
	if err != nil {
		return err
	}
	if len(b) != 32 {
		return errors.New("key must be 32 bytes")
	}
	return nil
}

// Load reads and validates a profile.
func Load(path string) (*Profile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Profile
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("parse profile: %w", err)
	}
	if p.Version != CurrentVersion {
		return nil, fmt.Errorf("unsupported profile version %d", p.Version)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Marshal returns the JSON encoding to be written via paths.WriteSecureFile.
func (p *Profile) Marshal() ([]byte, error) {
	p.Version = CurrentVersion
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return json.MarshalIndent(p, "", "  ")
}
