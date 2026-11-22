package provider

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"aurasplit/internal/profile"
)

// warpEndpoint can be replaced by package tests to avoid external requests.
var warpEndpoint = "https://api.cloudflareclient.com/v0a2158/reg"

// RegisterWARP registers a locally generated public key. The access token is
// deliberately excluded from the response type and never retained.
func RegisterWARP(ctx context.Context, c *http.Client) (profile.WireGuard, error) {
	fail := func(message string) (profile.WireGuard, error) { return profile.WireGuard{}, errors.New(message) }
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return fail("cannot generate WARP key")
	}
	var serial [16]byte
	if _, err := rand.Read(serial[:]); err != nil {
		return fail("cannot generate WARP serial")
	}
	body, err := json.Marshal(map[string]string{
		"key":        base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()),
		"install_id": "", "fcm_token": "", "tos": time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"model": "PC", "serial_number": hex.EncodeToString(serial[:]), "locale": "en_US",
	})
	if err != nil {
		return fail("cannot encode WARP registration")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, warpEndpoint, bytes.NewReader(body))
	if err != nil {
		return fail("cannot create WARP request")
	}
	req.Header.Set("User-Agent", "okhttp/3.12.1")
	req.Header.Set("CF-Client-Version", "a-6.30-3596")
	req.Header.Set("Content-Type", "application/json")
	if c == nil {
		c = &http.Client{Timeout: 20 * time.Second}
	}
	// Work on a copy so the caller's client is not modified, and never
	// follow a redirect: the registration body (our public key) must only
	// go to the configured endpoint.
	noRedirect := *c
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noRedirect.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return profile.WireGuard{}, ctx.Err()
		}
		return fail("WARP registration request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return fail("WARP registration was redirected; refusing to follow")
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fail("WARP registration returned unsuccessful HTTP status")
	}
	const maxResponse = 1 << 20
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return fail("cannot read WARP response")
	}
	if len(data) > maxResponse {
		return fail("WARP response exceeds 1 MiB")
	}
	var result struct {
		Config struct {
			Peers []struct {
				PublicKey string `json:"public_key"`
				Endpoint  struct {
					Host string `json:"host"`
				} `json:"endpoint"`
			} `json:"peers"`
			Interface struct {
				Addresses struct {
					V4 string `json:"v4"`
					V6 string `json:"v6"`
				} `json:"addresses"`
			} `json:"interface"`
			ClientID string `json:"client_id"`
		} `json:"config"`
	}
	if json.Unmarshal(data, &result) != nil {
		return fail("invalid WARP response JSON")
	}
	config := result.Config
	if len(config.Peers) == 0 || !validKey(config.Peers[0].PublicKey) {
		return fail("missing or invalid WARP peer")
	}
	reserved, err := base64.StdEncoding.DecodeString(config.ClientID)
	if err != nil || len(reserved) != 3 {
		return fail("invalid WARP client ID")
	}
	wg := profile.WireGuard{
		PrivateKey: base64.StdEncoding.EncodeToString(key.Bytes()), PeerPublicKey: config.Peers[0].PublicKey,
		Reserved: reserved, DNS: []string{"1.1.1.1", "1.0.0.1"}, MTU: 1280,
	}
	for i, s := range []string{config.Interface.Addresses.V4, config.Interface.Addresses.V6} {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" || (i == 0 && !a.Is4()) || (i == 1 && (!a.Is6() || a.Is4In6())) {
			return fail("missing or invalid WARP interface address")
		}
		wg.Addresses = append(wg.Addresses, netip.PrefixFrom(a, a.BitLen()).String())
	}
	wg.Endpoint = strings.TrimSpace(config.Peers[0].Endpoint.Host)
	if wg.Endpoint == "" {
		wg.Endpoint = "engage.cloudflareclient.com:2408"
	}
	if _, _, err := net.SplitHostPort(wg.Endpoint); err != nil {
		host := strings.TrimSuffix(strings.TrimPrefix(wg.Endpoint, "["), "]")
		if !strings.Contains(host, ":") || net.ParseIP(host) != nil {
			wg.Endpoint = net.JoinHostPort(host, "2408")
		}
	}
	if !validEndpoint(wg.Endpoint) {
		return fail("invalid WARP endpoint")
	}
	return wg, nil
}
