// Package provider imports WireGuard configurations and registers WARP devices.
package provider

import (
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"aurasplit/internal/profile"
)

func validKey(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}

func addressPrefix(s string) (string, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.String(), true
	}
	if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
		return netip.PrefixFrom(a, a.BitLen()).String(), true
	}
	return "", false
}

func validEndpoint(s string) bool {
	host, port, err := net.SplitHostPort(s)
	n, portErr := strconv.Atoi(port)
	return err == nil && host != "" && !strings.ContainsAny(host, " \t\r\n/#?@") && portErr == nil && n > 0 && n <= 65535
}

// ParseWireGuardConf imports one interface and exactly one peer. Errors never
// echo input, since even malformed fields can contain secret material.
func ParseWireGuardConf(data []byte) (profile.WireGuard, error) {
	var wg profile.WireGuard
	fail := func(message string) (profile.WireGuard, error) { return profile.WireGuard{}, errors.New(message) }
	if len(data) > 64*1024 {
		return fail("WireGuard configuration exceeds 64 KiB")
	}
	section, peers, interfaces := "", 0, 0
	for _, line := range strings.Split(strings.TrimPrefix(string(data), "\ufeff"), "\n") {
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			switch strings.ToLower(line) {
			case "[interface]":
				interfaces++
				section = "interface"
			case "[peer]":
				peers++
				section = "peer"
			default:
				return fail("invalid WireGuard section")
			}
			if peers > 1 || interfaces > 1 {
				return fail("exactly one interface and one peer are supported")
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || section == "" {
			return fail("invalid WireGuard configuration line")
		}
		key, value = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value)
		if section == "interface" {
			switch key {
			case "privatekey":
				wg.PrivateKey = value
			case "address":
				for _, item := range strings.Split(value, ",") {
					a, ok := addressPrefix(strings.TrimSpace(item))
					if !ok {
						return fail("invalid interface address")
					}
					wg.Addresses = append(wg.Addresses, a)
				}
			case "dns":
				for _, item := range strings.Split(value, ",") {
					if a, err := netip.ParseAddr(strings.TrimSpace(item)); err == nil && a.Zone() == "" {
						wg.DNS = append(wg.DNS, a.String())
					}
				}
			case "mtu":
				n, err := strconv.Atoi(value)
				if err != nil || n < 1280 || n > 1500 {
					return fail("invalid MTU (expected 1280-1500)")
				}
				wg.MTU = n
			}
		} else {
			switch key {
			case "publickey":
				wg.PeerPublicKey = value
			case "presharedkey":
				wg.PresharedKey = value
			case "endpoint":
				wg.Endpoint = value
				// AllowedIPs is deliberately ignored: the engine owns routing.
			}
		}
	}
	if interfaces != 1 || peers != 1 || len(wg.Addresses) == 0 || !validKey(wg.PrivateKey) || !validKey(wg.PeerPublicKey) || !validEndpoint(wg.Endpoint) {
		return fail("missing or invalid required WireGuard field")
	}
	if wg.PresharedKey != "" && !validKey(wg.PresharedKey) {
		return fail("invalid preshared key")
	}
	return wg, nil
}

// DetectProvider identifies Proton hints in comments, endpoints, and DNS fields.
func DetectProvider(data []byte) string {
	for _, line := range strings.Split(strings.TrimPrefix(string(data), "\ufeff"), "\n") {
		line = strings.ToLower(strings.TrimSpace(line))
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			comment := strings.TrimSpace(line[i+1:])
			if strings.HasPrefix(comment, "key for") || strings.Contains(comment, "proton") {
				return profile.ProviderProton
			}
			line = strings.TrimSpace(line[:i])
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "endpoint":
			if strings.Contains(value, "protonvpn") {
				return profile.ProviderProton
			}
		case "dns":
			for _, item := range strings.Split(value, ",") {
				if strings.TrimSpace(item) == "10.2.0.1" {
					return profile.ProviderProton
				}
			}
		}
	}
	return profile.ProviderWireGuard
}
