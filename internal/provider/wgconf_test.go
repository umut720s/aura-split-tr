package provider

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	"aurasplit/internal/profile"
)

func testKey(t *testing.T) string {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate test key:", err)
	}
	return base64.StdEncoding.EncodeToString(k.Bytes())
}

func testConf(private, public string) string {
	return "[Interface]\nPrivateKey = " + private + "\nAddress = 10.0.0.2\n[Peer]\nPublicKey = " + public + "\nEndpoint = vpn.example:51820\n"
}

func TestParseWireGuardConf(t *testing.T) {
	private, public, psk := testKey(t), testKey(t), testKey(t)
	data := "\ufeff; config\r\n[iNtErFaCe]\r\npRiVaTeKeY = " + private + " # secret\r\n" +
		"Address = 10.0.0.2, 2001:db8::2, 10.1.0.2/24\r\nDNS = 1.1.1.1, search.example, 2606:4700:4700::1111\r\nMTU=1420\r\n" +
		"[pEeR]\r\nPublicKey=" + public + "\r\nPresharedKey=" + psk + "\r\nEndpoint=[2001:db8::1]:51820 ; peer\r\nAllowedIPs=ignored\r\n"
	wg, err := ParseWireGuardConf([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if wg.PrivateKey != private || wg.PeerPublicKey != public || wg.PresharedKey != psk {
		t.Fatal("key fields differ")
	}
	if !reflect.DeepEqual(wg.Addresses, []string{"10.0.0.2/32", "2001:db8::2/128", "10.1.0.2/24"}) {
		t.Fatal("unexpected addresses")
	}
	if !reflect.DeepEqual(wg.DNS, []string{"1.1.1.1", "2606:4700:4700::1111"}) || wg.MTU != 1420 {
		t.Fatal("unexpected DNS or MTU")
	}
	if err := (&profile.Profile{Provider: profile.ProviderWireGuard, WireGuard: wg}).Validate(); err != nil {
		t.Fatal("profile validation failed")
	}
}

func TestParseWireGuardConfErrorsNeverExposeKeys(t *testing.T) {
	private, public := testKey(t), testKey(t)
	valid := testConf(private, public)
	tests := map[string]string{
		"empty":               "",
		"oversize":            valid + strings.Repeat("#", 64*1024),
		"multiple peers":      valid + "[Peer]\nPublicKey=" + public,
		"multiple interfaces": valid + "[Interface]\n",
		"missing peer":        strings.Split(valid, "[Peer]")[0],
		"missing interface":   strings.Split(valid, "[Peer]")[1],
		"missing private":     strings.Replace(valid, "PrivateKey = "+private, "", 1),
		"missing public":      strings.Replace(valid, "PublicKey = "+public, "", 1),
		"missing address":     strings.Replace(valid, "Address = 10.0.0.2", "", 1),
		"missing endpoint":    strings.Replace(valid, "Endpoint = vpn.example:51820", "", 1),
		"bad private":         strings.Replace(valid, private, private+"!", 1),
		"bad public":          strings.Replace(valid, public, private+"!", 1),
		"bad psk":             valid + "PresharedKey=" + private + "!\n",
		"bad address":         strings.Replace(valid, "10.0.0.2", private, 1),
		"bad MTU":             valid + "[Interface]\nMTU=" + private,
		"invalid MTU":         strings.Replace(valid, "Address =", "MTU = 999\nAddress =", 1),
		"invalid MTU text":    strings.Replace(valid, "Address =", "MTU = "+private+"\nAddress =", 1),
		"bad endpoint":        strings.Replace(valid, "vpn.example:51820", private, 1),
		"bad port":            strings.Replace(valid, "51820", "70000", 1),
		"bad line":            valid + strings.TrimRight(private, "="),
		"bad section":         valid + "[" + private + "]",
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			wg, err := ParseWireGuardConf([]byte(data))
			if err == nil {
				t.Fatal("expected error")
			}
			if strings.Contains(err.Error(), private) || strings.Contains(err.Error(), public) {
				t.Fatal("error exposed key material")
			}
			if !reflect.DeepEqual(wg, profile.WireGuard{}) {
				t.Fatal("partial config returned on error")
			}
		})
	}
	// The size boundary itself is allowed.
	data := valid + "#" + strings.Repeat("x", 64*1024-len(valid)-1)
	if _, err := ParseWireGuardConf([]byte(data)); err != nil {
		t.Fatal("64 KiB config rejected")
	}
}

func TestDetectProvider(t *testing.T) {
	for _, data := range []string{"# Key for workstation", "; Proton VPN", "Endpoint = nl.protonvpn.net:51820", "DNS=8.8.8.8, 10.2.0.1"} {
		if DetectProvider([]byte(data)) != profile.ProviderProton {
			t.Fatal("missed Proton hint")
		}
	}
	for _, data := range []string{"", "Endpoint=vpn.example:1234", "DNS=10.2.0.10", "PrivateKey=protonvpn"} {
		if DetectProvider([]byte(data)) != profile.ProviderWireGuard {
			t.Fatal("incorrect Proton hint")
		}
	}
}
