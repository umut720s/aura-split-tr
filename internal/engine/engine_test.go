package engine

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	stdjson "encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing/service"

	"aurasplit/internal/profile"
)

func newKey(t *testing.T) string {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k.Bytes())
}

func pubKey(t *testing.T) string {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
}

func testProfile(t *testing.T, provider string) *profile.Profile {
	p := &profile.Profile{
		Version:  profile.CurrentVersion,
		Provider: provider,
		WireGuard: profile.WireGuard{
			PrivateKey:    newKey(t),
			Addresses:     []string{"10.2.0.2/32"},
			DNS:           []string{"10.2.0.1"},
			PeerPublicKey: pubKey(t),
			PresharedKey:  newKey(t),
			Endpoint:      "198.51.100.7:51820",
		},
		ExtraProcessNames: []string{"Vesktop.exe"},
	}
	if provider == profile.ProviderWARP {
		p.WireGuard.Addresses = []string{"172.16.0.2/32", "2606:4700:110:8a36::1/128"}
		p.WireGuard.DNS = nil
		p.WireGuard.PresharedKey = ""
		p.WireGuard.Endpoint = "engage.cloudflareclient.com:2408"
		p.WireGuard.Reserved = []byte{1, 2, 3}
	}
	return p
}

type recordingManager struct {
	mu    sync.Mutex
	notes []string
}

func (m *recordingManager) ReportDeprecated(n deprecated.Note) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.notes = append(m.notes, n.Name)
}

func TestBuildConfigParsesWithSingBox(t *testing.T) {
	for _, prov := range []string{profile.ProviderWARP, profile.ProviderProton} {
		for _, mode := range []Mode{ModeTunnel, ModeBlock} {
			t.Run(fmt.Sprintf("%s/mode=%d", prov, mode), func(t *testing.T) {
				p := testProfile(t, prov)
				// The legacy browser option no longer changes anything.
				p.TunnelBrowserDiscord = mode == ModeBlock
				// A resolved peer, as prepareBox would pass it.
				env := netEnv{peerAddr: "192.0.2.10"}
				cfg, err := buildConfig(p, logOptions{Level: LogLevelDefault, Timestamp: true}, mode, env)
				if err != nil {
					t.Fatal(err)
				}
				rec := &recordingManager{}
				ctx := include.Context(service.ContextWith[deprecated.Manager](context.Background(), rec))
				if _, err := parseOptions(ctx, cfg); err != nil {
					t.Fatalf("sing-box rejected config: %v\n%s", err, cfg)
				}
				if len(rec.notes) != 0 {
					t.Fatalf("deprecated options used: %v", rec.notes)
				}
				checkStructure(t, p, cfg, mode)
			})
		}
	}
}

func checkStructure(t *testing.T, p *profile.Profile, cfg []byte, mode Mode) {
	t.Helper()
	var c config
	if err := stdjson.Unmarshal(cfg, &c); err != nil {
		t.Fatal(err)
	}
	wantAction, wantOutbound := "route", TagWG
	if mode == ModeBlock {
		wantAction, wantOutbound = "reject", ""
	}
	r := c.Route.Rules
	if len(r) != 6 || r[0].Action != "sniff" || r[1].Action != "hijack-dns" || r[1].Protocol[0] != "dns" ||
		!r[2].IPIsPrivate || r[2].Outbound != TagDirect {
		t.Fatalf("unexpected rule prefix: %+v", r)
	}
	for _, rule := range r[3:] {
		if rule.Action != wantAction || rule.Outbound != wantOutbound {
			t.Fatalf("discord rule action: %+v", rule)
		}
	}
	if !contains(r[3].ProcessPathRegex, DiscordPathRegex) || !contains(r[3].ProcessPathRegex, DiscordInstallerRegex) {
		t.Fatalf("process path rule: %+v", r[3])
	}
	for _, n := range append(append([]string{}, DiscordProcessNames...), "Vesktop.exe") {
		if !contains(r[4].ProcessName, n) {
			t.Fatalf("process name rule lacks %s: %+v", n, r[4])
		}
	}
	if contains(r[4].ProcessName, "Update.exe") {
		t.Fatal("Update.exe must not be matched by name")
	}
	for _, d := range []string{"discord.com", "discord.gg", "updates.discord.com", "dl.discordapp.net",
		"discordsays.com", "dis.gd", "discord.gift", "discord.dev", "cdn.discordapp.com"} {
		if !domainMatches(r[5], d) {
			t.Fatalf("domain rule misses %s: %+v", d, r[5])
		}
	}
	if !contains(r[5].Domain, "discord-attachments-uploads-prd.storage.googleapis.com") ||
		domainMatches(r[5], "storage.googleapis.com") {
		t.Fatalf("attachment host rule: %+v", r[5])
	}
	if c.Route.Final != TagDirect || !c.Route.AutoDetectInterface || c.Route.DefaultDomainResolver != TagDNSLocal {
		t.Fatalf("route options: %+v", c.Route)
	}
	tun := c.Inbounds[0]
	if !tun.AutoRoute || !tun.StrictRoute || tun.InterfaceName != TunInterfaceName || tun.Stack != "mixed" {
		t.Fatalf("tun: %+v", tun)
	}
	if !c.DNS.ReverseMapping || c.DNS.Final != TagDNSLocal {
		t.Fatalf("dns options: %+v", c.DNS)
	}
	// DNS: Discord domains must go to the tunnelled resolver (or be
	// rejected in block mode), never to the local one.
	discordDNS := false
	for _, d := range c.DNS.Rules {
		if contains(d.DomainSuffix, "discord.com") && len(d.QueryType) == 0 {
			discordDNS = d.Action == wantAction && (mode == ModeBlock || d.Server == TagDNSRemote) &&
				contains(d.Domain, DiscordHosts[0])
		}
	}
	if !discordDNS {
		t.Fatalf("dns rules: %+v", c.DNS.Rules)
	}
	if mode == ModeBlock {
		if len(c.Endpoints) != 0 || strings.Contains(string(cfg), p.WireGuard.PrivateKey) || strings.Contains(string(cfg), `"wg"`) {
			t.Fatal("block config must not contain the WireGuard endpoint")
		}
		return
	}
	ep := c.Endpoints[0]
	if ep.DomainResolver != TagDNSLocal || ep.Tag != TagWG {
		t.Fatalf("endpoint: %+v", ep)
	}
	if p.Provider == profile.ProviderWARP && (ep.MTU != warpWGMTU || len(ep.Peers[0].Reserved) != 3) {
		t.Fatalf("warp endpoint: mtu=%d reserved=%v", ep.MTU, ep.Peers[0].Reserved)
	}
	if c.DNS.Servers[0].Detour != TagWG {
		t.Fatalf("remote dns detour: %+v", c.DNS.Servers[0])
	}
	if p.Provider == profile.ProviderProton && c.DNS.Servers[0].Server != "10.2.0.1" {
		t.Fatalf("remote dns server: %+v", c.DNS.Servers[0])
	}
	if strings.Contains(string(cfg), "clash_api") || strings.Contains(string(cfg), "experimental") {
		t.Fatal("experimental options present")
	}
}

// domainMatches applies sing-box domain / domain_suffix semantics.
func domainMatches(r routeRule, host string) bool {
	if contains(r.Domain, host) {
		return true
	}
	for _, s := range r.DomainSuffix {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

func TestProcessRegexes(t *testing.T) {
	installer := regexp.MustCompile(DiscordInstallerRegex)
	path := regexp.MustCompile(DiscordPathRegex)
	for _, s := range []string{
		`C:\Users\u\Downloads\DiscordSetup.exe`,
		`C:\Users\u\Downloads\DiscordSetup (1).exe`,
		`D:\x\DiscordPTBSetup.exe`,
		`D:\x\discordcanarysetup.EXE`,
	} {
		if !installer.MatchString(s) {
			t.Errorf("installer regex misses %s", s)
		}
	}
	for _, s := range []string{`C:\x\Update.exe`, `C:\x\NotDiscordSetup\a.exe`, `C:\x\Discord.exe`, `C:\x\DiscordSetup.exe.bak`} {
		if installer.MatchString(s) {
			t.Errorf("installer regex matches %s", s)
		}
	}
	if !path.MatchString(`C:\Users\u\AppData\Local\Discord\Update.exe`) ||
		!path.MatchString(`C:\Users\u\AppData\Local\DiscordCanary\app-1.0\DiscordCanary.exe`) ||
		path.MatchString(`C:\Users\u\AppData\Local\Other\Update.exe`) {
		t.Error("path regex")
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func TestCheck(t *testing.T) {
	if !tagsOK {
		if err := Check(testProfile(t, profile.ProviderWARP)); !errors.Is(err, ErrMissingBuildTags) {
			t.Fatalf("want ErrMissingBuildTags, got %v", err)
		}
		t.Skip("built without " + BuildTags)
	}
	for _, prov := range []string{profile.ProviderWARP, profile.ProviderProton} {
		if err := Check(testProfile(t, prov)); err != nil {
			t.Fatalf("%s: %v", prov, err)
		}
	}
}

func TestErrorsDoNotLeakKeys(t *testing.T) {
	p := testProfile(t, profile.ProviderProton)
	p.WireGuard.Endpoint = "198.51.100.7:notaport"
	_, err := BuildConfig(p)
	if err == nil {
		t.Fatal("expected error")
	}
	assertNoSecret(t, p, err)

	p = testProfile(t, profile.ProviderProton)
	p.WireGuard.MTU = 9000 // rejected by Validate
	err = Check(p)
	if err == nil {
		t.Fatal("expected error")
	}
	assertNoSecret(t, p, err)

	// A dependency error that echoes the key must be scrubbed.
	p = testProfile(t, profile.ProviderProton)
	raw, _ := base64.StdEncoding.DecodeString(p.WireGuard.PrivateKey)
	leaky := fmt.Errorf("bad key %s / %x / %s", p.WireGuard.PrivateKey, raw, p.WireGuard.PresharedKey)
	assertNoSecret(t, p, redact(p, leaky))
}

func assertNoSecret(t *testing.T, p *profile.Profile, err error) {
	t.Helper()
	msg := err.Error()
	for _, s := range secretForms(p) {
		if strings.Contains(msg, s) {
			t.Fatalf("error leaks secret: %q", msg)
		}
	}
	for u := errors.Unwrap(err); u != nil; u = errors.Unwrap(u) {
		for _, s := range secretForms(p) {
			if strings.Contains(u.Error(), s) {
				t.Fatal("wrapped error leaks secret")
			}
		}
	}
}
