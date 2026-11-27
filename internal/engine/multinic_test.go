package engine

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/control"
)

func TestNICDiagnosticsPrivacyAndSelection(t *testing.T) {
	var lines []string
	var calls []int
	var nics []adapter.NetworkInterface
	for _, idx := range []int{25, 55} {
		nics = append(nics, adapter.NetworkInterface{Interface: control.Interface{Index: idx, Name: "fixture", Flags: net.FlagUp}, DNSServers: []string{"192.0.2.53"}, Gateways: []netip.Addr{netip.MustParseAddr("192.0.2.1")}})
	}
	diagnoseNICs(context.Background(), 25, nics, func(string) int { return 55 }, func(_ context.Context, nic adapter.NetworkInterface, _ string) string {
		calls = append(calls, nic.Index)
		return "başarılı"
	}, func(s string) { lines = append(lines, s) })
	out := strings.Join(lines, "\n")
	if len(calls) != 5 || calls[2] != 55 || !strings.Contains(out, "otomatik çıkış indeksi=55") || !strings.Contains(out, "indeksi=25") || !strings.Contains(out, "indeksi=55") || !strings.Contains(out, "seçili=true") || !strings.Contains(out, "seçili=false") || strings.Contains(out, "192.0.2.") {
		t.Fatal(out, calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	diagnoseNICs(ctx, 25, nics, func(string) int { return 25 }, func(context.Context, adapter.NetworkInterface, string) string {
		t.Fatal("probe after cancellation")
		return ""
	}, func(string) {})
}

func TestAdapterTablesDiagnostics(t *testing.T) {
	routes := []routeRow{
		{ifIndex: 25, prefix: defaultV4, metric: 30},
		{ifIndex: 25, prefix: defaultV4, metric: 10},
		{ifIndex: 55, prefix: defaultV4, metric: 20},
		{ifIndex: 75, prefix: netip.MustParsePrefix("192.0.2.0/24"), metric: 1},
	}
	var nics []diagnosticNIC
	for _, idx := range []int{25, 55, 75} {
		n := diagnosticNIC{NetworkInterface: adapter.NetworkInterface{Interface: control.Interface{Index: idx, Name: "fixture", Flags: net.FlagUp, Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")}}, DNSServers: []string{"192.0.2.53", "10.0.0.53", "1.1.1.1"}, Gateways: []netip.Addr{netip.MustParseAddr("192.0.2.254")}}, ifType: 6}
		n.v4.defaults(uint32(idx), routes, true)
		n.v4.known, n.v4.metric, n.v4.forwarding = true, 5, true
		n.v6.defaults(uint32(idx), []routeRow{{ifIndex: 55, prefix: defaultV6, metric: 40}}, true)
		n.v6.known, n.v6.weakSend, n.v6.weakReceive = true, true, true
		nics = append(nics, n)
	}
	if nics[0].v4.routeMetric != 10 || !nics[1].v6.defaultRoute || nics[2].v4.defaultRoute {
		t.Fatal("incorrect default route reduction", nics)
	}
	var lines []string
	reportNICs(25, nics, func(server string) int {
		if server == "192.0.2.53" {
			return 55
		}
		return 25
	}, func(level, msg string) {
		if level != "WARN" {
			t.Fatal(level)
		}
		lines = append(lines, msg)
	})
	out := strings.Join(lines, "\n")
	for _, want := range []string{"indeksi=25", "indeksi=55", "indeksi=75", "IPv4", "IPv6", "IfType=6", "DNS sayısı=3", "kapsam=yerel-bağlantı", "kapsam=özel", "kapsam=genel", "otomatik çıkış indeksi=55", "rota metriği=10", "arayüz metriği=5", "iletme=true", "zayıf-host-gönder=true", "zayıf-host-al=true"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q: %s", want, out)
		}
	}
	for _, address := range []string{"192.0.2.", "10.0.0.53", "1.1.1.1"} {
		if strings.Contains(out, address) {
			t.Fatal("address leaked", out)
		}
	}
	nics[1].Flags = 0
	if diagnosticLevel(nics) != "INFO" {
		t.Fatal("down NIC counted")
	}
	nics[1].Flags = net.FlagUp
	nics[1].v4.defaultRoute = false
	if diagnosticLevel(nics) != "INFO" {
		t.Fatal("IPv6-only default counted")
	}
	if diagnosticLevel(nil) != "INFO" {
		t.Fatal("empty table warning")
	}
}

func TestDNSScope(t *testing.T) {
	for server, want := range map[string]string{"invalid": "bilinmiyor", "fe80::1%55": "özel", "fd00::53": "özel", "100.64.0.53": "özel", "2606:4700:4700::1111": "genel"} {
		if got := dnsScope(server, nil); got != want {
			t.Errorf("%s: %s", server, got)
		}
	}
}
