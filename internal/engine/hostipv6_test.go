package engine

import (
	"encoding/json"
	"errors"
	"net/netip"
	"testing"

	"aurasplit/internal/profile"
)

// Tests never resolve real host names or read the host's tables: by
// default resolution fails and the host has no IPv6.
func init() {
	physicalNetwork = func() (physicalLink, error) { return physicalLink{index: 1, up: true}, nil }
	resolvePeerHost = func(string, bool) (netip.Addr, error) { return netip.Addr{}, errors.New("no network in tests") }
	hostIPv6 = func() (bool, error) { return false, nil }
}

func pinHostIPv6(t *testing.T, v6 bool) {
	t.Helper()
	old := hostIPv6
	hostIPv6 = func() (bool, error) { return v6, nil }
	t.Cleanup(func() { hostIPv6 = old })
}

// A host-name peer (WARP) is replaced by its resolved IPv4 address.
func TestPeerHostResolvedToIP(t *testing.T) {
	old := resolvePeerHost
	t.Cleanup(func() { resolvePeerHost = old })
	var gotV4Only bool
	resolvePeerHost = func(host string, v4 bool) (netip.Addr, error) {
		gotV4Only = v4
		return netip.MustParseAddr("192.0.2.10"), nil
	}
	pinHostIPv6(t, false)
	p := testProfile(t, "warp")
	p.WireGuard.Endpoint = "engage.example.invalid:2408"
	b, err := BuildConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	var c config
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	if got := c.Endpoints[0].Peers[0].Address; got != "192.0.2.10" {
		t.Fatalf("peer address = %q", got)
	}
	if !gotV4Only {
		t.Fatal("IPv4-only resolution not requested on an IPv6-less host")
	}
}

// An unresolvable host-name peer is a preparation error, never a
// configuration that carries the host name (Bug 3 path).
func TestUnresolvedPeerIsPreparationError(t *testing.T) {
	p := testProfile(t, profile.ProviderWARP) // host-name endpoint; resolver fails in tests
	if _, err := BuildConfig(p); !errors.Is(err, ErrEndpointUnresolved) {
		t.Fatalf("BuildConfig error = %v, want ErrEndpointUnresolved", err)
	}
	if _, err := resolveNetEnv(p, ModeTunnel, true); !errors.Is(err, ErrEndpointUnresolved) {
		t.Fatalf("resolveNetEnv error = %v", err)
	}
	// prepareBox (the real one) refuses before creating sing-box.
	if !tagsOK {
		t.Skip("built without " + BuildTags)
	}
	if r, err := prepareBox(p, ModeTunnel, LogLevelDefault, nil); !errors.Is(err, ErrEndpointUnresolved) || r != nil {
		t.Fatalf("prepareBox = %v, %v", r, err)
	}
	// Block mode needs no endpoint and still works.
	if _, err := BuildBlockConfig(p); err != nil {
		t.Fatalf("block config: %v", err)
	}
	// Check (setup validation) keeps the name: that configuration is never
	// started.
	if env, err := resolveNetEnv(p, ModeTunnel, false); err != nil || env.peerAddr != "" {
		t.Fatalf("non-strict env = %+v, %v", env, err)
	}
}

// The WireGuard endpoint must dial through the dedicated non-empty direct
// outbound (ClientBind path, no IPv6 socket), and hosts without IPv6 must
// get empty AAAA answers for every name.
func TestWireGuardDetourAndHostIPv6Rule(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		old := hostIPv6
		hostIPv6 = func() (bool, error) { return v6, nil }
		b, err := BuildConfig(testProfile(t, "proton"))
		hostIPv6 = old
		if err != nil {
			t.Fatal(err)
		}
		var c config
		if err := json.Unmarshal(b, &c); err != nil {
			t.Fatal(err)
		}
		if len(c.Endpoints) != 1 || c.Endpoints[0].Detour != TagWGDirect {
			t.Fatalf("endpoint detour = %+v", c.Endpoints)
		}
		found := false
		for _, o := range c.Outbounds {
			if o.Tag == TagWGDirect && o.Type == "direct" && o.ConnectTimeout != "" {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing non-empty %s outbound: %+v", TagWGDirect, c.Outbounds)
		}
		if got := len(c.Inbounds[0].Address); (v6 && got != 2) || (!v6 && got != 1) {
			t.Fatalf("hostIPv6=%v: tun addresses %v", v6, c.Inbounds[0].Address)
		}
		first := c.DNS.Rules[0]
		global := len(first.QueryType) == 1 && first.QueryType[0] == "AAAA" && first.Action == "predefined" &&
			len(first.Domain) == 0 && len(first.DomainSuffix) == 0 && len(first.ProcessName) == 0 && len(first.ProcessPathRegex) == 0
		if global == v6 {
			t.Fatalf("hostIPv6=%v: global AAAA rule present=%v", v6, global)
		}
	}
}

// An error reading the tables counts as "no IPv6" for the configuration.
func TestHostHasIPv6ErrorIsFalse(t *testing.T) {
	old := hostIPv6
	t.Cleanup(func() { hostIPv6 = old })
	hostIPv6 = func() (bool, error) { return true, errors.New("table unavailable") }
	if hostHasIPv6() {
		t.Fatal("error must not report IPv6")
	}
}

// Decision logic with fake IP helper tables.
func TestDecideHostIPv6(t *testing.T) {
	const eth, wifi, vswitch, tun, lo = 7, 9, 21, 30, 1
	const ethernetCsmacd = 6
	ifaces := map[uint32]ifaceRow{
		eth:     {up: true, alias: "Ethernet", ifType: ethernetCsmacd, v4OK: true, v4Connected: true, v4Metric: 25},
		wifi:    {up: false, alias: "Wi-Fi", ifType: 71, v4OK: true, v4Connected: true, v4Metric: 35},
		vswitch: {up: true, alias: "vEthernet (Default Switch)", ifType: ethernetCsmacd, v4OK: true, v4Connected: true, v4Metric: 5000},
		tun:     {up: true, alias: "AuraSplitTR", ifType: ifTypePropVirtual, v4OK: true, v4Connected: true, v4Metric: 0},
		lo:      {up: true, loopback: true, alias: "Loopback Pseudo-Interface 1", ifType: ifTypeSoftwareLoopback, v4OK: true, v4Connected: true, v4Metric: 75},
	}
	global := func(idx uint32) addrRow {
		return addrRow{ifIndex: idx, addr: netip.MustParseAddr("2001:db8:1::5"), preferred: true}
	}
	def := func(idx uint32) routeRow { return routeRow{ifIndex: idx, prefix: netip.MustParsePrefix("::/0")} }
	// IPv4 default route of each interface (the same default for every
	// case: Ethernet is the selected IPv4 egress).
	v4def := func(idx, metric uint32) routeRow {
		return routeRow{ifIndex: idx, prefix: netip.MustParsePrefix("0.0.0.0/0"), metric: metric}
	}
	v4 := []routeRow{v4def(tun, 0), v4def(vswitch, 0), v4def(eth, 0), v4def(lo, 0), v4def(wifi, 0)}
	cases := []struct {
		name   string
		addrs  []addrRow
		routes []routeRow
		want   bool
	}{
		{"native IPv6 on ethernet", []addrRow{global(eth)}, []routeRow{def(eth)}, true},
		{"IPv4-only host (no tables)", nil, nil, false},
		{"address without default route", []addrRow{global(eth)}, []routeRow{{ifIndex: eth, prefix: netip.MustParsePrefix("2001:db8:1::/64")}}, false},
		{"address on virtual adapter, default route elsewhere", []addrRow{global(vswitch)}, []routeRow{def(eth)}, false},
		{"default route without global address", []addrRow{{ifIndex: eth, addr: netip.MustParseAddr("fe80::1"), preferred: true}}, []routeRow{def(eth)}, false},
		{"ULA only", []addrRow{{ifIndex: eth, addr: netip.MustParseAddr("fd12:3456::1"), preferred: true}}, []routeRow{def(eth)}, false},
		{"tentative address", []addrRow{{ifIndex: eth, addr: netip.MustParseAddr("2001:db8:1::5")}}, []routeRow{def(eth)}, false},
		{"interface down", []addrRow{global(wifi)}, []routeRow{def(wifi)}, false},
		{"our own TUN", []addrRow{global(tun)}, []routeRow{def(tun)}, false},
		{"loopback", []addrRow{global(lo)}, []routeRow{def(lo)}, false},
		{"teredo", []addrRow{{ifIndex: eth, addr: netip.MustParseAddr("2001:0:53aa:64c::1"), preferred: true}}, []routeRow{def(eth)}, false},
		{"6to4", []addrRow{{ifIndex: eth, addr: netip.MustParseAddr("2002:c000:204::1"), preferred: true}}, []routeRow{def(eth)}, false},
		{"unknown interface index", []addrRow{global(99)}, []routeRow{def(99)}, false},
		{"one good among others", []addrRow{global(vswitch), global(eth)}, []routeRow{def(tun), def(eth)}, true},
		// Round 5: IPv6 address and ::/0 on an adapter that is up and
		// eligible, but is not the IPv4 default interface sing-box binds to.
		{"address and route on a different adapter than the IPv4 default", []addrRow{global(vswitch)}, []routeRow{def(vswitch)}, false},
		{"address on default, route on other adapter", []addrRow{global(eth), global(vswitch)}, []routeRow{def(vswitch)}, false},
	}
	for _, c := range cases {
		if got := decideHostIPv6(ifaces, v4, c.addrs, c.routes); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// The IPv4 default interface is chosen like sing-tun's monitor_windows.go.
func TestDefaultV4Interface(t *testing.T) {
	const a, b, virt, lo, down, disc, noV4 = 1, 2, 3, 4, 5, 6, 7
	ifaces := map[uint32]ifaceRow{
		a:    {up: true, ifType: 6, v4OK: true, v4Connected: true, v4Metric: 25},
		b:    {up: true, ifType: 71, v4OK: true, v4Connected: true, v4Metric: 10},
		virt: {up: true, ifType: ifTypePropVirtual, v4OK: true, v4Connected: true},
		lo:   {up: true, loopback: true, ifType: ifTypeSoftwareLoopback, v4OK: true, v4Connected: true},
		down: {up: false, ifType: 6, v4OK: true, v4Connected: true},
		disc: {up: true, ifType: 6, v4OK: true, v4Connected: false},
		noV4: {up: true, ifType: 6},
	}
	r := func(idx, metric uint32, pfx string) routeRow {
		return routeRow{ifIndex: idx, metric: metric, prefix: netip.MustParsePrefix(pfx)}
	}
	cases := []struct {
		name   string
		routes []routeRow
		want   uint32
		ok     bool
	}{
		{"none", nil, 0, false},
		{"IPv6 route ignored", []routeRow{r(a, 0, "::/0")}, 0, false},
		{"route + interface metric", []routeRow{r(a, 0, "0.0.0.0/0"), r(b, 20, "0.0.0.0/0")}, a, true}, // 25 < 30
		{"lower sum wins", []routeRow{r(a, 10, "0.0.0.0/0"), r(b, 0, "0.0.0.0/0")}, b, true},           // 35 > 10
		{"tie keeps first", []routeRow{r(b, 15, "0.0.0.0/0"), r(a, 0, "0.0.0.0/0")}, b, true},          // 25 == 25
		{"non-default ignored", []routeRow{r(b, 0, "0.0.0.0/1"), r(a, 100, "0.0.0.0/0")}, a, true},
		{"virtual, loopback, down, disconnected, no IPv4 entry skipped", []routeRow{
			r(virt, 0, "0.0.0.0/0"), r(lo, 0, "0.0.0.0/0"), r(down, 0, "0.0.0.0/0"),
			r(disc, 0, "0.0.0.0/0"), r(noV4, 0, "0.0.0.0/0"), r(99, 0, "0.0.0.0/0"), r(a, 500, "0.0.0.0/0"),
		}, a, true},
		{"only skipped interfaces", []routeRow{r(virt, 0, "0.0.0.0/0"), r(down, 0, "0.0.0.0/0")}, 0, false},
	}
	for _, c := range cases {
		got, ok := defaultV4Interface(ifaces, c.routes)
		if got != c.want || ok != c.ok {
			t.Errorf("%s: got %d,%v want %d,%v", c.name, got, ok, c.want, c.ok)
		}
	}
	// Moving the IPv4 default to the IPv6-capable adapter flips the answer.
	addrs := []addrRow{{ifIndex: b, addr: netip.MustParseAddr("2001:db8::1"), preferred: true}}
	v6 := []routeRow{r(b, 0, "::/0")}
	if decideHostIPv6(ifaces, []routeRow{r(a, 0, "0.0.0.0/0")}, addrs, v6) {
		t.Error("IPv6 on b while a is the IPv4 default must be false")
	}
	if !decideHostIPv6(ifaces, []routeRow{r(a, 0, "0.0.0.0/0"), r(b, 0, "0.0.0.0/0")}, addrs, v6) {
		t.Error("IPv6 on b while b is the IPv4 default must be true")
	}
}
