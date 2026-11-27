package engine

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/control"
)

type nicFamily struct {
	known, routesKnown, defaultRoute  bool
	routeMetric, metric               uint32
	forwarding, weakSend, weakReceive bool
}

type diagnosticNIC struct {
	adapter.NetworkInterface
	ifType uint32
	v4, v6 nicFamily
}

func (f *nicFamily) defaults(index uint32, routes []routeRow, known bool) {
	f.routesKnown = known
	for _, r := range routes {
		if r.ifIndex == index && r.prefix.Bits() == 0 {
			if !f.defaultRoute || r.metric < f.routeMetric {
				f.routeMetric = r.metric
			}
			f.defaultRoute = true
		}
	}
}

func diagnosticLevel(nics []diagnosticNIC) string {
	count := 0
	for _, n := range nics {
		if n.Flags&net.FlagUp != 0 && n.v4.defaultRoute {
			count++
		}
	}
	if count > 1 {
		return "WARN"
	}
	return "INFO"
}

func dnsScope(server string, prefixes []netip.Prefix) string {
	a, err := netip.ParseAddr(server)
	if err != nil {
		return "bilinmiyor"
	}
	a = a.WithZone("").Unmap()
	for _, p := range prefixes {
		if p.Contains(a) {
			return "yerel-bağlantı"
		}
	}
	if a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLoopback() || netip.MustParsePrefix("100.64.0.0/10").Contains(a) {
		return "özel"
	}
	if a.IsGlobalUnicast() {
		return "genel"
	}
	return "diğer"
}

func reportNICs(selected int, nics []diagnosticNIC, autoIndex func(string) int, log func(string, string)) {
	level := diagnosticLevel(nics)
	log(level, fmt.Sprintf("Ağ tanılama: sing-tun varsayılan arayüz indeksi=%d; yerel DNS genel hedef çıkış indeksi=%d; yerel hedef çıkışı sunucuya göre belirlenir.", selected, selected))
	for _, n := range nics {
		if n.Flags&net.FlagUp == 0 {
			continue
		}
		log(level, fmt.Sprintf("Ağ tanılama: arayüz indeksi=%d adı=%q IfType=%d seçili=%t DNS sayısı=%d", n.Index, n.Name, n.ifType, n.Index == selected, len(n.DNSServers)))
		for j, f := range []nicFamily{n.v4, n.v6} {
			log(level, fmt.Sprintf("Ağ tanılama: arayüz indeksi=%d IPv%d tablo okunabildi=%t varsayılan rota=%t rota metriği=%d arayüz okunabildi=%t arayüz metriği=%d iletme=%t zayıf-host-gönder=%t zayıf-host-al=%t", n.Index, 4+2*j, f.routesKnown, f.defaultRoute, f.routeMetric, f.known, f.metric, f.forwarding, f.weakSend, f.weakReceive))
		}
		for j, server := range n.DNSServers {
			// The local transport collects only gateway-bearing, non-tunnel
			// adapters, then uses the shared destination-based auto dialer.
			eligible := len(n.Gateways) != 0 && n.ifType != 131 && n.Name != TunInterfaceName
			if a, err := netip.ParseAddr(server); err == nil && a.Is6() && a.As16()[0] == 0xfe && a.As16()[1] == 0xc0 {
				eligible = false
			}
			log(level, fmt.Sprintf("Ağ tanılama: DNS sahibi indeksi=%d DNS sırası=%d kapsam=%s yerel DNS adayı=%t otomatik çıkış indeksi=%d", n.Index, j+1, dnsScope(server, n.Addresses), eligible, autoIndex(server)))
		}
	}
}

// Diagnostics never print addresses, DNS answers, SSIDs or raw network errors.
// They do not change routes, filters or the interface used by production dials.
func diagnoseNICs(ctx context.Context, selected int, ifaces []adapter.NetworkInterface, autoIndex func(string) int, probe func(context.Context, adapter.NetworkInterface, string) string, warn func(string)) {
	warn(fmt.Sprintf("Ağ tanılama: sing-tun varsayılan arayüz indeksi=%d; direct, wg-direct ve yerel DNS otomatik bağlama kullanıyor.", selected))
	for _, nic := range ifaces {
		if nic.Flags&net.FlagUp == 0 || len(nic.Gateways) == 0 || nic.Name == TunInterfaceName {
			continue
		}
		warn(fmt.Sprintf("Ağ tanılama: arayüz indeksi=%d adı=%q seçili=%t DNS sayısı=%d ağ geçidi sayısı=%d", nic.Index, nic.Name, nic.Index == selected, len(nic.DNSServers), len(nic.Gateways)))
		if ctx.Err() != nil {
			return
		}
		warn(fmt.Sprintf("Ağ tanılama: arayüz indeksi=%d doğrudan TCP=%s", nic.Index, probe(ctx, nic, "")))
		for n, server := range nic.DNSServers {
			if n >= 8 || ctx.Err() != nil {
				break
			}
			warn(fmt.Sprintf("Ağ tanılama: arayüz indeksi=%d DNS sırası=%d bağlı sorgu=%s", nic.Index, n+1, probe(ctx, nic, server)))
			idx := autoIndex(server)
			warn(fmt.Sprintf("Ağ tanılama: DNS sahibi indeksi=%d DNS sırası=%d otomatik çıkış indeksi=%d", nic.Index, n+1, idx))
			if idx != nic.Index {
				for _, egress := range ifaces {
					if egress.Index == idx && ctx.Err() == nil {
						warn(fmt.Sprintf("Ağ tanılama: DNS sahibi indeksi=%d DNS sırası=%d otomatik çıkış indeksi=%d sorgu=%s", nic.Index, n+1, idx, probe(ctx, egress, server)))
						break
					}
				}
			}
		}
	}
}

func probeNIC(ctx context.Context, nic adapter.NetworkInterface, server string) string {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	d := net.Dialer{Control: control.BindToInterface(nil, nic.Name, nic.Index)}
	var err error
	if server == "" {
		var c net.Conn
		c, err = d.DialContext(ctx, "tcp4", "1.1.1.1:443")
		if c != nil {
			c.Close()
		}
	} else {
		if _, e := netip.ParseAddr(server); e != nil {
			return "geçersiz sunucu"
		}
		r := net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, net.JoinHostPort(server, "53"))
		}}
		_, err = r.LookupHost(ctx, "example.com.")
	}
	if err == nil {
		return "başarılı"
	}
	if e, ok := err.(net.Error); ok && e.Timeout() {
		return "zaman aşımı"
	}
	return "başarısız"
}

func (i *instance) startNICDiagnostics() {
	nm := i.box.Network()
	log := func(level, msg string) {
		if i.pump != nil {
			i.pump.Log(level, msg)
		} else {
			fmt.Fprintln(os.Stderr, string(formatLine(level, msg)))
		}
	}
	autoIndex := func(selected int) func(string) int {
		return func(server string) int {
			if addr, err := netip.ParseAddr(server); err == nil {
				if nic, err := nm.InterfaceFinder().ByAddr(addr); err == nil {
					return nic.Index
				}
			}
			return selected
		}
	}
	// Serialize snapshots with monitor callbacks. No network operations are
	// performed on the monitor callback thread.
	var access sync.Mutex
	stopped := false
	snapshot := func(selected int) []diagnosticNIC {
		nics, err := readDiagnosticNICs()
		if err != nil {
			log("INFO", "Ağ tanılama: Windows bağdaştırıcı tablosu okunamadı.")
		}
		reportNICs(selected, nics, autoIndex(selected), log)
		return nics
	}
	ctx, cancel := context.WithCancel(context.Background())
	mon := nm.InterfaceMonitor()
	access.Lock()
	if mon != nil {
		element := mon.RegisterCallback(func(nic *control.Interface, _ int) {
			access.Lock()
			defer access.Unlock()
			if stopped || ctx.Err() != nil {
				return
			}
			selected := 0
			if nic != nil {
				selected = nic.Index
			}
			snapshot(selected)
		})
		i.diagCancel = func() {
			cancel()
			mon.UnregisterCallback(element)
			// Unregister does not join callbacks already copied by emit.
			access.Lock()
			stopped = true
			access.Unlock()
		}
	} else {
		i.diagCancel = cancel
	}
	selected := 0
	if mon != nil {
		if nic := mon.DefaultInterface(); nic != nil {
			selected = nic.Index
		}
	}
	nics := snapshot(selected)
	access.Unlock()
	var ifaces []adapter.NetworkInterface
	for _, n := range nics {
		ifaces = append(ifaces, n.NetworkInterface)
	}
	i.diagDone = make(chan struct{})
	go func() {
		defer close(i.diagDone)
		probeCtx, probeCancel := context.WithTimeout(ctx, 12*time.Second)
		defer probeCancel()
		diagnoseNICs(probeCtx, selected, ifaces, autoIndex(selected), probeNIC, func(msg string) { log(diagnosticLevel(nics), msg) })
	}()
}
