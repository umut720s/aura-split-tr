package engine

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"time"

	"aurasplit/internal/profile"
	"github.com/sagernet/sing/common/control"
)

const egressThreshold = 3

var egressCheckInterval = 30 * time.Second

// Variable seams let Run tests exercise failover without network sockets.
var checkEgress = probeEgress

// One failover may bypass the regular two-minute rebuild gate per two-minute
// window. Egress attempts still remain at least one health interval apart.
func egressRebuildWait(last, lastEgress, bypass, now time.Time, failover bool) time.Duration {
	wait := rebuildWait(last, now, minRebuildInterval)
	if failover && rebuildWait(bypass, now, minRebuildInterval) == 0 {
		wait = rebuildWait(lastEgress, now, egressCheckInterval)
	}
	return wait
}

type egressPin struct {
	index int
	alias string
}

type egressChoice struct {
	pin       egressPin
	automatic int
}

// EgressStatus intentionally contains no interface index or addresses.
type EgressStatus struct {
	Alias     string        `json:"alias,omitempty"`
	Failover  bool          `json:"failover,omitempty"`
	NoHealthy bool          `json:"no_healthy,omitempty"`
	Health    *EgressSample `json:"health,omitempty"`
}

// EgressSample separates Internet reachability from the secondary DNS signal.
// DNS may be served by a router whose Internet uplink is down.
type EgressSample struct {
	TCP bool `json:"tcp"`
	DNS bool `json:"dns"`
}

type egressSource interface {
	egressSnapshot() (int, []diagnosticNIC, error)
	egressChanges() <-chan struct{}
}

func hostIPv6ForEgress(pin egressPin) (bool, error) {
	if pin.index == 0 {
		return hostIPv6()
	}
	return detectHostIPv6On(pin.index)
}

func probeEndpointForEgress(ctx context.Context, p *profile.Profile, pin egressPin) error {
	if pin.index != 0 {
		return nil
	} // prepareEgressBox resolves on the pinned NIC.
	return probeEndpoint(ctx, p)
}

func (i *instance) egressSnapshot() (int, []diagnosticNIC, error) {
	nics, err := readDiagnosticNICs()
	selected := 0
	if mon := i.box.Network().InterfaceMonitor(); mon != nil {
		if nic := mon.DefaultInterface(); nic != nil {
			selected = nic.Index
		}
	}
	return selected, nics, err
}

func (i *instance) egressChanges() <-chan struct{} { return i.egressWake }

func egressCandidates(nics []diagnosticNIC) []diagnosticNIC {
	var out []diagnosticNIC
	for _, n := range nics {
		if n.Flags&net.FlagUp != 0 && n.v4.routesKnown && n.v4.known && n.v4.defaultRoute && n.Name != TunInterfaceName && n.ifType != ifTypePropVirtual && n.ifType != ifTypeSoftwareLoopback && n.ifType != 131 {
			out = append(out, n)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].v4.routeMetric+out[i].v4.metric < out[j].v4.routeMetric+out[j].v4.metric
	})
	return out
}

type egressHealth struct {
	failures, successes map[int]int
	automatic           int
}

// check is serialized by the owner. Only a successful bound TCP probe keeps a
// NIC healthy; three TCP-failed samples permit failover. Recovery also needs
// three consecutive TCP-confirmed samples of the current automatic default, never a stale
// original NIC that auto detection would no longer select.
func (h *egressHealth) check(ctx context.Context, current egressPin, automatic int, nics []diagnosticNIC, probe func(context.Context, diagnosticNIC) EgressSample) (egressPin, bool, EgressStatus) {
	if h.failures == nil {
		h.failures, h.successes = map[int]int{}, map[int]int{}
	}
	if h.automatic != automatic {
		h.successes[automatic], h.failures[automatic] = 0, 0
		h.automatic = automatic
	}
	candidates := egressCandidates(nics)
	selected := current.index
	if selected == 0 {
		selected = automatic
	}
	status := EgressStatus{Alias: current.alias, Failover: current.index != 0}
	seen := map[int]bool{}
	results := map[int]bool{}
	for _, n := range candidates {
		seen[n.Index] = true
		if n.Index == selected {
			status.Alias = n.Name
		}
	}
	for idx := range h.successes {
		if !seen[idx] {
			delete(h.successes, idx)
			delete(h.failures, idx)
		}
	}
	test := func(idx int) bool {
		if ok, done := results[idx]; done {
			return ok
		}
		for _, n := range candidates {
			if n.Index != idx {
				continue
			}
			sample := probe(ctx, n)
			if idx == selected {
				status.Health = &sample
			}
			ok := sample.TCP
			results[idx] = ok
			if ok {
				h.failures[idx] = 0
				h.successes[idx]++
			} else {
				h.successes[idx] = 0
				h.failures[idx]++
			}
			return ok
		}
		return false
	}
	healthy := test(selected)
	if current.index != 0 && automatic != 0 {
		if test(automatic) && h.successes[automatic] >= egressThreshold {
			return egressPin{}, true, status
		}
	}
	if healthy {
		return current, false, status
	}
	if seen[selected] && h.failures[selected] < egressThreshold {
		return current, false, status
	}
	for _, n := range candidates {
		if n.Index != selected && test(n.Index) {
			return egressPin{n.Index, n.Name}, true, status
		}
	}
	status.NoHealthy = true
	return current, false, status
}

// Probe results are booleans only; raw errors and destinations never enter logs.
// Two TCP connects send no payload. DNS uses only the fixed example.com name
// and the candidate's own servers. A cycle has a shared two-second deadline.
func probeEgress(ctx context.Context, n diagnosticNIC, logf func(string, string)) EgressSample {
	return probeEgressWith(ctx, n, logf, func(ctx context.Context, n diagnosticNIC, endpoint string) bool {
		d := net.Dialer{Control: control.BindToInterface(nil, n.Name, n.Index)}
		c, err := d.DialContext(ctx, "tcp4", endpoint)
		if c != nil {
			_ = c.Close()
		}
		return err == nil
	}, func(ctx context.Context, n diagnosticNIC, server string) bool {
		return probeNIC(ctx, n.NetworkInterface, server) == "başarılı"
	})
}

// Inject probes so aggregation can be verified without opening sockets.
func probeEgressWith(ctx context.Context, n diagnosticNIC, logf func(string, string), tcpProbe, dnsProbe func(context.Context, diagnosticNIC, string) bool) EgressSample {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	jobs := 2 + min(len(n.DNSServers), 8)
	type result struct{ dns, ok bool }
	results := make(chan result, jobs)
	for _, endpoint := range []string{"1.1.1.1:443", "8.8.8.8:443"} {
		go func() {
			results <- result{ok: tcpProbe(ctx, n, endpoint)}
		}()
	}
	for _, server := range n.DNSServers[:min(len(n.DNSServers), 8)] {
		go func() { results <- result{dns: true, ok: dnsProbe(ctx, n, server)} }()
	}
	dnsOK, tcpOK := false, false
	for range jobs {
		r := <-results
		if r.dns {
			dnsOK = dnsOK || r.ok
		} else {
			tcpOK = tcpOK || r.ok
		}
	}
	logf("INFO", fmt.Sprintf("Çıkış sağlık denetimi: arayüz indeksi=%d adı=%q DNS=%t TCP=%t", n.Index, n.Name, dnsOK, tcpOK))
	if tcpOK && !dnsOK && len(n.DNSServers) > 0 {
		logf("WARN", "Çıkış İnternet erişimi doğrulandı; arayüz DNS denetimi başarısız")
	}
	return EgressSample{TCP: tcpOK, DNS: dnsOK}
}

// prepareEgressBox preserves the existing fake seam for automatic selection.
// Explicit selection applies before resolving a hostname peer, so recovery does
// not depend on the dead NIC's system resolver.
var prepareEgressBox = func(p *profile.Profile, mode Mode, level string, pump *logPump, pin egressPin) (runner, error) {
	if pin.index == 0 {
		return prepareBox(p, mode, level, pump)
	}
	v6, err := detectHostIPv6On(pin.index)
	if err != nil {
		v6 = false
	}
	env := netEnv{hostIPv6: v6, egress: pin}
	host, _, err := net.SplitHostPort(p.WireGuard.Endpoint)
	if err == nil && mode == ModeTunnel {
		if ip, err := netip.ParseAddr(host); err == nil {
			env.peerAddr = ip.String()
		} else {
			addr, err := resolveEgressPeer(host, pin, v6)
			if err != nil {
				return nil, err
			}
			env.peerAddr = addr.String()
		}
	}
	return prepareBoxEnv(p, mode, level, pump, env)
}

// A shared deadline bounds peer resolution even with several dead DNS servers.
func resolveEgressPeer(host string, pin egressPin, v6 bool) (netip.Addr, error) {
	nics, err := readDiagnosticNICs()
	if err != nil {
		return netip.Addr{}, ErrEndpointUnresolved
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	answers := make(chan netip.Addr, 8)
	for _, n := range egressCandidates(nics) {
		if n.Index != pin.index || n.Name != pin.alias {
			continue
		}
		servers := n.DNSServers[:min(len(n.DNSServers), 8)]
		for _, server := range servers {
			go func() {
				d := net.Dialer{Control: control.BindToInterface(nil, pin.alias, pin.index)}
				r := net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return d.DialContext(ctx, network, net.JoinHostPort(server, "53"))
				}}
				family := "ip4"
				if v6 {
					family = "ip"
				}
				ips, _ := r.LookupNetIP(ctx, family, host)
				var addr netip.Addr
				for _, ip := range ips {
					if ip.Is4() {
						addr = ip
						break
					}
					if !addr.IsValid() {
						addr = ip
					}
				}
				answers <- addr
			}()
		}
		for range servers {
			select {
			case <-ctx.Done():
				return netip.Addr{}, ErrEndpointUnresolved
			case addr := <-answers:
				if addr.IsValid() {
					return addr, nil
				}
			}
		}
		break
	}
	return netip.Addr{}, ErrEndpointUnresolved
}
