package engine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"aurasplit/internal/profile"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing/common/control"
)

func fakeEgressNIC(idx int, name string, metric uint32) diagnosticNIC {
	return diagnosticNIC{
		NetworkInterface: adapter.NetworkInterface{Interface: control.Interface{Index: idx, Name: name, Flags: net.FlagUp, Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24")}}},
		ifType:           6, v4: nicFamily{known: true, routesKnown: true, defaultRoute: true, metric: metric},
	}
}

type fakeEgressRunner struct {
	runner
	nics []diagnosticNIC
}

func (f *fakeEgressRunner) egressSnapshot() (int, []diagnosticNIC, error) { return 1, f.nics, nil }
func (f *fakeEgressRunner) egressChanges() <-chan struct{}                { return nil }

func TestRunEgressFailoverAndRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		events := installFakes(t, script{}, nil)
		oldEgress, oldPrepare, oldProbe, oldHostCheck := prepareEgressBox, prepareBox, checkEgress, hostCheckInterval
		defer func() {
			prepareEgressBox, prepareBox, checkEgress, hostCheckInterval = oldEgress, oldPrepare, oldProbe, oldHostCheck
		}()
		hostCheckInterval = time.Hour
		var recovered atomic.Bool
		checkEgress = func(_ context.Context, n diagnosticNIC, _ func(string, string)) EgressSample {
			return EgressSample{TCP: n.Index == 2 || recovered.Load(), DNS: true}
		}
		nics := []diagnosticNIC{fakeEgressNIC(1, "Ethernet", 25), fakeEgressNIC(2, "Wi-Fi", 55)}
		prepareBox = func(p *profile.Profile, m Mode, l string, pump *logPump) (runner, error) {
			r, err := oldPrepare(p, m, l, pump)
			return &fakeEgressRunner{r, nics}, err
		}
		var prepared []egressPin
		prepareEgressBox = func(p *profile.Profile, m Mode, l string, pump *logPump, pin egressPin) (runner, error) {
			prepared = append(prepared, pin)
			return prepareBox(p, m, l, pump)
		}
		var states stateLog
		starts := 0
		var failoverAt time.Time
		started := time.Now()
		opts := RunOptions{LogWriter: &safeBuffer{}, OnState: func(s State, d string) {
			states.on("", nil)(s, d)
			if s != StateTunnelStarted {
				return
			}
			starts++
			if starts == 2 {
				failoverAt = time.Now()
				if time.Since(started) > 2*time.Minute {
					t.Error("failover exceeded two minutes")
				}
				recovered.Store(true)
			}
			if starts == 3 {
				if time.Since(failoverAt) < minRebuildInterval {
					t.Error("recovery bypassed normal gate")
				}
				cancel()
			}
		}, OnTunnelUp: func() (io.Closer, error) {
			events.add("permit open")
			return closerFunc(func() error { events.add("close permit"); return nil }), nil
		}}
		if err := Run(ctx, testProfile(t, profile.ProviderWARP), opts); err != nil {
			t.Fatal(err)
		}
		if len(prepared) != 2 || prepared[0].index != 2 || prepared[1].index != 0 {
			t.Fatalf("preparations %+v", prepared)
		}
		got := joined(events.get())
		want := "prepare tunnel#2|close permit|close tunnel#1|start tunnel#2|permit open"
		if !strings.Contains(got, want) {
			t.Fatalf("prepare/permit/close/start order changed: %s", got)
		}
	})
}

func TestEgressRebuildRateLimit(t *testing.T) {
	now := time.Unix(1000, 0)
	if egressRebuildWait(now, time.Time{}, time.Time{}, now, true) != 0 {
		t.Fatal("first failover cannot bypass")
	}
	if egressRebuildWait(now, now, time.Time{}, now.Add(time.Second), true) != 29*time.Second {
		t.Fatal("failover attempts are not bounded")
	}
	if egressRebuildWait(now, now, now, now.Add(30*time.Second), true) != 90*time.Second {
		t.Fatal("second bypass allowed in same window")
	}
	if egressRebuildWait(now, now, time.Time{}, now.Add(30*time.Second), false) != 90*time.Second {
		t.Fatal("recovery bypassed gate")
	}
}

func TestBlockModeEgressRecoveryWithoutWorkingPeer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		events := installFakes(t, script{}, nil)
		oldEgress, oldPrepare, oldProbe := prepareEgressBox, prepareBox, checkEgress
		defer func() { prepareEgressBox, prepareBox, checkEgress = oldEgress, oldPrepare, oldProbe }()
		nics := []diagnosticNIC{fakeEgressNIC(1, "Ethernet", 25), fakeEgressNIC(2, "Wi-Fi", 55)}
		prepareBox = func(p *profile.Profile, mode Mode, level string, pump *logPump) (runner, error) {
			if mode == ModeTunnel {
				return nil, ErrEndpointUnresolved
			}
			r, err := oldPrepare(p, mode, level, pump)
			return &fakeEgressRunner{r, nics}, err
		}
		checkEgress = func(_ context.Context, n diagnosticNIC, _ func(string, string)) EgressSample {
			return EgressSample{TCP: n.Index == 2, DNS: true}
		}
		prepareEgressBox = func(p *profile.Profile, mode Mode, level string, pump *logPump, pin egressPin) (runner, error) {
			if mode == ModeBlock && pin.index != 2 && pin.index != 0 {
				t.Error("wrong block pin")
			}
			return prepareBox(p, mode, level, pump)
		}
		var status EgressStatus
		err := Run(ctx, testProfile(t, profile.ProviderWARP), RunOptions{
			LogWriter: &safeBuffer{}, RetryDelay: 10 * time.Second,
			OnTunnelUp: func() (io.Closer, error) {
				t.Error("block mode opened a permit")
				return nil, errors.New("unexpected permit")
			},
			OnEgress: func(s EgressStatus) {
				status = s
				if s.Failover {
					cancel()
				}
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if status.Alias != "Wi-Fi" || !status.Failover {
			t.Fatalf("block egress status: %+v", status)
		}
		if got := joined(events.get()); !strings.Contains(got, "prepare block#2|close block#1|start block#2") || strings.Contains(got, "start tunnel") {
			t.Fatalf("block failover order: %s", got)
		}
	})
}

func TestEgressFailuresRecoveryAndNoFlapping(t *testing.T) {
	nics := []diagnosticNIC{fakeEgressNIC(1, "Ethernet", 25), fakeEgressNIC(2, "Wi-Fi", 55)}
	var h egressHealth
	ok := map[int]bool{2: true}
	probe := func(_ context.Context, n diagnosticNIC) EgressSample {
		return EgressSample{TCP: ok[n.Index], DNS: true}
	}
	check := func(pin egressPin) (egressPin, bool, EgressStatus) {
		return h.check(context.Background(), pin, 1, nics, probe)
	}
	for range 2 {
		if _, change, _ := check(egressPin{}); change {
			t.Fatal("early failover")
		}
	}
	// A single TCP success resets the TCP-failed streak.
	ok[1] = true
	check(egressPin{})
	ok[1] = false
	for range 2 {
		if _, change, _ := check(egressPin{}); change {
			t.Fatal("failure counter did not reset")
		}
	}
	pin, change, status := check(egressPin{})
	if !change || pin.index != 2 || status.NoHealthy {
		t.Fatalf("selection: %+v %v %+v", pin, change, status)
	}
	for range 10 {
		if _, change, _ := check(pin); change {
			t.Fatal("DNS-answering dead primary stole traffic from working backup")
		}
	}
	for range 4 {
		ok[1] = true
		for range 2 {
			if _, change, _ := check(pin); change {
				t.Fatal("recovered too early")
			}
		}
		ok[1] = false
		check(pin)
	}
	ok[1] = true
	for range 2 {
		check(pin)
	}
	back, change, _ := check(pin)
	if !change || back.index != 0 {
		t.Fatal("did not restore auto selection after hysteresis")
	}
}

func TestProbeEgressTCPRequired(t *testing.T) {
	for _, tc := range []struct {
		name, reachable string
		dns             bool
	}{
		{"DNS only", "", true},
		{"all failed", "", false},
		{"Cloudflare TCP only", "1.1.1.1:443", false},
		{"Google TCP and DNS", "8.8.8.8:443", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := fakeEgressNIC(1, "Ethernet", 25)
			n.DNSServers = []string{"192.0.2.1"}
			var logs []string
			sample := probeEgressWith(context.Background(), n, func(level, message string) {
				logs = append(logs, level+" "+message)
			}, func(_ context.Context, nic diagnosticNIC, endpoint string) bool {
				if nic.Index != n.Index || nic.Name != n.Name {
					t.Error("TCP probe used wrong interface")
				}
				if endpoint != "1.1.1.1:443" && endpoint != "8.8.8.8:443" {
					t.Errorf("unexpected TCP endpoint %q", endpoint)
				}
				return endpoint == tc.reachable
			}, func(_ context.Context, _ diagnosticNIC, server string) bool {
				if server != "192.0.2.1" {
					t.Errorf("unexpected DNS server %q", server)
				}
				return tc.dns
			})
			want := EgressSample{TCP: tc.reachable != "", DNS: tc.dns}
			if sample != want {
				t.Fatalf("sample %+v, want %+v", sample, want)
			}
			if sample.TCP && !sample.DNS && !strings.Contains(strings.Join(logs, "\n"), "WARN") {
				t.Fatal("missing secondary DNS degradation warning")
			}
		})
	}
}

func TestEgressDNSOnlyBackupIsNotSelected(t *testing.T) {
	nics := []diagnosticNIC{fakeEgressNIC(1, "Primary", 25), fakeEgressNIC(2, "DNS only", 55), fakeEgressNIC(3, "Working", 90)}
	for _, working := range []bool{false, true} {
		var h egressHealth
		for sample := 1; sample <= 3; sample++ {
			pin, changed, status := h.check(context.Background(), egressPin{}, 1, nics,
				func(_ context.Context, n diagnosticNIC) EgressSample {
					return EgressSample{TCP: working && n.Index == 3, DNS: true}
				})
			if status.Health == nil || status.Health.TCP || !status.Health.DNS {
				t.Fatalf("DNS-only primary health not reported: %+v", status)
			}
			if sample < 3 {
				if changed {
					t.Fatal("failover skipped failure hysteresis")
				}
			} else if working {
				if !changed || pin.index != 3 {
					t.Fatalf("must skip DNS-only backup: %+v %v", pin, changed)
				}
			} else if changed || !status.NoHealthy {
				t.Fatalf("DNS-only NICs counted as healthy: %+v %v", status, changed)
			}
		}
	}
}

func TestEgressRecoveryRequiresThreeConsecutiveTCPSamples(t *testing.T) {
	nics := []diagnosticNIC{fakeEgressNIC(1, "Primary", 25), fakeEgressNIC(2, "Backup", 55)}
	var h egressHealth
	pin := egressPin{2, "Backup"}
	// DNS always answers, including the TCP failure interrupting recovery.
	for i, tcp := range []bool{false, false, false, true, true, false, true, true, true} {
		next, changed, _ := h.check(context.Background(), pin, 1, nics,
			func(_ context.Context, n diagnosticNIC) EgressSample {
				return EgressSample{TCP: n.Index == 2 || tcp, DNS: true}
			})
		if i == 8 {
			if !changed || next.index != 0 {
				t.Fatal("third consecutive TCP success did not restore automatic selection")
			}
		} else if changed || next != pin {
			t.Fatalf("primary stole traffic before TCP recovery at sample %d: %+v", i+1, next)
		}
	}
}

func TestEgressCandidatesAndNoHealthy(t *testing.T) {
	nics := []diagnosticNIC{fakeEgressNIC(1, "Ethernet", 25), fakeEgressNIC(3, "Backup", 90), fakeEgressNIC(2, "Wi-Fi", 55)}
	nics = append(nics, fakeEgressNIC(4, TunInterfaceName, 0), fakeEgressNIC(5, "Down", 0), fakeEgressNIC(6, "NoRoute", 0), fakeEgressNIC(7, "Virtual", 0))
	nics[4].Flags = 0
	nics[5].v4.defaultRoute = false
	nics[6].ifType = ifTypePropVirtual
	if c := egressCandidates(nics); len(c) != 3 || c[1].Index != 2 {
		t.Fatalf("candidates: %+v", c)
	}
	for _, healthy := range []int{2, 3, 0} {
		var h egressHealth
		var pin egressPin
		var changed bool
		var status EgressStatus
		for range 3 {
			pin, changed, status = h.check(context.Background(), egressPin{}, 1, nics, func(_ context.Context, n diagnosticNIC) EgressSample {
				return EgressSample{TCP: n.Index == healthy, DNS: true}
			})
		}
		if healthy == 0 {
			if changed || !status.NoHealthy {
				t.Fatal("no healthy warning missing")
			}
		} else if !changed || pin.index != healthy {
			t.Fatalf("wanted %d, got %+v", healthy, pin)
		}
	}
}

func TestEgressDefaultChangeAndDisappearance(t *testing.T) {
	var h egressHealth
	nics := []diagnosticNIC{fakeEgressNIC(1, "Ethernet", 25), fakeEgressNIC(2, "Wi-Fi", 55)}
	probe := func(_ context.Context, _ diagnosticNIC) EgressSample { return EgressSample{TCP: true, DNS: true} }
	pin := egressPin{2, "Wi-Fi"}
	for range 2 {
		if _, changed, _ := h.check(context.Background(), pin, 2, nics, probe); changed {
			t.Fatal("default change skipped hysteresis")
		}
	}
	if next, changed, _ := h.check(context.Background(), pin, 2, nics, probe); !changed || next.index != 0 {
		t.Fatal("new automatic default not restored")
	}
	// A disappeared/down selected NIC need not wait for network timeouts.
	if next, changed, _ := h.check(context.Background(), pin, 1, nics[:1], probe); !changed || next.index != 1 {
		t.Fatal("disappeared selection retained")
	}
}

func TestPinnedConfigPreservesIsolation(t *testing.T) {
	p := testProfile(t, profile.ProviderWARP)
	for _, mode := range []Mode{ModeTunnel, ModeBlock} {
		for _, v6 := range []bool{false, true} {
			base := netEnv{hostIPv6: v6}
			raw, err := buildConfig(p, logOptions{}, mode, base)
			if err != nil {
				t.Fatal(err)
			}
			var automatic, pinned config
			if err := json.Unmarshal(raw, &automatic); err != nil {
				t.Fatal(err)
			}
			base.egress = egressPin{2, "Wi-Fi"}
			raw, err = buildConfig(p, logOptions{}, mode, base)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseOptions(include.Context(context.Background()), raw); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(raw, &pinned); err != nil {
				t.Fatal(err)
			}
			if pinned.Route.AutoDetectInterface || pinned.Route.DefaultInterface != "Wi-Fi" {
				t.Fatal("route not pinned")
			}
			for i := range pinned.Outbounds {
				if pinned.Outbounds[i].BindInterface != "Wi-Fi" {
					t.Fatal("outbound not pinned")
				}
				pinned.Outbounds[i].BindInterface = ""
			}
			for i := range pinned.DNS.Servers {
				if pinned.DNS.Servers[i].Tag == TagDNSLocal {
					if pinned.DNS.Servers[i].BindInterface != "Wi-Fi" {
						t.Fatal("local DNS not pinned")
					}
					pinned.DNS.Servers[i].BindInterface = ""
				}
			}
			pinned.Route.DefaultInterface, pinned.Route.AutoDetectInterface = "", true
			if !reflect.DeepEqual(automatic, pinned) {
				t.Fatalf("pinning changed isolation/config for mode=%v IPv6=%v", mode, v6)
			}
		}
	}
}

func TestPinnedIPv6Decision(t *testing.T) {
	ifaces := map[uint32]ifaceRow{1: {up: true, v4OK: true, v4Connected: true, v4Metric: 25}, 2: {up: true, v4OK: true, v4Connected: true, v4Metric: 55}}
	v4 := []routeRow{{ifIndex: 1, prefix: defaultV4}, {ifIndex: 2, prefix: defaultV4}}
	v6 := []routeRow{{ifIndex: 2, prefix: defaultV6}}
	addrs := []addrRow{{ifIndex: 2, addr: netip.MustParseAddr("2001:db8::2"), preferred: true}}
	if decideHostIPv6On(0, ifaces, v4, addrs, v6) || decideHostIPv6On(1, ifaces, v4, addrs, v6) || !decideHostIPv6On(2, ifaces, v4, addrs, v6) {
		t.Fatal("IPv6 did not follow selected index")
	}
}
