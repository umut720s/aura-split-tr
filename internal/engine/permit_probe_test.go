package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"aurasplit/internal/profile"
)

// --- WFP permit ordering (fake runners, no TUN, no WFP) ---

type ppEvents struct {
	mu sync.Mutex
	ev []string
}

func (e *ppEvents) add(s string) { e.mu.Lock(); e.ev = append(e.ev, s); e.mu.Unlock() }
func (e *ppEvents) String() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return strings.Join(e.ev, "|")
}

type ppRunner struct {
	name     string
	startErr error
	ev       *ppEvents
}

func (r *ppRunner) Start() error {
	if r.startErr != nil {
		r.ev.add("start " + r.name + ": fail")
		return r.startErr
	}
	r.ev.add("start " + r.name)
	return nil
}

func (r *ppRunner) Close() error { r.ev.add("close " + r.name); return nil }

type ppCloser struct {
	name string
	ev   *ppEvents
}

func (c *ppCloser) Close() error { c.ev.add("close " + c.name); return nil }

func withFakeBoxes(t *testing.T, ev *ppEvents, fail map[string]bool) {
	t.Helper()
	counts := map[Mode]int{}
	oldPrepare, oldLookup := prepareBox, lookupHost
	t.Cleanup(func() { prepareBox, lookupHost = oldPrepare, oldLookup })
	prepareBox = func(_ *profile.Profile, mode Mode, _ string, _ *logPump) (runner, error) {
		counts[mode]++
		kind := "tunnel"
		if mode == ModeBlock {
			kind = "block"
		}
		name := fmt.Sprintf("%s#%d", kind, counts[mode])
		r := &ppRunner{name: name, ev: ev}
		if fail[name] {
			r.startErr = errors.New("start failed")
		}
		return r, nil
	}
	lookupHost = func(context.Context, string) ([]string, error) { return []string{"192.0.2.1"}, nil }
}

// The permit is opened only after the tunnel started, before the state is
// reported, and closed before the tunnel instance is closed.
func TestRunPermitAfterStartClosedBeforeBox(t *testing.T) {
	if !tagsOK {
		t.Skip("built without " + BuildTags)
	}
	ev := &ppEvents{}
	withFakeBoxes(t, ev, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := Run(ctx, testProfile(t, profile.ProviderWARP), RunOptions{
		LogWriter: io.Discard,
		OnTunnelUp: func() (io.Closer, error) {
			ev.add("permit open")
			return &ppCloser{name: "permit", ev: ev}, nil
		},
		OnState: func(s State, _ string) {
			ev.add("state " + string(s))
			if s == StateTunnelStarted {
				cancel()
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "start tunnel#1|permit open|state tunnel-started|close permit|close tunnel#1|state stopped"
	if got := ev.String(); got != want {
		t.Fatalf("events\n got %s\nwant %s", got, want)
	}
}

// A permit failure counts as a failed tunnel start: the tunnel is closed,
// block mode runs (no permit), and the next tunnel gets a permit.
func TestRunPermitFailureFallsBackToBlock(t *testing.T) {
	if !tagsOK {
		t.Skip("built without " + BuildTags)
	}
	ev := &ppEvents{}
	withFakeBoxes(t, ev, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n := 0
	err := Run(ctx, testProfile(t, profile.ProviderWARP), RunOptions{
		LogWriter:  io.Discard,
		RetryDelay: time.Millisecond,
		OnTunnelUp: func() (io.Closer, error) {
			n++
			if n == 1 {
				ev.add("permit fail")
				return nil, errors.New("no WFP session")
			}
			ev.add("permit open")
			return &ppCloser{name: "permit", ev: ev}, nil
		},
		OnState: func(s State, _ string) {
			ev.add("state " + string(s))
			if s == StateTunnelStarted {
				cancel()
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "start tunnel#1|permit fail|close tunnel#1|start block#1|state blocking|close block#1|start tunnel#2|permit open|state tunnel-started|close permit|close tunnel#2|state stopped"
	if got := ev.String(); got != want {
		t.Fatalf("events\n got %s\nwant %s", got, want)
	}
}

// A hanging Close does not hang Run beyond closeTimeout.
func TestRunBoundedClose(t *testing.T) {
	if !tagsOK {
		t.Skip("built without " + BuildTags)
	}
	old := closeTimeout
	closeTimeout = 50 * time.Millisecond
	t.Cleanup(func() { closeTimeout = old })
	release := make(chan struct{})
	defer close(release)
	oldPrepare := prepareBox
	t.Cleanup(func() { prepareBox = oldPrepare })
	prepareBox = func(*profile.Profile, Mode, string, *logPump) (runner, error) {
		return &hangRunner{release: release}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, testProfile(t, profile.ProviderWARP), RunOptions{LogWriter: io.Discard})
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "did not finish") {
			t.Fatalf("Run = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run hung on Close")
	}
}

// A fallback that does not close is terminal: Run never starts the
// prepared tunnel next to it and returns ErrCloseTimeout (the service then
// exits for an SCM restart).
func TestRunCloseTimeoutIsTerminal(t *testing.T) {
	if !tagsOK {
		t.Skip("built without " + BuildTags)
	}
	old := closeTimeout
	closeTimeout = 50 * time.Millisecond
	t.Cleanup(func() { closeTimeout = old })
	release := make(chan struct{})
	defer close(release)
	ev := &ppEvents{}
	counts := map[Mode]int{}
	oldPrepare, oldLookup := prepareBox, lookupHost
	t.Cleanup(func() { prepareBox, lookupHost = oldPrepare, oldLookup })
	lookupHost = func(context.Context, string) ([]string, error) { return []string{"192.0.2.1"}, nil }
	prepareBox = func(_ *profile.Profile, mode Mode, _ string, _ *logPump) (runner, error) {
		counts[mode]++
		if mode == ModeBlock {
			return &hangCloseRunner{name: fmt.Sprintf("block#%d", counts[mode]), ev: ev, release: release}, nil
		}
		r := &ppRunner{name: fmt.Sprintf("tunnel#%d", counts[mode]), ev: ev}
		if counts[mode] == 1 {
			r.startErr = errors.New("down")
		}
		return r, nil
	}
	var states []State
	err := Run(context.Background(), testProfile(t, profile.ProviderWARP), RunOptions{
		LogWriter: io.Discard, RetryDelay: time.Millisecond,
		OnState: func(s State, _ string) { states = append(states, s) },
	})
	if !errors.Is(err, ErrCloseTimeout) {
		t.Fatalf("Run = %v", err)
	}
	got := ev.String()
	if strings.Contains(got, "start tunnel#2") {
		t.Fatalf("second instance started next to a hanging one: %s", got)
	}
	if !strings.Contains(got, "close tunnel#2") {
		t.Fatalf("prepared instance not released: %s", got)
	}
	if fmt.Sprint(states) != fmt.Sprint([]State{StateBlocking, StateError}) {
		t.Fatalf("states %v", states)
	}
}

type hangCloseRunner struct {
	name    string
	ev      *ppEvents
	release chan struct{}
}

func (h *hangCloseRunner) Start() error { h.ev.add("start " + h.name); return nil }
func (h *hangCloseRunner) Close() error {
	h.ev.add("close " + h.name + ": hangs")
	<-h.release
	return nil
}

// The probe resolves the host name through the tunnel DNS server (UDP via
// the tunnel dialer) and dials the resulting IP, never the host name.
func TestProbeResolvesThroughTunnelDNS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ip=192.0.2.9\nwarp=on\n")
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	dnsAddr := fakeDNS(t, "example.com.", [4]byte{127, 0, 0, 1})
	const tunnelDNS = "10.2.0.1:53" // what the profile would configure
	var mu sync.Mutex
	var dials []string
	var d net.Dialer
	base := func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		dials = append(dials, network+" "+addr)
		mu.Unlock()
		if network == "udp" {
			if addr != tunnelDNS {
				return nil, fmt.Errorf("DNS query to unexpected server %s", addr)
			}
			return d.DialContext(ctx, "udp", dnsAddr)
		}
		return d.DialContext(ctx, network, addr)
	}
	tlsConf := srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	client := newProbeClient(tunnelDial(base, tunnelDNS), tlsConf)
	if err := probeOnce(context.Background(), client, "https://example.com:"+port+"/cdn-cgi/trace", true); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{"udp " + tunnelDNS, "tcp 127.0.0.1:" + port}
	if fmt.Sprint(dials) != fmt.Sprint(want) {
		t.Fatalf("dials %v, want %v", dials, want)
	}
}

func TestProbeDNSFailureReason(t *testing.T) {
	dnsAddr := fakeDNS(t, "other.example.", [4]byte{127, 0, 0, 1}) // NXDOMAIN for anything else
	var d net.Dialer
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if network == "udp" {
			return d.DialContext(ctx, "udp", dnsAddr)
		}
		return nil, errors.New("must not dial")
	}
	client := newProbeClient(tunnelDial(dial, "1.1.1.1:53"), &tls.Config{})
	err := probeOnce(context.Background(), client, "https://www.cloudflare.com/cdn-cgi/trace", false)
	if got := probeReason(err); got != "dns lookup through the tunnel failed" {
		t.Fatalf("reason %q (err %v)", got, err)
	}
}

// The probe uses the same in-tunnel DNS server as the configuration.
func TestTunnelDNSServer(t *testing.T) {
	p := testProfile(t, profile.ProviderWireGuard)
	p.WireGuard.DNS = []string{"2001:db8::53", "10.2.0.1"}
	if got := tunnelDNSServer(p); got != "10.2.0.1:53" && !strings.HasPrefix(got, "[2001:db8::53]") {
		t.Fatalf("server %q", got)
	}
	p.WireGuard.DNS = nil
	if got := tunnelDNSServer(p); got != net.JoinHostPort(defaultRemoteDNS, "53") {
		t.Fatalf("default server %q", got)
	}
}

// fakeDNS answers A queries for name with ip and NXDOMAIN otherwise.
func fakeDNS(t *testing.T, name string, ip [4]byte) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			rh := dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: true}
			match := strings.EqualFold(q.Name.String(), name)
			if !match {
				rh.RCode = dnsmessage.RCodeNameError
			}
			b := dnsmessage.NewBuilder(nil, rh)
			_ = b.StartQuestions()
			_ = b.Question(q)
			_ = b.StartAnswers()
			if match && q.Type == dnsmessage.TypeA {
				_ = b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: ip})
			}
			out, err := b.Finish()
			if err == nil {
				_, _ = pc.WriteTo(out, from)
			}
		}
	}()
	return pc.LocalAddr().String()
}

type hangRunner struct{ release chan struct{} }

func (h *hangRunner) Start() error { return nil }
func (h *hangRunner) Close() error { <-h.release; return nil }

// --- probe ---

func TestParseTrace(t *testing.T) {
	ti := parseTrace([]byte("fl=1\nh=www.cloudflare.com\nip=198.51.100.7\nwarp=on\ngateway=off\n"))
	if ti.warp != "on" || !ti.hasIP {
		t.Fatalf("%+v", ti)
	}
	if ti := parseTrace([]byte("ip=not-an-ip\nwarp=plus")); ti.hasIP || ti.warp != "plus" {
		t.Fatalf("%+v", ti)
	}
	if ti := parseTrace([]byte("<html>nope</html>")); ti.hasIP || ti.warp != "" {
		t.Fatalf("%+v", ti)
	}
}

func TestNextResultThresholds(t *testing.T) {
	now := time.Unix(1000, 0)
	var r ProbeResult
	r = nextResult(r, errors.New("x"), now)
	if r.State != ConnDegraded || r.Failures != 1 {
		t.Fatalf("%+v", r)
	}
	r = nextResult(r, errors.New("x"), now)
	if r.State != ConnDegraded {
		t.Fatalf("%+v", r)
	}
	r = nextResult(r, errors.New("x"), now)
	if r.State != ConnDisconnected || r.Failures != ProbeDisconnectedAfter {
		t.Fatalf("%+v", r)
	}
	r = nextResult(r, nil, now)
	if r.State != ConnVerified || r.Failures != 0 || r.Verified != now || r.Detail != "" {
		t.Fatalf("%+v", r)
	}
}

func traceServer(t *testing.T, body string, status int) (*httptest.Server, *http.Client) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()
	var d net.Dialer
	// The dial function ignores the requested address, like the tunnel
	// dialer would carry any address through the endpoint.
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return d.DialContext(ctx, network, addr)
	}
	tlsConf := srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	return srv, newProbeClient(dial, tlsConf)
}

func TestProbeOnce(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		status int
		warp   bool
		want   string // "" = ok, else probeReason
	}{
		{"warp on", "ip=192.0.2.9\nwarp=on\n", 200, true, ""},
		{"warp plus", "ip=2001:db8::1\nwarp=plus\n", 200, true, ""},
		{"warp off", "ip=192.0.2.9\nwarp=off\n", 200, true, "warp=off"},
		{"other provider ignores warp", "ip=192.0.2.9\nwarp=off\n", 200, false, ""},
		{"no ip", "warp=on\n", 200, true, "unexpected trace response"},
		{"too large", "ip=192.0.2.9\n" + strings.Repeat("x", ProbeBodyLimit), 200, false, "unexpected trace response"},
		{"status", "ip=192.0.2.9\n", 503, false, "http status 503"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, client := traceServer(t, c.body, c.status)
			err := probeOnce(context.Background(), client, srv.URL+"/cdn-cgi/trace", c.warp)
			if got := probeReason(err); got != c.want {
				t.Fatalf("reason %q (err %v), want %q", got, err, c.want)
			}
		})
	}
}

// Failures never put an address into the reported detail.
func TestProbeReasonHasNoAddress(t *testing.T) {
	client := newProbeClient(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 443}, Err: errors.New("refused")}
	}, &tls.Config{})
	err := probeOnce(context.Background(), client, "https://www.cloudflare.com/cdn-cgi/trace", false)
	if r := probeReason(err); strings.Contains(r, "198.51") || r == "" {
		t.Fatalf("reason %q", r)
	}
}

func TestRunProberSchedule(t *testing.T) {
	var mu sync.Mutex
	reqs := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		reqs++
		if reqs <= 3 {
			w.WriteHeader(500)
			return
		}
		_, _ = io.WriteString(w, "ip=192.0.2.1\nwarp=on\n")
	}))
	defer srv.Close()
	client := srv.Client()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := make(chan ProbeResult, 16)
	s := probeSchedule{first: time.Millisecond, interval: time.Hour, retryMin: time.Millisecond, retryMax: 2 * time.Millisecond}
	go runProber(ctx, client, srv.URL, true, s, func(r ProbeResult) { results <- r })
	var states []Connectivity
	for len(states) < 4 {
		select {
		case r := <-results:
			states = append(states, r.State)
		case <-time.After(5 * time.Second):
			t.Fatalf("timeout, states %v", states)
		}
	}
	want := []Connectivity{ConnDegraded, ConnDegraded, ConnDisconnected, ConnVerified}
	if fmt.Sprint(states) != fmt.Sprint(want) {
		t.Fatalf("states %v want %v", states, want)
	}
	// After a success the next probe waits the full interval (1h here).
	select {
	case r := <-results:
		t.Fatalf("unexpected extra probe %+v", r)
	case <-time.After(50 * time.Millisecond):
	}
}

// Secrets are removed from sing-box log lines on the writer goroutine.
func TestLineRedactor(t *testing.T) {
	p := testProfile(t, profile.ProviderWARP)
	red := lineRedactor(p)
	line := []byte("setup wireguard: private_key=" + secretForms(p)[1] + " x " + p.WireGuard.PrivateKey + "\n")
	out := string(red(line))
	for _, s := range secretForms(p) {
		if strings.Contains(out, s) {
			t.Fatalf("secret left in %q", out)
		}
	}
}
