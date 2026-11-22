package engine

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Connectivity is the result of the last tunnel probe.
type Connectivity string

const (
	// ConnUnknown: no probe has completed since the tunnel started.
	ConnUnknown Connectivity = ""
	// ConnVerified: the last probe fetched the trace page through the
	// WireGuard endpoint (and, for WARP, it reported warp=on or plus).
	ConnVerified Connectivity = "VPN_CONNECTIVITY_VERIFIED"
	// ConnDegraded: 1 or 2 consecutive probes failed, or WARP reported
	// warp=off.
	ConnDegraded Connectivity = "VPN_DEGRADED"
	// ConnDisconnected: ProbeDisconnectedAfter or more consecutive probes
	// failed.
	ConnDisconnected Connectivity = "VPN_DISCONNECTED"
)

// Probe parameters.
const (
	ProbeURL               = "https://www.cloudflare.com/cdn-cgi/trace"
	ProbeTimeout           = 10 * time.Second
	ProbeBodyLimit         = 4 << 10
	ProbeFirstDelay        = 3 * time.Second
	ProbeInterval          = 5 * time.Minute
	ProbeRetryMin          = 30 * time.Second
	ProbeRetryMax          = ProbeInterval
	ProbeDisconnectedAfter = 3
)

// ProbeResult is reported through RunOptions.OnConnectivity. It never
// contains an IP address.
type ProbeResult struct {
	State    Connectivity
	Detail   string // short reason for a failure, "" on success
	Time     time.Time
	Failures int // consecutive failures
	// Verified is the time of the last successful probe (zero if none).
	Verified time.Time
}

// wgDialer is implemented by runners that can dial through the WireGuard
// endpoint (the real sing-box instance).
type wgDialer interface {
	dialWG(ctx context.Context, network, addr string) (net.Conn, error)
}

// traceInfo holds the only two fields read from the trace page.
type traceInfo struct {
	warp  string
	hasIP bool
}

// parseTrace reads key=value lines. Only warp= and ip= are looked at, and
// the ip value is only checked for being an address; it is never stored.
func parseTrace(body []byte) traceInfo {
	var t traceInfo
	sc := bufio.NewScanner(bytes.NewReader(body))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		switch k {
		case "warp":
			t.warp = strings.ToLower(v)
		case "ip":
			_, err := netip.ParseAddr(v)
			t.hasIP = err == nil
		}
	}
	return t
}

var (
	errProbeWARPOff  = errors.New("warp=off")
	errProbeResponse = errors.New("unexpected response")
)

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// probeDNSTimeout bounds one in-tunnel DNS query of the probe.
const probeDNSTimeout = 5 * time.Second

// tunnelDial returns the probe's dial function. Host names are resolved
// by the probe itself, with a DNS query sent through dial (the WireGuard
// endpoint) to the in-tunnel DNS server dnsServer (host:port, an IP), and
// the connection is then dialed to the resulting IP through dial as well.
// So neither the name lookup nor the connection ever uses the local
// resolver or the physical interface. (Dialing the endpoint with a host
// name would make sing-box resolve it with its DNS router, whose final
// server is the local resolver.) TLS still verifies the certificate for
// the URL's host name (SNI), because http.Transport takes the server name
// from the request, not from the dialed address.
func tunnelDial(dial dialFunc, dnsServer string) dialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if _, err := netip.ParseAddr(host); err == nil {
			return dial(ctx, network, addr)
		}
		ips, err := resolveViaTunnel(ctx, dial, dnsServer, host)
		if err != nil {
			return nil, err
		}
		var lastErr error
		for _, ip := range ips {
			c, err := dial(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return c, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}

var errProbeDNS = errors.New("dns lookup through the tunnel failed")

// resolveViaTunnel asks dnsServer (over UDP through dial) for the A
// records of host, then AAAA if there are none.
func resolveViaTunnel(ctx context.Context, dial dialFunc, dnsServer, host string) ([]netip.Addr, error) {
	var lastErr error
	for _, qt := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		ips, err := dnsQuery(ctx, dial, dnsServer, host, qt)
		if err == nil && len(ips) > 0 {
			return ips, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no address")
	}
	return nil, fmt.Errorf("%w: %v", errProbeDNS, lastErr)
}

func dnsQuery(ctx context.Context, dial dialFunc, dnsServer, host string, qt dnsmessage.Type) ([]netip.Addr, error) {
	fqdn := strings.TrimSuffix(host, ".") + "."
	name, err := dnsmessage.NewName(fqdn)
	if err != nil {
		return nil, err
	}
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, err
	}
	id := uint16(idb[0])<<8 | uint16(idb[1])
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: name, Type: qt, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	msg, err := b.Finish()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, probeDNSTimeout)
	defer cancel()
	conn, err := dial(ctx, "udp", dnsServer)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	if _, err := conn.Write(msg); err != nil {
		return nil, err
	}
	buf := make([]byte, 1500)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		out, ours, err := parseDNSResponse(buf[:n], id, fqdn, qt)
		if !ours {
			continue // not our answer
		}
		return out, err
	}
}

// maxCNAMEChain bounds how many CNAME records are followed from the
// queried name.
const maxCNAMEChain = 8

type dnsAnswer struct {
	owner string // lower case, with trailing dot
	typ   dnsmessage.Type
	class dnsmessage.Class
	cname string
	addr  netip.Addr
}

// parseDNSResponse parses one UDP datagram. ours is false when it is not
// the answer to our query (wrong ID, not a standard response, or not
// exactly one IN question for fqdn/qt); the caller then keeps reading.
// For our answer it requires RCODE 0 and no truncation, and returns only
// IN A/AAAA records (matching qt) whose owner is fqdn or a name reached
// from it through a chain of IN CNAME records (at most maxCNAMEChain).
func parseDNSResponse(msg []byte, id uint16, fqdn string, qt dnsmessage.Type) (addrs []netip.Addr, ours bool, err error) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil || h.ID != id || !h.Response || h.OpCode != 0 {
		return nil, false, nil
	}
	qs, err := p.AllQuestions()
	if err != nil || len(qs) != 1 {
		return nil, false, nil
	}
	q := qs[0]
	qname := strings.ToLower(q.Name.String())
	if q.Type != qt || q.Class != dnsmessage.ClassINET || qname != strings.ToLower(fqdn) {
		return nil, false, nil
	}
	if h.RCode != dnsmessage.RCodeSuccess {
		return nil, true, fmt.Errorf("rcode %d", h.RCode)
	}
	if h.Truncated {
		return nil, true, errors.New("truncated answer")
	}
	var ans []dnsAnswer
	for {
		ah, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return nil, true, err
		}
		a := dnsAnswer{owner: strings.ToLower(ah.Name.String()), typ: ah.Type, class: ah.Class}
		switch ah.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return nil, true, err
			}
			a.addr = netip.AddrFrom4(r.A)
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return nil, true, err
			}
			a.addr = netip.AddrFrom16(r.AAAA)
		case dnsmessage.TypeCNAME:
			r, err := p.CNAMEResource()
			if err != nil {
				return nil, true, err
			}
			a.cname = strings.ToLower(r.CNAME.String())
		default:
			if err := p.SkipAnswer(); err != nil {
				return nil, true, err
			}
			continue
		}
		ans = append(ans, a)
	}
	// Names validly reached from the question.
	chain := map[string]bool{qname: true}
	cur := qname
	for hop := 0; hop < maxCNAMEChain; hop++ {
		next := ""
		for _, a := range ans {
			if a.typ == dnsmessage.TypeCNAME && a.class == dnsmessage.ClassINET && a.owner == cur {
				next = a.cname
				break
			}
		}
		if next == "" || chain[next] {
			break
		}
		chain[next] = true
		cur = next
	}
	for _, a := range ans {
		if a.class != dnsmessage.ClassINET || !chain[a.owner] {
			continue
		}
		if (a.typ == dnsmessage.TypeA && qt == dnsmessage.TypeA) || (a.typ == dnsmessage.TypeAAAA && qt == dnsmessage.TypeAAAA) {
			addrs = append(addrs, a.addr)
		}
	}
	return addrs, true, nil
}

// newProbeClient returns an HTTP client whose every connection is made by
// dial (through the tunnel). tlsConf nil uses the system roots.
func newProbeClient(dial func(ctx context.Context, network, addr string) (net.Conn, error), tlsConf *tls.Config) *http.Client {
	return &http.Client{
		Timeout: ProbeTimeout,
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         dial,
			TLSClientConfig:     tlsConf,
			TLSHandshakeTimeout: ProbeTimeout,
			DisableKeepAlives:   true,
			MaxIdleConns:        1,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// probeOnce fetches url once. requireWARP demands warp=on or warp=plus.
func probeOnce(ctx context.Context, c *http.Client, url string, requireWARP bool) error {
	ctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, ProbeBodyLimit+1))
	if err != nil {
		return err
	}
	if len(body) > ProbeBodyLimit {
		return errProbeResponse
	}
	t := parseTrace(body)
	if !t.hasIP {
		return errProbeResponse
	}
	if requireWARP && t.warp != "on" && t.warp != "plus" {
		return errProbeWARPOff
	}
	return nil
}

// probeReason turns an error into a short reason without addresses.
func probeReason(err error) string {
	var ne net.Error
	switch {
	case err == nil:
		return ""
	case errors.Is(err, errProbeWARPOff):
		return "warp=off"
	case errors.Is(err, errProbeResponse):
		return "unexpected trace response"
	case errors.Is(err, errProbeDNS):
		return "dns lookup through the tunnel failed"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case strings.HasPrefix(err.Error(), "http status "):
		return err.Error()
	case strings.Contains(err.Error(), "tls") || strings.Contains(err.Error(), "x509"):
		return "tls error"
	}
	return "connection failed"
}

// nextResult folds one probe outcome into the running result.
func nextResult(prev ProbeResult, err error, now time.Time) ProbeResult {
	r := prev
	r.Time = now
	if err == nil {
		r.State, r.Detail, r.Failures, r.Verified = ConnVerified, "", 0, now
		return r
	}
	r.Failures++
	r.Detail = probeReason(err)
	if r.Failures >= ProbeDisconnectedAfter {
		r.State = ConnDisconnected
	} else {
		r.State = ConnDegraded
	}
	return r
}

// probeSchedule holds the delays; tests shorten them.
type probeSchedule struct {
	first, interval, retryMin, retryMax time.Duration
}

var defaultProbeSchedule = probeSchedule{ProbeFirstDelay, ProbeInterval, ProbeRetryMin, ProbeRetryMax}

// runProber probes until ctx is cancelled: first after s.first, then every
// s.interval while it succeeds; after a failure with a doubling delay from
// s.retryMin up to s.retryMax.
func runProber(ctx context.Context, c *http.Client, url string, requireWARP bool, s probeSchedule, report func(ProbeResult)) {
	var cur ProbeResult
	delay := s.first
	retry := s.retryMin
	for {
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		err := probeOnce(ctx, c, url, requireWARP)
		if ctx.Err() != nil {
			return
		}
		cur = nextResult(cur, err, time.Now().UTC())
		report(cur)
		if err == nil {
			delay, retry = s.interval, s.retryMin
			continue
		}
		delay = retry
		if retry *= 2; retry > s.retryMax {
			retry = s.retryMax
		}
	}
}
