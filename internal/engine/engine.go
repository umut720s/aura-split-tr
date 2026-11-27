package engine

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"

	"aurasplit/internal/profile"
)

// State is the tunnel state reported through RunOptions.OnState.
type State string

const (
	// StateStarting: the service process is up and about to start the
	// tunnel. Written by the service itself, not by Run.
	StateStarting State = "starting"
	// StateTunnelStarted: the normal configuration was started without an
	// error, so Discord is routed to the WireGuard endpoint. This means
	// "configured", not "verified": sing-box v1.14.4 does not expose the
	// WireGuard handshake time, so whether the peer actually answers is not
	// known here.
	StateTunnelStarted State = "tunnel-started"
	// StateBlocking: the tunnel could not start; the fail-closed fallback
	// is running, so Discord traffic is rejected while Run retries.
	StateBlocking State = "blocking"
	// StateError: neither the tunnel nor the fallback could start (for
	// example the TUN device failed). Discord uses the direct connection.
	StateError State = "error"
	// StateStopped: Run returned after cancellation.
	StateStopped State = "stopped"
)

const (
	defaultRetryDelay = 10 * time.Second
	maxRetryDelay     = 60 * time.Second
	// probeTimeout bounds the endpoint name lookup done before the
	// fallback is closed for a retry.
	probeTimeout = 5 * time.Second
	// logSentinel is the log "file name" our file manager turns into a pipe
	// to RunOptions.LogWriter. It is never opened on disk.
	logSentinel = "aurasplit-log-writer"
)

// RunOptions configures Run.
type RunOptions struct {
	// LogWriter receives sing-box and engine log lines through a bounded,
	// non-blocking queue (lines are dropped and counted when the writer
	// cannot keep up). nil writes to the console (stderr) directly.
	LogWriter io.Writer
	// Debug selects LogLevelDebug ("info": every connection is logged)
	// instead of LogLevelDefault ("warn").
	Debug bool
	// OnState is called on every state change. detail is already
	// stripped of key material.
	OnState func(state State, detail string)
	// RetryDelay is the initial delay between tunnel start attempts while
	// the fallback is active (default 10s, doubling up to 60s).
	RetryDelay time.Duration
	// OnTunnelUp is called right after the normal tunnel has started and
	// before StateTunnelStarted is reported; the service uses it to open
	// the dynamic WFP permit for Discord on the TUN. If it fails, the
	// tunnel is closed and treated as a failed start (Discord stays
	// blocked). The returned closer (may be nil) is closed before the
	// tunnel instance is closed. Never called for ModeBlock.
	OnTunnelUp func() (io.Closer, error)
	// OnConnectivity receives tunnel probe results (see probe.go). nil
	// disables the probe.
	OnConnectivity func(ProbeResult)
	// ProbeURL overrides ProbeURL (tests).
	ProbeURL string
}

// parseOptions decodes cfg with sing-box's own (strict) option parser.
func parseOptions(ctx context.Context, cfg []byte) (option.Options, error) {
	return json.UnmarshalExtendedContext[option.Options](ctx, cfg)
}

// logRedirect is a sing-box file manager that hands sing-box a pipe into
// our log pump instead of a log file, so the service controls where and how
// the log is written (verified handle, size-bounded rotation) and sing-box
// never waits for the disk. Every other file operation is delegated to the
// default manager.
type logRedirect struct {
	filemanager.Manager
	pump *logPump
}

func (m *logRedirect) OpenFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	if name != logSentinel {
		return m.Manager.OpenFile(name, flag, perm)
	}
	return m.pump.Pipe()
}

func withLogRedirect(ctx context.Context, pump *logPump) context.Context {
	base := service.FromContext[filemanager.Manager](filemanager.WithDefault(context.Background(), "", "", os.Getuid(), os.Getgid()))
	return service.ContextWith[filemanager.Manager](ctx, &logRedirect{Manager: base, pump: pump})
}

// runner is a created (not yet started) sing-box instance.
type runner interface {
	Start() error
	Close() error
}

type instance struct {
	p          *profile.Profile
	box        *box.Box
	cancel     context.CancelFunc
	env        netEnv
	pump       *logPump
	diagCancel context.CancelFunc
	diagDone   chan struct{}
}

// builtHostIPv6 is the host IPv6 capability the instance was built for.
func (i *instance) builtHostIPv6() bool { return i.env.hostIPv6 }

// hostIPv6Builder is implemented by runners that know the host IPv6
// capability they were built for (the real instance).
type hostIPv6Builder interface{ builtHostIPv6() bool }

// Start opens the TUN device and starts every component. On failure the
// instance is closed.
func (i *instance) Start() error {
	if err := i.box.Start(); err != nil {
		startErr := redact(i.p, fmt.Errorf("start sing-box: %w", err))
		if cerr := closeBounded(i); errors.Is(cerr, ErrCloseTimeout) {
			return fmt.Errorf("%w (after: %v)", cerr, startErr)
		}
		return startErr
	}
	i.startNICDiagnostics()
	return nil
}

func (i *instance) Close() error {
	if i.diagCancel != nil {
		i.diagCancel()
		<-i.diagDone
	}
	err := i.box.Close()
	i.cancel()
	return redact(i.p, err)
}

// dialWG dials addr through the WireGuard endpoint only.
func (i *instance) dialWG(ctx context.Context, network, addr string) (net.Conn, error) {
	ep, ok := i.box.Endpoint().Get(TagWG)
	if !ok {
		return nil, errors.New("wireguard endpoint not found")
	}
	return ep.DialContext(ctx, network, M.ParseSocksaddr(addr))
}

// closeTimeout bounds how long one instance may take to close, so service
// shutdown stays ordered and finishes within the SCM stop wait.
var closeTimeout = 10 * time.Second

// ErrCloseTimeout is returned (wrapped) by Run when a sing-box instance
// did not close within closeTimeout. It is terminal for the process: the
// hanging Close keeps running and may still own the TUN interface, routes
// and strict-route filters, so Run never starts another instance after it.
// The service exits and lets the SCM restart it in a fresh process; the
// persistent WFP blocks keep Discord fail-closed in between.
var ErrCloseTimeout = errors.New("sing-box instance did not close in time")

// closeBounded closes r but gives up waiting after closeTimeout. A close
// that hangs keeps running in the background; only the process exit ends
// it (and removes the TUN and sing-tun's dynamic WFP session).
func closeBounded(r runner) error {
	done := make(chan error, 1)
	go func() { done <- r.Close() }()
	select {
	case err := <-done:
		return err
	case <-time.After(closeTimeout):
		return fmt.Errorf("%w: close did not finish within %s", ErrCloseTimeout, closeTimeout)
	}
}

func newBox(ctx context.Context, p *profile.Profile, logOpts logOptions, mode Mode, env netEnv) (*box.Box, error) {
	cfg, err := buildConfig(p, logOpts, mode, env)
	if err != nil {
		return nil, err
	}
	opts, err := parseOptions(ctx, cfg)
	if err != nil {
		return nil, redact(p, fmt.Errorf("parse sing-box config: %w", err))
	}
	if opts.Log != nil {
		// Plain text: neither files nor the Windows console want ANSI codes.
		opts.Log.DisableColor = true
	}
	b, err := box.New(box.Options{Options: opts, Context: ctx})
	if err != nil {
		return nil, redact(p, fmt.Errorf("create sing-box: %w", err))
	}
	return b, nil
}

// Check builds both configurations and instantiates sing-box without
// starting it (no TUN device is opened). A host-name endpoint is resolved
// if possible; if not, the name is kept for this check only, because the
// checked configuration is never started (Run refuses to start a tunnel
// whose endpoint does not resolve).
func Check(p *profile.Profile) error {
	if !tagsOK {
		return ErrMissingBuildTags
	}
	for _, mode := range []Mode{ModeTunnel, ModeBlock} {
		env, _ := resolveNetEnv(p, mode, false)
		ctx, cancel := context.WithCancel(include.Context(context.Background()))
		b, err := newBox(ctx, p, logOptions{Disabled: true}, mode, env)
		if err != nil {
			cancel()
			return err
		}
		err = b.Close()
		cancel()
		if err != nil {
			return redact(p, fmt.Errorf("close sing-box: %w", err))
		}
	}
	return nil
}

// prepareBox creates (but does not start) a sing-box instance. Creating
// opens no device, so it can be done while another instance still owns the
// TUN. For ModeTunnel it resolves a host-name endpoint first (system
// resolver, outside any tunnel); an unresolvable name is a preparation
// error wrapping ErrEndpointUnresolved, so Run keeps (or starts) the
// fail-closed fallback and retries. pump nil logs to stderr. It is a
// variable so the retry logic can be tested without a TUN device.
var prepareBox = func(p *profile.Profile, mode Mode, level string, pump *logPump) (runner, error) {
	env, err := resolveNetEnv(p, mode, true)
	if err != nil {
		return nil, err
	}
	logOpts := logOptions{Level: level, Timestamp: true, Output: logSentinel}
	// sing-box gets its own context so shutdown is ordered by Close rather
	// than by an abrupt cancellation of the caller's context.
	ctx, cancel := context.WithCancel(include.Context(context.Background()))
	if pump == nil {
		logOpts.Output = "stderr"
	} else {
		ctx = withLogRedirect(ctx, pump)
	}
	b, err := newBox(ctx, p, logOpts, mode, env)
	if err != nil {
		cancel()
		return nil, err
	}
	return &instance{p: p, box: b, cancel: cancel, env: env, pump: pump}, nil
}

func startBox(p *profile.Profile, mode Mode, level string, pump *logPump) (runner, error) {
	r, err := prepareBox(p, mode, level, pump)
	if err != nil {
		return nil, err
	}
	if err := r.Start(); err != nil {
		return nil, err
	}
	return r, nil
}

// lookupHost resolves the WireGuard endpoint name before a retry; a
// variable for tests.
var lookupHost = net.DefaultResolver.LookupHost

// probeEndpoint checks that the endpoint host resolves. An unresolvable
// name is the usual reason the tunnel cannot start at boot; checking first
// avoids tearing the fallback down for an attempt that cannot succeed.
func probeEndpoint(ctx context.Context, p *profile.Profile) error {
	host, _, err := net.SplitHostPort(p.WireGuard.Endpoint)
	if err != nil {
		return err
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	_, err = lookupHost(ctx, host)
	return err
}

// Rebuild parameters (variables so tests can shorten them).
var (
	// hostCheckInterval is how often a running tunnel re-checks the host
	// IPv6 capability it was built for.
	hostCheckInterval = 60 * time.Second
	// minRebuildInterval bounds tunnel rebuilds: at most one attempt per
	// interval, whatever triggers it.
	minRebuildInterval = 2 * time.Minute
)

// rebuildWait is how long a rebuild triggered at now has to wait after the
// previous attempt at last (zero: none yet).
func rebuildWait(last, now time.Time, min time.Duration) time.Duration {
	if last.IsZero() {
		return 0
	}
	if d := last.Add(min).Sub(now); d > 0 {
		return d
	}
	return 0
}

// startProbe starts the connectivity probe for a started instance and
// returns false if the instance cannot be probed (it does not dial through
// the WireGuard endpoint, or there is no consumer). A variable for tests.
var startProbe = func(ctx context.Context, inst runner, p *profile.Profile, url string, report func(ProbeResult)) bool {
	d, ok := inst.(wgDialer)
	if !ok {
		return false
	}
	// Name lookup and connection both go through the tunnel (in-tunnel DNS
	// server of the profile), never the local resolver.
	client := newProbeClient(tunnelDial(d.dialWG, tunnelDNSServer(p)), nil)
	runProber(ctx, client, url, p.Provider == profile.ProviderWARP, defaultProbeSchedule, report)
	return true
}

// Run starts the tunnel and blocks until ctx is cancelled, then shuts it
// down and returns nil.
//
// If the tunnel cannot start (for example the WireGuard peer name cannot
// be resolved at boot: ErrEndpointUnresolved), Run starts the fail-closed
// fallback (ModeBlock: same TUN, Discord rejected) and retries the tunnel
// with a growing delay. Each retry first creates the new tunnel instance
// and resolves the endpoint while the fallback still runs; only then is the
// fallback closed and the prepared tunnel started, so the unprotected gap
// is just the time the new instance needs to open the TUN device. The two
// cannot run side by side: both use the same interface name, routes and
// strict-route filters. If the prepared tunnel fails to start, the
// fallback is started again at once.
//
// A running tunnel is rebuilt (new configuration, endpoint resolved again)
// when the connectivity probe reports ConnDisconnected or when the host
// IPv6 capability (checked every hostCheckInterval) no longer matches the
// one the configuration was built for; at most one rebuild attempt per
// minRebuildInterval. The replacement is prepared while the old tunnel
// still runs; if that fails the old tunnel is kept and the rebuild is
// retried later. Otherwise the Discord permit and the old tunnel are
// closed and the replacement is started like a retry from the fallback
// (persistent WFP policy blocks Discord in the gap; a failed start enters
// the fallback).
//
// After every successful tunnel start opts.OnTunnelUp opens the Discord
// permit (service: dynamic WFP filters on the TUN); a failure there is
// handled like a failed start. The permit is closed before the tunnel.
//
// If the fallback cannot start either (typically because the TUN device
// itself failed), nothing can hold Discord back: Run reports StateError and
// returns the error, and the caller (the service supervisor) retries later.
func Run(ctx context.Context, p *profile.Profile, opts RunOptions) error {
	if !tagsOK {
		return ErrMissingBuildTags
	}
	var pump *logPump
	logf := func(level, msg string) { _, _ = os.Stderr.Write(formatLine(level, msg)) }
	if opts.LogWriter != nil {
		pump = newLogPump(opts.LogWriter, logQueueSize)
		pump.redact = lineRedactor(p)
		// Every instance is closed before Run returns, so this only waits
		// for the queued lines.
		defer pump.Close(logDrainTimeout)
		logf = pump.Log
	}
	level := LogLevelDefault
	if opts.Debug {
		level = LogLevelDebug
	}
	report := func(s State, detail string) {
		if opts.OnState != nil {
			opts.OnState(s, detail)
		}
	}
	initialDelay := opts.RetryDelay
	if initialDelay <= 0 {
		initialDelay = defaultRetryDelay
	}
	delay := initialDelay
	// lastRebuild is the time of the last rebuild attempt (rate limit).
	var lastRebuild time.Time

	// up runs OnTunnelUp for a started tunnel; on failure the tunnel is
	// closed and the error is handled like a failed start.
	up := func(inst runner) (io.Closer, error) {
		if opts.OnTunnelUp == nil {
			return nil, nil
		}
		c, err := opts.OnTunnelUp()
		if err != nil {
			err = fmt.Errorf("allow Discord on the tunnel: %w", err)
			if cerr := closeBounded(inst); cerr != nil && errors.Is(cerr, ErrCloseTimeout) {
				return nil, fmt.Errorf("%w (after: %v)", cerr, err)
			}
			return nil, err
		}
		return c, nil
	}
	// terminal reports and returns a close timeout: no further instance is
	// started in this process.
	terminal := func(err error) error {
		logf("ERROR", "sing-box did not close; no new instance is started in this process (Discord stays blocked by the persistent WFP policy): "+err.Error())
		report(StateError, err.Error())
		return err
	}
	// prepareTunnel resolves the endpoint and creates (does not start) a
	// tunnel instance; used while another instance still runs.
	prepareTunnel := func() (runner, error) {
		if perr := probeEndpoint(ctx, p); perr != nil {
			return nil, fmt.Errorf("%w: %v", ErrEndpointUnresolved, redact(p, perr))
		}
		return prepareBox(p, ModeTunnel, level, pump)
	}

	// serve reports the started tunnel and holds it until cancellation
	// (returns nil and the shutdown error) or until a rebuild is due and
	// its replacement was prepared (returns the prepared, not yet started
	// instance after the permit and inst were closed). Shutdown order: stop
	// the probe and the IPv6 monitor, close the Discord permit (Discord is
	// blocked again by the persistent filters), then close sing-box.
	serve := func(inst runner, permit io.Closer) (runner, error) {
		var builtV6 bool
		if b, ok := inst.(hostIPv6Builder); ok {
			builtV6 = b.builtHostIPv6()
		} else {
			builtV6 = hostHasIPv6()
		}
		logf("INFO", "tunnel started (configuration applied; WireGuard handshake not verified)")
		report(StateTunnelStarted, "")
		delay = initialDelay

		type rebuildRequest struct {
			reason       string
			connectivity bool
		}
		var connectivityLost atomic.Bool
		rebuild := make(chan rebuildRequest, 1)
		trigger := func(reason string, connectivity bool) {
			select {
			case rebuild <- rebuildRequest{reason, connectivity}:
			default: // one pending trigger is enough
			}
		}
		watchCtx, stopWatch := context.WithCancel(ctx)
		probeDone := make(chan struct{})
		if opts.OnConnectivity != nil {
			url := opts.ProbeURL
			if url == "" {
				url = ProbeURL
			}
			onResult := func(r ProbeResult) {
				opts.OnConnectivity(r)
				lost := r.State == ConnDisconnected && r.Failures >= ProbeDisconnectedAfter
				connectivityLost.Store(lost)
				if lost {
					trigger(fmt.Sprintf("VPN connectivity lost (%d consecutive probe failures)", r.Failures), true)
				}
			}
			go func() {
				defer close(probeDone)
				startProbe(watchCtx, inst, p, url, onResult)
			}()
		} else {
			close(probeDone)
		}
		monitorDone := make(chan struct{})
		go func() {
			defer close(monitorDone)
			t := time.NewTicker(hostCheckInterval)
			defer t.Stop()
			for {
				select {
				case <-watchCtx.Done():
					return
				case <-t.C:
				}
				if v6, err := hostIPv6(); err == nil && v6 != builtV6 {
					trigger(fmt.Sprintf("host IPv6 capability changed (built for %v, now %v)", builtV6, v6), false)
				}
			}
		}()
		stopWatchers := func() {
			stopWatch()
			for _, done := range []chan struct{}{probeDone, monitorDone} {
				select {
				case <-done:
				case <-time.After(2 * time.Second): // cancellation aborts the request
				}
			}
		}
		// closeCurrent closes the permit, then the instance.
		closeCurrent := func() (permitErr, closeErr error) {
			if permit != nil {
				permitErr = permit.Close()
			}
			return permitErr, closeBounded(inst)
		}
		shutdown := func() error {
			stopWatchers()
			permitErr, closeErr := closeCurrent()
			report(StateStopped, "")
			if closeErr != nil {
				return fmt.Errorf("stop sing-box: %w", closeErr)
			}
			if permitErr != nil {
				return fmt.Errorf("close Discord tunnel permit: %w", permitErr)
			}
			return nil
		}

		for {
			var request rebuildRequest
			select {
			case <-ctx.Done():
				return nil, shutdown()
			case request = <-rebuild:
			}
			if wait := rebuildWait(lastRebuild, time.Now(), minRebuildInterval); wait > 0 {
				t := time.NewTimer(wait)
				select {
				case <-ctx.Done():
					t.Stop()
					return nil, shutdown()
				case <-t.C:
				}
			}
			// Discard a queued probe rebuild if connectivity recovered while
			// waiting for the rate limit, or the physical link went down.
			if (request.connectivity && !connectivityLost.Load()) || !canRebuild() {
				continue
			}
			reason := request.reason
			lastRebuild = time.Now()
			logf("WARN", "rebuilding the tunnel: "+reason)
			next, err := prepareTunnel()
			if err != nil {
				// The running tunnel still confines Discord (persistent WFP
				// policy off the TUN): keep it and try again later.
				logf("ERROR", "tunnel rebuild preparation failed, keeping the current tunnel: "+err.Error())
				continue
			}
			// Preparation can resolve DNS and build the configuration while
			// probes and link monitoring continue. Revalidate before teardown.
			if ctx.Err() != nil || (request.connectivity && !connectivityLost.Load()) || !canRebuild() {
				if cerr := closeBounded(next); errors.Is(cerr, ErrCloseTimeout) {
					stopWatchers()
					_, _ = closeCurrent()
					return nil, terminal(cerr)
				}
				continue
			}
			stopWatchers()
			permitErr, closeErr := closeCurrent()
			if errors.Is(closeErr, ErrCloseTimeout) {
				// The old instance may still own the TUN: never start the
				// replacement next to it. The prepared one opened nothing.
				_ = closeBounded(next)
				return nil, terminal(closeErr)
			}
			if permitErr != nil {
				logf("WARN", "close Discord tunnel permit before rebuild: "+permitErr.Error())
			}
			if closeErr != nil {
				logf("WARN", "close tunnel before rebuild: "+closeErr.Error())
			}
			report(StateStarting, "rebuilding the tunnel: "+reason)
			return next, nil
		}
	}

	// block runs the fail-closed fallback after cause until a tunnel
	// instance is prepared; it returns that instance (not started, the
	// fallback already closed), or nil and Run's result.
	block := func(cause error) (runner, error) {
		logf("ERROR", "tunnel start failed, blocking Discord until it works: "+cause.Error())
		fallback, fbErr := startBox(p, ModeBlock, level, pump)
		if errors.Is(fbErr, ErrCloseTimeout) {
			return nil, terminal(fbErr)
		}
		if fbErr != nil {
			detail := "tunnel: " + cause.Error() + "; block fallback: " + fbErr.Error()
			logf("ERROR", "block fallback failed, Discord is NOT protected: "+fbErr.Error())
			report(StateError, detail)
			return nil, errors.New(detail)
		}
		report(StateBlocking, cause.Error())

		// Wait, then prepare the next attempt while the fallback runs.
		var next runner
		for next == nil {
			select {
			case <-ctx.Done():
				cerr := closeBounded(fallback)
				report(StateStopped, "")
				if cerr != nil && errors.Is(cerr, ErrCloseTimeout) {
					return nil, cerr
				}
				return nil, nil
			case <-time.After(delay):
			}
			if delay *= 2; delay > maxRetryDelay {
				delay = maxRetryDelay
			}
			if perr := probeEndpoint(ctx, p); perr != nil {
				logf("WARN", "WireGuard endpoint still does not resolve, keeping Discord blocked: "+redact(p, perr).Error())
				continue
			}
			var err error
			if next, err = prepareBox(p, ModeTunnel, level, pump); err != nil {
				logf("ERROR", "tunnel preparation failed, keeping Discord blocked: "+err.Error())
				next = nil
			}
		}

		// Gap without sing-box: from here until next.Start returns (or the
		// fallback is started again). The persistent WFP policy keeps the
		// discovered Discord executables blocked meanwhile.
		if cerr := closeBounded(fallback); errors.Is(cerr, ErrCloseTimeout) {
			// The fallback may still own the TUN: never start the prepared
			// tunnel next to it. The prepared instance opened nothing yet.
			_ = closeBounded(next)
			return nil, terminal(cerr)
		}
		return next, nil
	}

	inst, err := startBox(p, ModeTunnel, level, pump)
	for {
		if err == nil {
			var permit io.Closer
			if permit, err = up(inst); err == nil {
				next, serr := serve(inst, permit)
				if next == nil {
					return serr
				}
				// Rebuild: same gap as a retry from the fallback.
				inst, err = next, next.Start()
				if err == nil {
					continue
				}
			}
		}
		if errors.Is(err, ErrCloseTimeout) {
			return terminal(err)
		}
		if ctx.Err() != nil {
			report(StateStopped, "")
			return nil
		}
		next, berr := block(err)
		if next == nil {
			return berr
		}
		inst, err = next, next.Start()
	}
}

// redact removes every secret value of p from err's message.
func redact(p *profile.Profile, err error) error {
	if err == nil || p == nil {
		return err
	}
	msg := err.Error()
	changed := false
	for _, s := range secretForms(p) {
		if s != "" && strings.Contains(msg, s) {
			msg = strings.ReplaceAll(msg, s, "[redacted]")
			changed = true
		}
	}
	if !changed {
		return err
	}
	// The original error is intentionally not wrapped: unwrapping it would
	// expose the secret again.
	return errors.New(msg)
}

// lineRedactor returns a function that removes the profile secrets from a
// log line (sing-box and wireguard-go lines do not pass through redact).
func lineRedactor(p *profile.Profile) func([]byte) []byte {
	var forms [][]byte
	for _, s := range secretForms(p) {
		if s != "" {
			forms = append(forms, []byte(s))
		}
	}
	return func(line []byte) []byte {
		for _, f := range forms {
			if bytes.Contains(line, f) {
				line = bytes.ReplaceAll(line, f, []byte("[redacted]"))
			}
		}
		return line
	}
}

// secretForms returns the base64 and hex spellings of the profile secrets
// (wireguard-go uses hex internally).
func secretForms(p *profile.Profile) []string {
	var out []string
	for _, k := range []string{p.WireGuard.PrivateKey, p.WireGuard.PresharedKey} {
		if k == "" {
			continue
		}
		out = append(out, k)
		if raw, err := base64.StdEncoding.DecodeString(k); err == nil && len(raw) > 0 {
			h := hex.EncodeToString(raw)
			out = append(out, h, strings.ToUpper(h))
		}
	}
	return out
}
