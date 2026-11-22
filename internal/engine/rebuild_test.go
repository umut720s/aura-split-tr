package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"aurasplit/internal/profile"
)

func TestRunSuppressesOfflineRebuild(t *testing.T) {
	old := physicalNetwork
	defer func() { physicalNetwork = old }()
	synctest.Test(t, func(t *testing.T) {
		link := physicalLink{}
		physicalNetwork = func() (physicalLink, error) { return link, nil }
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var events *eventLog
		events, opts := rebuildFakes(t, script{}, func(_ context.Context, name string, report func(ProbeResult)) {
			if name != "tunnel#1" {
				return
			}
			report(ProbeResult{State: ConnDisconnected, Failures: 3})
			time.Sleep(time.Second)
			if strings.Contains(joined(events.get()), "prepare tunnel#2") {
				t.Error("rebuilt while offline")
			}
			link = physicalLink{index: 1, up: true}
			report(ProbeResult{State: ConnDegraded, Failures: 1})
			time.Sleep(time.Second)
			if strings.Contains(joined(events.get()), "prepare tunnel#2") {
				t.Error("rebuilt before failure threshold")
			}
			report(ProbeResult{State: ConnDisconnected, Failures: 3})
		})
		var states stateLog
		opts.OnState = cancelOnNth(2, cancel, &states)
		if err := Run(ctx, testProfile(t, profile.ProviderWARP), opts); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(joined(events.get()), "prepare tunnel#2") {
			t.Fatal("no rebuild after persistent failures on restored link")
		}
	})
}

func TestRunDiscardsRecoveredQueuedRebuild(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		events, opts := rebuildFakes(t, script{prepareErr: map[string]error{
			"tunnel#2": errors.New("temporary preparation failure"),
		}}, func(_ context.Context, name string, report func(ProbeResult)) {
			if name != "tunnel#1" {
				return
			}
			report(ProbeResult{State: ConnDisconnected, Failures: 3})
			time.Sleep(time.Second)
			report(ProbeResult{State: ConnDisconnected, Failures: 3})
			time.Sleep(time.Second)
			report(ProbeResult{State: ConnDisconnected}) // Physical link down invalidates the queued request.
			time.Sleep(time.Second)
			report(ProbeResult{State: ConnVerified})
			time.Sleep(3 * time.Minute)
			cancel()
		})
		minRebuildInterval = 2 * time.Minute
		if err := Run(ctx, testProfile(t, profile.ProviderWARP), opts); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(joined(events.get()), "prepare tunnel#3") {
			t.Fatal("stale rebuild executed after recovery")
		}
	})
}

// rebuildFakes installs the fake boxes (installFakes), a permit that logs
// into the same event list, a fake probe and short rebuild timings.
func rebuildFakes(t *testing.T, s script, probe func(ctx context.Context, name string, report func(ProbeResult))) (*eventLog, RunOptions) {
	t.Helper()
	events := installFakes(t, s, nil)
	oldProbe, oldCheck, oldMin := startProbe, hostCheckInterval, minRebuildInterval
	t.Cleanup(func() { startProbe, hostCheckInterval, minRebuildInterval = oldProbe, oldCheck, oldMin })
	hostCheckInterval = time.Hour
	minRebuildInterval = 0
	startProbe = func(ctx context.Context, inst runner, _ *profile.Profile, _ string, report func(ProbeResult)) bool {
		name := inst.(*pipeRunner).name
		if probe != nil {
			probe(ctx, name, report)
		}
		<-ctx.Done()
		return true
	}
	opts := RunOptions{
		LogWriter:      &safeBuffer{},
		RetryDelay:     time.Millisecond,
		OnConnectivity: func(ProbeResult) {},
		OnTunnelUp: func() (io.Closer, error) {
			events.add("permit open")
			return closerFunc(func() error { events.add("close permit"); return nil }), nil
		},
	}
	return events, opts
}

type closerFunc func() error

func TestRunRechecksRebuildAfterPreparation(t *testing.T) {
	for _, change := range []string{"recovered", "offline"} {
		t.Run(change, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				old := physicalNetwork
				defer func() { physicalNetwork = old }()
				link := physicalLink{index: 1, up: true}
				physicalNetwork = func() (physicalLink, error) { return link, nil }
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				prepared := make(chan struct{})
				events, opts := rebuildFakes(t, script{}, func(_ context.Context, name string, report func(ProbeResult)) {
					if name != "tunnel#1" {
						return
					}
					report(ProbeResult{State: ConnDisconnected, Failures: 3})
					<-prepared
					if change == "recovered" {
						report(ProbeResult{State: ConnVerified})
					} else {
						link = physicalLink{}
					}
				})
				inner := prepareBox
				prepareBox = func(p *profile.Profile, m Mode, l string, pump *logPump) (runner, error) {
					r, err := inner(p, m, l, pump)
					if inst, ok := r.(*pipeRunner); ok && inst.name == "tunnel#2" {
						close(prepared)
						time.Sleep(time.Second)
					}
					return r, err
				}
				go func() { time.Sleep(3 * time.Second); cancel() }()
				if err := Run(ctx, testProfile(t, profile.ProviderWARP), opts); err != nil {
					t.Fatal(err)
				}
				got := joined(events.get())
				if strings.Contains(got, "start tunnel#2") || !strings.Contains(got, "close tunnel#2") {
					t.Fatalf("obsolete replacement was not discarded: %s", got)
				}
			})
		})
	}
}

func (f closerFunc) Close() error { return f() }

// cancelOnNth cancels after the n-th StateTunnelStarted and records states.
func cancelOnNth(n int, cancel context.CancelFunc, states *stateLog) func(State, string) {
	var mu sync.Mutex
	seen := 0
	return func(s State, d string) {
		states.on("", nil)(s, d)
		if s != StateTunnelStarted {
			return
		}
		mu.Lock()
		seen++
		done := seen == n
		mu.Unlock()
		if done {
			cancel()
		}
	}
}

func disconnectOnce(target string) func(context.Context, string, func(ProbeResult)) {
	return func(_ context.Context, name string, report func(ProbeResult)) {
		if name == target {
			report(ProbeResult{State: ConnDisconnected, Failures: ProbeDisconnectedAfter, Detail: "timeout"})
		}
	}
}

// VPN_DISCONNECTED rebuilds the tunnel: the replacement is prepared (and
// the endpoint resolved) while the old tunnel runs; then the permit and the
// old tunnel are closed and the replacement started with a new permit.
func TestRunRebuildOnDisconnect(t *testing.T) {
	events, opts := rebuildFakes(t, script{}, disconnectOnce("tunnel#1"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var sl stateLog
	opts.OnState = cancelOnNth(2, cancel, &sl)
	if err := Run(ctx, testProfile(t, profile.ProviderWARP), opts); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"prepare tunnel#1", "start tunnel#1", "permit open",
		"lookup: ok", "prepare tunnel#2", "close permit", "close tunnel#1",
		"start tunnel#2", "permit open",
		"close permit", "close tunnel#2",
	}
	if got := joined(events.get()); got != joined(want) {
		t.Fatalf("events:\n got %s\nwant %s", got, joined(want))
	}
	if sl.String() != fmt.Sprint([]State{StateTunnelStarted, StateStarting, StateTunnelStarted, StateStopped}) {
		t.Fatalf("states %s", sl.String())
	}
}

// A change of the host IPv6 capability (checked periodically) rebuilds the
// tunnel once; the replacement is built for the new value, so it is stable.
func TestRunRebuildOnHostIPv6Change(t *testing.T) {
	events, opts := rebuildFakes(t, script{}, nil)
	hostCheckInterval = 2 * time.Millisecond
	var v6 atomic.Bool
	old := hostIPv6
	hostIPv6 = func() (bool, error) { return v6.Load(), nil }
	t.Cleanup(func() { hostIPv6 = old })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var sl stateLog
	started := 0
	opts.OnState = func(s State, d string) {
		sl.on("", nil)(s, d)
		if s == StateTunnelStarted {
			started++
			switch started {
			case 1:
				v6.Store(true) // the network gained IPv6 after the start
			case 2:
				// Give the monitor a few periods to prove it stays quiet.
				go func() { time.Sleep(30 * time.Millisecond); cancel() }()
			}
		}
	}
	if err := Run(ctx, testProfile(t, profile.ProviderWARP), opts); err != nil {
		t.Fatal(err)
	}
	got := joined(events.get())
	if strings.Count(got, "start tunnel#") != 2 || !strings.Contains(got, "prepare tunnel#2|close permit|close tunnel#1|start tunnel#2") {
		t.Fatalf("events %s", got)
	}
	if strings.Contains(got, "tunnel#3") {
		t.Fatalf("rebuilt again although the capability did not change: %s", got)
	}
}

// A replacement that cannot be prepared (endpoint does not resolve) keeps
// the running tunnel; the next attempt waits at least minRebuildInterval.
func TestRunRebuildPrepareFailureKeepsTunnelAndIsRateLimited(t *testing.T) {
	events, opts := rebuildFakes(t, script{prepareErr: map[string]error{
		"tunnel#2": fmt.Errorf("%w: test", ErrEndpointUnresolved),
	}}, func(ctx context.Context, name string, report func(ProbeResult)) {
		if name != "tunnel#1" {
			return
		}
		// Keeps reporting disconnected, like the prober would.
		go func() {
			for ctx.Err() == nil {
				report(ProbeResult{State: ConnDisconnected, Failures: 3})
				time.Sleep(time.Millisecond)
			}
		}()
	})
	minRebuildInterval = 60 * time.Millisecond
	var mu sync.Mutex
	var prepTimes []time.Time
	inner := prepareBox
	prepareBox = func(p *profile.Profile, m Mode, l string, pump *logPump) (runner, error) {
		if m == ModeTunnel {
			mu.Lock()
			prepTimes = append(prepTimes, time.Now())
			mu.Unlock()
		}
		return inner(p, m, l, pump)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var sl stateLog
	opts.OnState = cancelOnNth(2, cancel, &sl)
	if err := Run(ctx, testProfile(t, profile.ProviderWARP), opts); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"prepare tunnel#1", "start tunnel#1", "permit open",
		"lookup: ok", "prepare tunnel#2: fail",
		"lookup: ok", "prepare tunnel#3", "close permit", "close tunnel#1",
		"start tunnel#3", "permit open",
		"close permit", "close tunnel#3",
	}
	if got := joined(events.get()); got != joined(want) {
		t.Fatalf("events:\n got %s\nwant %s", got, joined(want))
	}
	mu.Lock()
	defer mu.Unlock()
	if len(prepTimes) != 3 {
		t.Fatalf("tunnel preparations: %d", len(prepTimes))
	}
	if d := prepTimes[2].Sub(prepTimes[1]); d < minRebuildInterval {
		t.Fatalf("second rebuild attempt after %s, want >= %s", d, minRebuildInterval)
	}
}

// A replacement that fails to start enters the fail-closed fallback, which
// then retries as usual.
func TestRunRebuildStartFailureFallsBack(t *testing.T) {
	events, opts := rebuildFakes(t, script{startErr: map[string]error{
		"tunnel#2": errors.New("tun busy"),
	}}, disconnectOnce("tunnel#1"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var sl stateLog
	opts.OnState = cancelOnNth(2, cancel, &sl)
	if err := Run(ctx, testProfile(t, profile.ProviderWARP), opts); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"prepare tunnel#1", "start tunnel#1", "permit open",
		"lookup: ok", "prepare tunnel#2", "close permit", "close tunnel#1",
		"start tunnel#2: fail",
		"prepare block#1", "start block#1",
		"lookup: ok", "prepare tunnel#3", "close block#1", "start tunnel#3", "permit open",
		"close permit", "close tunnel#3",
	}
	if got := joined(events.get()); got != joined(want) {
		t.Fatalf("events:\n got %s\nwant %s", got, joined(want))
	}
	if sl.String() != fmt.Sprint([]State{StateTunnelStarted, StateStarting, StateBlocking, StateTunnelStarted, StateStopped}) {
		t.Fatalf("states %s", sl.String())
	}
}

// An endpoint that does not resolve at the first start keeps Discord
// blocked (fallback) instead of starting a tunnel with the host name.
func TestRunUnresolvedEndpointAtStartBlocks(t *testing.T) {
	events, opts := rebuildFakes(t, script{prepareErr: map[string]error{
		"tunnel#1": fmt.Errorf("%w: boot", ErrEndpointUnresolved),
	}}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var sl stateLog
	opts.OnState = cancelOnNth(1, cancel, &sl)
	if err := Run(ctx, testProfile(t, profile.ProviderWARP), opts); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"prepare tunnel#1: fail",
		"prepare block#1", "start block#1",
		"lookup: ok", "prepare tunnel#2", "close block#1", "start tunnel#2", "permit open",
		"close permit", "close tunnel#2",
	}
	if got := joined(events.get()); got != joined(want) {
		t.Fatalf("events:\n got %s\nwant %s", got, joined(want))
	}
}

func TestRebuildWait(t *testing.T) {
	now := time.Unix(1000, 0)
	if d := rebuildWait(time.Time{}, now, 2*time.Minute); d != 0 {
		t.Fatalf("first rebuild waits %s", d)
	}
	if d := rebuildWait(now.Add(-30*time.Second), now, 2*time.Minute); d != 90*time.Second {
		t.Fatalf("wait %s", d)
	}
	if d := rebuildWait(now.Add(-3*time.Minute), now, 2*time.Minute); d != 0 {
		t.Fatalf("wait %s", d)
	}
}
