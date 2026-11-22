package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"aurasplit/internal/profile"
)

// script drives a fake prepareBox: for each mode it says, per attempt,
// whether preparing or starting fails. Missing entries succeed.
type script struct {
	prepareErr map[string]error // key "tunnel#2"
	startErr   map[string]error
	usePipe    bool // fake instances write to a log pipe like sing-box
}

type pipeRunner struct {
	fakeRunner
	w *os.File
}

func (p *pipeRunner) Close() error {
	if p.w != nil {
		p.w.Close()
	}
	return p.fakeRunner.Close()
}

func installFakes(t *testing.T, s script, lookup func(context.Context, string) ([]string, error)) *eventLog {
	t.Helper()
	if !tagsOK {
		t.Skip("built without " + BuildTags)
	}
	events := &eventLog{}
	var mu sync.Mutex
	counts := map[Mode]int{}
	oldPrepare, oldLookup := prepareBox, lookupHost
	t.Cleanup(func() { prepareBox, lookupHost = oldPrepare, oldLookup })
	prepareBox = func(_ *profile.Profile, mode Mode, _ string, pump *logPump) (runner, error) {
		mu.Lock()
		counts[mode]++
		n := counts[mode]
		mu.Unlock()
		kind := "block"
		if mode == ModeTunnel {
			kind = "tunnel"
		}
		name := fmt.Sprintf("%s#%d", kind, n)
		if err := s.prepareErr[name]; err != nil {
			events.add("prepare " + name + ": fail")
			return nil, err
		}
		events.add("prepare " + name)
		r := &pipeRunner{fakeRunner: fakeRunner{name: name, events: events, startErr: s.startErr[name]}}
		if s.usePipe && pump != nil {
			w, err := pump.Pipe()
			if err != nil {
				return nil, err
			}
			fmt.Fprintf(w, "sing-box %s ready\n", name)
			r.w = w
		}
		return r, nil
	}
	if lookup == nil {
		lookup = func(context.Context, string) ([]string, error) {
			events.add("lookup: ok")
			return []string{"192.0.2.1"}, nil
		}
	}
	lookupHost = lookup
	return events
}

type stateLog struct {
	mu     sync.Mutex
	states []State
	detail []string
}

func (s *stateLog) on(cancelOn State, cancel context.CancelFunc) func(State, string) {
	return func(st State, d string) {
		s.mu.Lock()
		s.states = append(s.states, st)
		s.detail = append(s.detail, d)
		s.mu.Unlock()
		if st == cancelOn && cancel != nil {
			cancel()
		}
	}
}

func (s *stateLog) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fmt.Sprint(s.states)
}

func joined(ev []string) string { return strings.Join(ev, "|") }

func TestRunFirstAttemptNeedsNoFallback(t *testing.T) {
	events := installFakes(t, script{}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var sl stateLog
	if err := Run(ctx, testProfile(t, profile.ProviderWARP), RunOptions{
		LogWriter: &safeBuffer{}, OnState: sl.on(StateTunnelStarted, cancel),
	}); err != nil {
		t.Fatal(err)
	}
	if got, want := joined(events.get()), "prepare tunnel#1|start tunnel#1|close tunnel#1"; got != want {
		t.Fatalf("events %s, want %s", got, want)
	}
	if sl.String() != fmt.Sprint([]State{StateTunnelStarted, StateStopped}) {
		t.Fatalf("states %s", sl.String())
	}
}

// Tunnel and fallback both fail: nothing protects Discord, so Run reports
// StateError and returns the error for the supervisor to retry; no instance
// stays open.
func TestRunFallbackFailureReturnsError(t *testing.T) {
	p := testProfile(t, profile.ProviderWARP)
	events := installFakes(t, script{startErr: map[string]error{
		"tunnel#1": errors.New("tun: access denied"),
		"block#1":  errors.New("tun: access denied"),
	}}, nil)
	var sl stateLog
	err := Run(context.Background(), p, RunOptions{LogWriter: &safeBuffer{}, OnState: sl.on("", nil)})
	if err == nil || !strings.Contains(err.Error(), "block fallback") {
		t.Fatalf("Run error = %v", err)
	}
	if sl.String() != fmt.Sprint([]State{StateError}) {
		t.Fatalf("states %s", sl.String())
	}
	if got, want := joined(events.get()), "prepare tunnel#1|start tunnel#1: fail|prepare block#1|start block#1: fail"; got != want {
		t.Fatalf("events %s, want %s", got, want)
	}
	// Redaction happens inside instance.Start/newBox, which the fake
	// bypasses; it is covered by TestErrorsDoNotLeakKeys.
}

// Cancellation while blocking closes the fallback and reports stopped
// without waiting for the retry delay.
func TestRunCancelWhileBlocking(t *testing.T) {
	events := installFakes(t, script{startErr: map[string]error{"tunnel#1": errors.New("no route")}}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var sl stateLog
	start := time.Now()
	if err := Run(ctx, testProfile(t, profile.ProviderWARP), RunOptions{
		LogWriter: &safeBuffer{}, RetryDelay: time.Hour, OnState: sl.on(StateBlocking, cancel),
	}); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("shutdown waited for the retry delay: %s", d)
	}
	if got, want := joined(events.get()), "prepare tunnel#1|start tunnel#1: fail|prepare block#1|start block#1|close block#1"; got != want {
		t.Fatalf("events %s, want %s", got, want)
	}
	if sl.String() != fmt.Sprint([]State{StateBlocking, StateStopped}) {
		t.Fatalf("states %s", sl.String())
	}
}

// Cancelled before the first attempt failed: no fallback is started.
func TestRunCancelledDuringFirstAttempt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	events := installFakes(t, script{}, nil)
	oldPrepare := prepareBox
	prepareBox = func(p *profile.Profile, m Mode, l string, pump *logPump) (runner, error) {
		cancel() // shutdown arrives while sing-box is starting
		r, _ := oldPrepare(p, m, l, pump)
		r.(*pipeRunner).startErr = errors.New("interrupted")
		return r, nil
	}
	var sl stateLog
	if err := Run(ctx, testProfile(t, profile.ProviderWARP), RunOptions{LogWriter: &safeBuffer{}, OnState: sl.on("", nil)}); err != nil {
		t.Fatal(err)
	}
	if got := joined(events.get()); strings.Contains(got, "block") {
		t.Fatalf("fallback started after cancellation: %s", got)
	}
	if sl.String() != fmt.Sprint([]State{StateStopped}) {
		t.Fatalf("states %s", sl.String())
	}
}

// The prepared tunnel fails to start after the fallback was closed: the
// fallback must be started again at once (before the next delay), and the
// next attempt is prepared while the new fallback runs.
func TestRunPreparedTunnelFailureRestartsFallback(t *testing.T) {
	events := installFakes(t, script{startErr: map[string]error{
		"tunnel#1": errors.New("handshake setup"),
		"tunnel#2": errors.New("tun busy"),
	}}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var sl stateLog
	if err := Run(ctx, testProfile(t, profile.ProviderWARP), RunOptions{
		LogWriter: &safeBuffer{}, RetryDelay: time.Millisecond, OnState: sl.on(StateTunnelStarted, cancel),
	}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"prepare tunnel#1", "start tunnel#1: fail",
		"prepare block#1", "start block#1",
		"lookup: ok", "prepare tunnel#2", "close block#1", "start tunnel#2: fail",
		"prepare block#2", "start block#2",
		"lookup: ok", "prepare tunnel#3", "close block#2", "start tunnel#3",
		"close tunnel#3",
	}
	if got := joined(events.get()); got != joined(want) {
		t.Fatalf("events:\n got %s\nwant %s", got, joined(want))
	}
	if sl.String() != fmt.Sprint([]State{StateBlocking, StateBlocking, StateTunnelStarted, StateStopped}) {
		t.Fatalf("states %s", sl.String())
	}
}

// A failed preparation keeps the fallback running (never closed before a
// prepared tunnel exists).
func TestRunPrepareFailureKeepsBlocking(t *testing.T) {
	events := installFakes(t, script{
		startErr:   map[string]error{"tunnel#1": errors.New("down")},
		prepareErr: map[string]error{"tunnel#2": errors.New("config")},
	}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var sl stateLog
	if err := Run(ctx, testProfile(t, profile.ProviderWARP), RunOptions{
		LogWriter: &safeBuffer{}, RetryDelay: time.Millisecond, OnState: sl.on(StateTunnelStarted, cancel),
	}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"prepare tunnel#1", "start tunnel#1: fail",
		"prepare block#1", "start block#1",
		"lookup: ok", "prepare tunnel#2: fail",
		"lookup: ok", "prepare tunnel#3", "close block#1", "start tunnel#3",
		"close tunnel#3",
	}
	if got := joined(events.get()); got != joined(want) {
		t.Fatalf("events:\n got %s\nwant %s", got, joined(want))
	}
}

// An IP endpoint needs no name lookup before a retry.
func TestRunIPEndpointSkipsLookup(t *testing.T) {
	lookups := 0
	installFakes(t, script{startErr: map[string]error{"tunnel#1": errors.New("down")}},
		func(context.Context, string) ([]string, error) { lookups++; return nil, errors.New("unexpected") })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var sl stateLog
	p := testProfile(t, profile.ProviderWireGuard) // endpoint 198.51.100.7:51820
	if err := Run(ctx, p, RunOptions{LogWriter: &safeBuffer{}, RetryDelay: time.Millisecond, OnState: sl.on(StateTunnelStarted, cancel)}); err != nil {
		t.Fatal(err)
	}
	if lookups != 0 {
		t.Fatalf("lookupHost called %d times for an IP endpoint", lookups)
	}
}

// Run must not leak goroutines: the log pump writer and every pipe reader
// exit before Run returns (instances close their pipes like sing-box).
func TestRunLeavesNoGoroutines(t *testing.T) {
	before := runtime.NumGoroutine()
	installFakes(t, script{usePipe: true, startErr: map[string]error{"tunnel#1": errors.New("down")}}, nil)
	for i := 0; i < 5; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		var sink safeBuffer
		var sl stateLog
		if err := Run(ctx, testProfile(t, profile.ProviderWARP), RunOptions{
			LogWriter: &sink, RetryDelay: time.Millisecond, OnState: sl.on(StateTunnelStarted, cancel),
		}); err != nil {
			t.Fatal(err)
		}
		cancel()
		if !strings.Contains(sink.String(), "ready") {
			t.Fatalf("pipe output lost: %q", sink.String())
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		sleepShort()
	}
	if n := runtime.NumGoroutine(); n > before {
		buf := make([]byte, 1<<16)
		t.Fatalf("goroutines: %d before, %d after\n%s", before, n, buf[:runtime.Stack(buf, true)])
	}
}

// Pipe after Close is refused, and Log after Close never blocks or panics
// (sing-box may still log while it is being closed).
func TestLogPumpUseAfterClose(t *testing.T) {
	var buf safeBuffer
	pump := newLogPump(&buf, 4)
	pump.Close(time.Second)
	pump.Close(time.Second) // idempotent
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			pump.Log("INFO", "late")
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Log blocked after Close")
	}
	if _, err := pump.Pipe(); err == nil {
		t.Fatal("Pipe after Close succeeded")
	}
}
