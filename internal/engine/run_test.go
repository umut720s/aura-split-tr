package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/service"

	"aurasplit/internal/profile"
)

// The log redirect must hand sing-box a pipe that ends in our sink and
// leave every other file operation to the default manager.
func TestLogRedirect(t *testing.T) {
	var buf safeBuffer
	pump := newLogPump(&buf, 16)
	ctx := withLogRedirect(context.Background(), pump)
	m := service.FromContext[fileManager](ctx)
	if m == nil {
		t.Fatal("no file manager in context")
	}
	f, err := m.OpenFile(logSentinel, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("hello\n"))
	f.Close()
	pump.Close(time.Second)
	if buf.String() != "hello\n" {
		t.Fatalf("redirected log = %q", buf.String())
	}
}

// blockingSink stalls every write until release is closed.
type blockingSink struct {
	release chan struct{}
	safeBuffer
}

func (b *blockingSink) Write(p []byte) (int, error) {
	<-b.release
	return b.safeBuffer.Write(p)
}

// A stalled sink must never stall the writer: lines beyond the queue are
// dropped and the drop is reported once the sink works again.
func TestLogPumpDoesNotBlockOnStalledSink(t *testing.T) {
	sink := &blockingSink{release: make(chan struct{})}
	pump := newLogPump(sink, 8)
	w, err := pump.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 5000; i++ {
			fmt.Fprintf(w, "line %d\n", i)
		}
		pump.Log("INFO", "engine message")
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("writes blocked on a stalled sink")
	}
	w.Close()
	close(sink.release)
	pump.Close(2 * time.Second)
	out := sink.String()
	if !strings.Contains(out, "log lines dropped") {
		t.Fatalf("no drop notice in %q", out)
	}
	if !strings.Contains(out, "line 0\n") {
		t.Fatal("first lines lost")
	}
}

// failingSink fails its first n writes.
type failingSink struct {
	mu sync.Mutex
	n  int
	safeBuffer
}

func (f *failingSink) Write(p []byte) (int, error) {
	f.mu.Lock()
	fail := f.n > 0
	f.n--
	f.mu.Unlock()
	if fail {
		return 0, errors.New("disk full")
	}
	return f.safeBuffer.Write(p)
}

func TestLogPumpKeepsDrainingAfterSinkErrors(t *testing.T) {
	sink := &failingSink{n: 3}
	pump := newLogPump(sink, 64)
	w, err := pump.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		fmt.Fprintf(w, "line %d\n", i)
	}
	w.Close()
	pump.Close(2 * time.Second)
	out := sink.String()
	if !strings.Contains(out, "line 9\n") || !strings.Contains(out, "3 log writes failed") {
		t.Fatalf("output %q", out)
	}
}

// Shutdown is bounded even when the sink never returns.
func TestLogPumpCloseIsBounded(t *testing.T) {
	sink := &blockingSink{release: make(chan struct{})}
	defer close(sink.release)
	pump := newLogPump(sink, 8)
	w, err := pump.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(w, "stuck")
	start := time.Now()
	pump.Close(200 * time.Millisecond) // also closes w
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Close took %s", d)
	}
	if _, err := pump.Pipe(); err == nil {
		t.Fatal("Pipe after Close succeeded")
	}
}

func TestLogPumpSplitsLongLines(t *testing.T) {
	var buf safeBuffer
	pump := newLogPump(&buf, 64)
	w, _ := pump.Pipe()
	fmt.Fprint(w, strings.Repeat("a", maxLogLine+10)+"\nend")
	w.Close()
	pump.Close(2 * time.Second)
	out := buf.String()
	if strings.Count(out, "\n") != 3 || !strings.HasSuffix(out, "end\n") {
		t.Fatalf("lines: %d, suffix %q", strings.Count(out, "\n"), out[len(out)-5:])
	}
}

type fakeRunner struct {
	name     string
	startErr error
	events   *eventLog
}

func (f *fakeRunner) Start() error {
	if f.startErr != nil {
		f.events.add("start " + f.name + ": fail")
		return f.startErr
	}
	f.events.add("start " + f.name)
	return nil
}

func (f *fakeRunner) Close() error { f.events.add("close " + f.name); return nil }

type eventLog struct {
	mu sync.Mutex
	ev []string
}

func (e *eventLog) add(s string) { e.mu.Lock(); e.ev = append(e.ev, s); e.mu.Unlock() }
func (e *eventLog) get() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.ev...)
}

// The retry from block mode prepares the tunnel and resolves the endpoint
// while the fallback still runs, keeps blocking while the name does not
// resolve, and closes the fallback only right before starting the
// prepared tunnel.
func TestRunRetryOrdering(t *testing.T) {
	if !tagsOK {
		t.Skip("built without " + BuildTags)
	}
	events := &eventLog{}
	counts := map[Mode]int{}
	oldPrepare, oldLookup := prepareBox, lookupHost
	t.Cleanup(func() { prepareBox, lookupHost = oldPrepare, oldLookup })
	prepareBox = func(_ *profile.Profile, mode Mode, _ string, _ *logPump) (runner, error) {
		counts[mode]++
		name := fmt.Sprintf("block#%d", counts[mode])
		if mode == ModeTunnel {
			name = fmt.Sprintf("tunnel#%d", counts[mode])
		}
		events.add("prepare " + name)
		r := &fakeRunner{name: name, events: events}
		if name == "tunnel#1" {
			r.startErr = errors.New("peer unreachable")
		}
		return r, nil
	}
	lookups := 0
	lookupHost = func(context.Context, string) ([]string, error) {
		lookups++
		if lookups == 1 {
			events.add("lookup: fail")
			return nil, errors.New("no such host")
		}
		events.add("lookup: ok")
		return []string{"192.0.2.1"}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var states []State
	var buf safeBuffer
	err := Run(ctx, testProfile(t, profile.ProviderWARP), RunOptions{
		LogWriter:  &buf,
		RetryDelay: time.Millisecond,
		OnState: func(s State, _ string) {
			states = append(states, s)
			if s == StateTunnelStarted {
				cancel()
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"prepare tunnel#1", "start tunnel#1: fail",
		"prepare block#1", "start block#1",
		"lookup: fail",
		"lookup: ok", "prepare tunnel#2",
		"close block#1", "start tunnel#2",
		"close tunnel#2",
	}
	if got := events.get(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("events:\n got %v\nwant %v", got, want)
	}
	if fmt.Sprint(states) != fmt.Sprint([]State{StateBlocking, StateTunnelStarted, StateStopped}) {
		t.Fatalf("states %v", states)
	}
	if out := buf.String(); !strings.Contains(out, "still does not resolve") || !strings.Contains(out, "tunnel started") {
		t.Fatalf("log %q", out)
	}
}
