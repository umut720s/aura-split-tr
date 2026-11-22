package wfp

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestNextWatchBackoff(t *testing.T) {
	oldMin, oldMax := watchRetryMin, watchRetryMax
	t.Cleanup(func() { watchRetryMin, watchRetryMax = oldMin, oldMax })
	watchRetryMin, watchRetryMax = time.Second, 60*time.Second
	var d time.Duration
	var got []time.Duration
	for i := 0; i < 9; i++ {
		d = nextWatchBackoff(d, time.Second)
		got = append(got, d)
	}
	want := []time.Duration{1, 2, 4, 8, 16, 32, 60, 60, 60}
	for i := range want {
		if got[i] != want[i]*time.Second {
			t.Fatalf("backoff sequence %v", got)
		}
	}
	// A failure long after the last restart starts again at the minimum.
	if d := nextWatchBackoff(60*time.Second, 61*time.Second); d != time.Second {
		t.Fatalf("not reset: %s", d)
	}
}

type fakeWatch struct {
	mu     sync.Mutex
	starts [][]WatchTarget
	times  []time.Time
	run    func(n int, ctx context.Context, ts []WatchTarget, notify func(), fail func(WatchTarget, error)) error
	// onNotify, if set, runs inside RunWatcher's notify callback (on the
	// RunWatcher goroutine for restarts) before the notification is sent.
	onNotify func()
}

func (f *fakeWatch) fn(ctx context.Context, ts []WatchTarget, notify func(), fail func(WatchTarget, error)) error {
	f.mu.Lock()
	f.starts = append(f.starts, ts)
	f.times = append(f.times, time.Now())
	n := len(f.starts)
	f.mu.Unlock()
	return f.run(n, ctx, ts, notify, fail)
}

func (f *fakeWatch) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.starts)
}

func runFakeWatcher(t *testing.T, fw *fakeWatch, targets []WatchTarget) (notified <-chan struct{}, logs func() []string) {
	t.Helper()
	oldFn, oldMin, oldMax := watchFn, watchRetryMin, watchRetryMax
	watchFn = fw.fn
	watchRetryMin, watchRetryMax = 20*time.Millisecond, 80*time.Millisecond
	n := make(chan struct{}, 64)
	var mu sync.Mutex
	var lines []string
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		RunWatcher(ctx, func() ([]WatchTarget, error) { return targets, nil }, time.Hour, func() {
			if fw.onNotify != nil {
				fw.onNotify()
			}
			select {
			case n <- struct{}{}:
			default:
			}
		}, func(level, msg string) {
			mu.Lock()
			lines = append(lines, level+" "+msg)
			mu.Unlock()
		})
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
		watchFn, watchRetryMin, watchRetryMax = oldFn, oldMin, oldMax
	})
	return n, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), lines...)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timeout waiting for " + what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// One target fails to open: the failure is logged at once (while the
// other target is still watched) and the watches are restarted after the
// backoff although the target list is unchanged; once the open succeeds
// no further restart happens.
func TestRunWatcherRetriesFailedTarget(t *testing.T) {
	targets := []WatchTarget{{Path: `C:\u\AppData\Local`}, {Path: `C:\u\AppData\Local\Discord`, Subtree: true}}
	fw := &fakeWatch{run: func(n int, ctx context.Context, ts []WatchTarget, notify func(), fail func(WatchTarget, error)) error {
		if n <= 2 {
			fail(ts[1], errors.New("access denied"))
		}
		<-ctx.Done()
		return nil
	}}
	notified, logs := runFakeWatcher(t, fw, targets)
	waitFor(t, "failure logged", func() bool { return len(logs()) > 0 })
	waitFor(t, "third start", func() bool { return fw.count() >= 3 })
	select {
	case <-notified:
	case <-time.After(5 * time.Second):
		t.Fatal("no notify after the restart")
	}
	time.Sleep(300 * time.Millisecond)
	if n := fw.count(); n != 3 {
		t.Fatalf("starts = %d after the watch recovered", n)
	}
	fw.mu.Lock()
	gap1, gap2 := fw.times[1].Sub(fw.times[0]), fw.times[2].Sub(fw.times[1])
	fw.mu.Unlock()
	if gap1 < 15*time.Millisecond || gap2 < 35*time.Millisecond {
		t.Fatalf("restarts not backed off: %s %s", gap1, gap2)
	}
}

// A generation that saturates the failure queue must not make the next
// generation's termination report get lost: the watcher keeps restarting.
//
// Deterministic, with no timing assumptions:
//   - Generation 1 reports one failure, so the loop schedules a restart.
//     When start() cancels it and is blocked joining it, generation 1 fills
//     the queue far beyond its capacity before returning: nothing can
//     consume the queue then, so it is full of obsolete reports.
//   - Generation 2 is dead at once: its only watch fails immediately (one
//     report through fail, synchronously from the watch).
//   - The loop calls notify right after start(); the test holds that call
//     until generation 2's report has been made, so the loop cannot free a
//     queue slot first.
//
// That single report is the only way to get a third start (refresh is one
// hour, targets never change). Without the drain in start() it is dropped
// against the full queue and the test fails at two starts. (A termination
// report, posted by RunWatcher's own goroutine after the watch returns,
// cannot be ordered against the loop by a test; the per-target report
// exercises the same queue.)
func TestRunWatcherSaturatedQueueAcrossGenerations(t *testing.T) {
	targets := []WatchTarget{{Path: `C:\u\AppData\Local`}}
	flooded := make(chan struct{})
	gen2Reported := make(chan struct{})
	var once sync.Once
	fw := &fakeWatch{run: func(n int, ctx context.Context, ts []WatchTarget, notify func(), fail func(WatchTarget, error)) error {
		switch n {
		case 1:
			fail(ts[0], errors.New("first failure"))
			<-ctx.Done()
			// start() is now joining this generation.
			for i := 0; i < 1000; i++ {
				fail(ts[0], errors.New("flood"))
			}
			close(flooded)
			return nil
		case 2:
			fail(ts[0], errors.New("replacement failed at once"))
			close(gen2Reported)
			<-ctx.Done()
			return nil
		default:
			<-ctx.Done()
			return nil
		}
	}}
	fw.onNotify = func() {
		// First notify = right after the restart into generation 2.
		once.Do(func() {
			select {
			case <-gen2Reported:
			case <-time.After(5 * time.Second):
			}
		})
	}
	runFakeWatcher(t, fw, targets)
	waitFor(t, "third start", func() bool { return fw.count() >= 3 })
	select {
	case <-flooded:
	default:
		t.Fatal("generation 1 did not flood the queue")
	}
	time.Sleep(100 * time.Millisecond)
	if n := fw.count(); n != 3 {
		t.Fatalf("starts = %d, want exactly 3", n)
	}
}

// The OS watcher ending on its own (wait loop terminated) is propagated:
// the watcher restarts it with a bounded backoff.
func TestRunWatcherRestartsEndedWatch(t *testing.T) {
	targets := []WatchTarget{{Path: `C:\u\AppData\Local`}}
	fw := &fakeWatch{run: func(n int, ctx context.Context, ts []WatchTarget, notify func(), fail func(WatchTarget, error)) error {
		if n <= 5 {
			return errors.New("every directory watch ended")
		}
		<-ctx.Done()
		return nil
	}}
	_, logs := runFakeWatcher(t, fw, targets)
	waitFor(t, "sixth start", func() bool { return fw.count() >= 6 })
	fw.mu.Lock()
	var maxGap time.Duration
	for i := 1; i < len(fw.times); i++ {
		if g := fw.times[i].Sub(fw.times[i-1]); g > maxGap {
			maxGap = g
		}
	}
	fw.mu.Unlock()
	if maxGap > 2*time.Second {
		t.Fatalf("backoff not bounded: %s", maxGap)
	}
	if len(logs()) < 5 {
		t.Fatalf("terminations not reported: %v", logs())
	}
}
