package wfp

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// watchFn watches targets until ctx is cancelled and calls notify after
// every change notification. fail is called promptly (from any goroutine)
// for every target whose watch could not be opened, could not be re-armed
// or whose wait failed; that target is no longer watched. watchFn returns
// nil after ctx is cancelled, and an error if it ends earlier (nothing
// left to watch). A variable so tests can replace the OS watcher.
var watchFn = platformWatch

// Retry backoff for failed or dropped watches (variables so tests can
// shorten them).
var (
	watchRetryMin = time.Second
	watchRetryMax = 60 * time.Second
)

// nextWatchBackoff returns the delay before the next watch restart: it
// doubles (bounded by watchRetryMax) while failures follow each other
// within watchRetryMax of the last restart, and starts again at
// watchRetryMin otherwise.
func nextWatchBackoff(prev, sinceLastRetry time.Duration) time.Duration {
	if prev <= 0 || sinceLastRetry > watchRetryMax {
		return watchRetryMin
	}
	next := prev * 2
	if next > watchRetryMax {
		next = watchRetryMax
	}
	return next
}

type watchFailure struct {
	gen int
	t   WatchTarget
	err error
}

// RunWatcher keeps OS change notifications on the Discord directories
// returned by targets and calls notify (which must not block) whenever
// something changes there. The target list is re-read every refresh, and
// one second after a change (a new install directory becomes watchable at
// once); when it changes the watches are restarted and notify is called
// once, because events may have been missed during the restart.
//
// A target whose watch fails to open, cannot be re-armed or whose wait
// ends is reported at once (logged) and the watches are restarted after a
// bounded exponential backoff (watchRetryMin to watchRetryMax), also when
// the target list did not change; notify is called after each such
// restart. If the OS watcher itself ends before ctx is cancelled, that is
// handled the same way.
//
// The watcher only shortens the time until Guard reconciles; it is not an
// enforcement mechanism. Until the reconcile has added the blocks, a new
// executable is not covered by the persistent policy (see ARCHITECTURE.md).
func RunWatcher(ctx context.Context, targets func() ([]WatchTarget, error), refresh time.Duration, notify func(), logf func(level, msg string)) {
	if refresh <= 0 {
		refresh = DefaultRescanInterval
	}
	log := func(level, msg string) {
		if logf != nil {
			logf(level, msg)
		}
	}
	changed := make(chan struct{}, 1)
	onEvent := func() {
		notify()
		select {
		case changed <- struct{}{}:
		default:
		}
	}
	// failures carries per-target failures promptly. It only ever holds
	// reports of the current generation (start drains it after joining the
	// old watcher), so when it is full the loop will still consume one of
	// them and schedule a restart; dropping further reports loses nothing.
	failures := make(chan watchFailure, 64)
	report := func(f watchFailure) {
		select {
		case failures <- f:
		default:
		}
	}
	var cur []WatchTarget
	gen := 0
	var cancel context.CancelFunc = func() {}
	var done chan struct{}
	stop := func() {
		cancel()
		if done != nil {
			<-done
			done = nil
		}
	}
	defer stop()
	start := func(ts []WatchTarget) {
		stop()
		// The previous watcher has been joined, so every queued report is
		// obsolete. Drain them now: otherwise a full queue of old-generation
		// reports would make the new generation's failures (including its
		// termination report) drop, and the watcher could stay dead.
		for drained := false; !drained; {
			select {
			case <-failures:
			default:
				drained = true
			}
		}
		gen++
		cur = ts
		if len(ts) == 0 {
			return
		}
		wctx, c := context.WithCancel(ctx)
		cancel = c
		done = make(chan struct{})
		d, g := done, gen
		go func() {
			defer close(d)
			err := watchFn(wctx, ts, onEvent, func(t WatchTarget, err error) {
				report(watchFailure{gen: g, t: t, err: err})
			})
			if wctx.Err() == nil && !errors.Is(err, ErrUnsupported) {
				// The OS watcher ended on its own: nothing is watched now.
				if err == nil {
					err = errors.New("ended")
				}
				report(watchFailure{gen: g, err: fmt.Errorf("directory watcher stopped: %w", err)})
			}
		}()
	}
	load := func() []WatchTarget {
		ts, err := targets()
		if err != nil {
			log("WARN", "wfp: watch targets incomplete: "+err.Error())
		}
		return ts
	}
	start(load())
	t := time.NewTimer(refresh)
	defer t.Stop()
	var (
		backoff   time.Duration
		lastRetry time.Time
		retry     *time.Timer
		retryC    <-chan time.Time
	)
	defer func() {
		if retry != nil {
			retry.Stop()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case f := <-failures:
			if f.gen != gen {
				continue // from watches that were already restarted
			}
			what := f.err.Error()
			if f.t.Path != "" {
				what = "watch " + f.t.Path + ": " + what
			}
			if retryC == nil {
				since := time.Duration(1<<62 - 1)
				if !lastRetry.IsZero() {
					since = time.Since(lastRetry)
				}
				backoff = nextWatchBackoff(backoff, since)
				retry = time.NewTimer(backoff)
				retryC = retry.C
			}
			log("WARN", fmt.Sprintf("wfp: directory watch failed: %s (retry in %s; periodic rescan continues)", what, backoff))
			continue
		case <-retryC:
			retryC, retry = nil, nil
			lastRetry = time.Now()
			start(load())
			notify() // events may have been missed while not watching
			continue
		case <-changed:
			d := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				d.Stop()
				return
			case <-d.C:
			}
			select {
			case <-changed:
			default:
			}
		case <-t.C:
			t.Reset(refresh)
		}
		if ts := load(); !equalTargets(ts, cur) {
			start(ts)
			notify()
		}
	}
}
