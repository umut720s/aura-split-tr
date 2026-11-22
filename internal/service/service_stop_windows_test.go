//go:build windows

package service

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

// If run does not return within the stop wait, Execute logs the timeout
// but reports exit code 0: the stop was requested, and a non-zero code
// would make the SCM run the failure actions (restart the service, for
// example right after `disable` removed the policy).
func TestExecuteStopTimeoutIsNotAFailure(t *testing.T) {
	oldStop, oldReport := stopTimeout, reportStopTimeout
	stopTimeout = 2100 * time.Millisecond // waits stopTimeout-2s = 100ms
	var reported atomic.Int32
	reportStopTimeout = func() { reported.Add(1) }
	t.Cleanup(func() { stopTimeout, reportStopTimeout = oldStop, oldReport })

	release := make(chan struct{})
	defer close(release)
	f := newFakeSCM()
	defer close(f.done)
	h := &handler{run: func(ctx context.Context) error { <-ctx.Done(); <-release; return nil }}
	res := runExecute(h, f)
	f.waitState(t, svc.Running)
	f.req <- svc.ChangeRequest{Cmd: svc.Stop}
	select {
	case r := <-res:
		if r.code != 0 || r.specific {
			t.Fatalf("Execute = %v, %d; want exit 0", r.specific, r.code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Execute did not return")
	}
	if reported.Load() != 1 {
		t.Fatalf("timeout reported %d times", reported.Load())
	}
}

// S-3 seam: a run failure before cancellation goes to reportRunError
// (not the real event log here) and run is retried after the delay.
func TestSuperviseLoopReportsAndRetries(t *testing.T) {
	old := reportRunError
	var reports atomic.Int32
	reportRunError = func(error, time.Duration) { reports.Add(1) }
	t.Cleanup(func() { reportRunError = old })
	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	done := make(chan error, 1)
	go func() {
		done <- superviseLoop(ctx, func(context.Context) error {
			if calls.Add(1) == 3 {
				cancel()
				return nil
			}
			return errors.New("tunnel failed")
		}, time.Millisecond)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("superviseLoop did not return")
	}
	if calls.Load() != 3 || reports.Load() != 2 {
		t.Fatalf("calls %d reports %d", calls.Load(), reports.Load())
	}
}

// ErrFatal ends the supervisor without a retry, and Execute then reports
// a failure exit code so the SCM recovery action restarts the process.
func TestFatalRunErrorExitsNonZero(t *testing.T) {
	oldReport, oldFatal := reportRunError, reportFatal
	var reports, fatals atomic.Int32
	reportRunError = func(error, time.Duration) { reports.Add(1) }
	reportFatal = func(error) { fatals.Add(1) }
	t.Cleanup(func() { reportRunError, reportFatal = oldReport, oldFatal })
	var calls atomic.Int32
	f := newFakeSCM()
	defer close(f.done)
	h := &handler{run: func(context.Context) error {
		calls.Add(1)
		return errors.Join(ErrFatal, errors.New("close did not finish"))
	}}
	res := runExecute(h, f)
	select {
	case r := <-res:
		if !r.specific || r.code == 0 {
			t.Fatalf("Execute = %v, %d; want a failure code", r.specific, r.code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Execute did not return")
	}
	if calls.Load() != 1 || reports.Load() != 0 || fatals.Load() != 1 {
		t.Fatalf("calls %d reports %d fatals %d", calls.Load(), reports.Load(), fatals.Load())
	}
}

func TestHasDependencies(t *testing.T) {
	if !hasDependencies([]string{"bfe", "Tcpip"}, []string{"BFE"}) {
		t.Fatal("case-insensitive match failed")
	}
	if !hasDependencies([]string{"+BFE"}, []string{"BFE"}) {
		t.Fatal("group prefix not accepted")
	}
	if hasDependencies(nil, []string{"BFE"}) || hasDependencies([]string{"nsi"}, Dependencies) {
		t.Fatal("missing dependency accepted")
	}
	found := false
	for _, d := range Dependencies {
		found = found || strings.EqualFold(d, "BFE")
	}
	if !found {
		t.Fatal("BFE is not a dependency")
	}
}

// S-11: event-log text carries no user names or line breaks.
func TestScrubEventText(t *testing.T) {
	in := "open C:\\Users\\Some Name\\AppData\\x: denied\r\nnext \\\\?\\D:\\Users\\other\\y " + strings.Repeat("a", 2000)
	out := ScrubEventText(in)
	if strings.Contains(out, "Some Name") || strings.Contains(out, "other") || strings.ContainsAny(out, "\r\n") {
		t.Fatalf("not scrubbed: %q", out[:120])
	}
	if len(out) > 1010 {
		t.Fatalf("not truncated: %d", len(out))
	}
}
