//go:build windows

package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"aurasplit/internal/engine"
	"aurasplit/internal/paths"
	"aurasplit/internal/service"
)

// The heartbeat goroutine must exit promptly when its context ends (the
// service run function returns and closes the log right after).
func TestRunHeartbeatStopsOnCancel(t *testing.T) {
	var writes atomic.Int32
	w := &stateWriter{write: func(string, []byte) error { writes.Add(1); return nil }}
	w.set(engine.StateStarting, "")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.runHeartbeat(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runHeartbeat did not return after cancellation")
	}
	if n := writes.Load(); n != 1 {
		t.Fatalf("unexpected writes after cancel: %d", n)
	}
}

// Before any state was set, a heartbeat writes nothing (an empty record
// would be shown as an unknown state).
func TestHeartbeatBeforeFirstStateWritesNothing(t *testing.T) {
	called := false
	w := &stateWriter{write: func(string, []byte) error { called = true; return nil }}
	w.heartbeat()
	if called {
		t.Fatal("heartbeat wrote a record without a state")
	}
}

// Boundary cases of stateValid that the status command relies on.
func TestStateValidBoundaries(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	start := now.Add(-time.Hour)
	ts := tunnelState{State: string(engine.StateBlocking), PID: 7, ProcessStart: start}
	for name, c := range map[string]struct {
		hb    time.Time
		start time.Time
		want  bool
	}{
		"just fresh":             {now.Add(-heartbeatMaxAge + time.Second), start, true},
		"exactly max age":        {now.Add(-heartbeatMaxAge), start, false},
		"slightly in the future": {now.Add(heartbeatMaxAge - time.Second), start, true},
		"start within 1s":        {now, start.Add(900 * time.Millisecond), true},
		"start off by 2s":        {now, start.Add(2 * time.Second), false},
		"zero heartbeat":         {time.Time{}, start, false},
	} {
		s := ts
		s.Heartbeat = c.hb
		ps := func(uint32) (time.Time, bool) { return c.start, true }
		if got := stateValid(s, 7, now, ps); got != c.want {
			t.Errorf("%s: stateValid = %v, want %v", name, got, c.want)
		}
	}
	neg := ts
	neg.PID = -1
	neg.Heartbeat = now
	if stateValid(neg, 0xFFFFFFFF, now, func(uint32) (time.Time, bool) { return start, true }) {
		t.Error("negative PID accepted")
	}
}

// The uninstall log lines name what happened and never claim a removal
// that did not happen.
func TestDescribeCleanup(t *testing.T) {
	dir := `C:\ProgramData\AuraSplitTR`
	if l := describeCleanup(dir, paths.CleanResult{Missing: true}); len(l) != 1 || !strings.Contains(l[0], "yok") {
		t.Fatalf("missing: %v", l)
	}
	if l := describeCleanup(dir, paths.CleanResult{Removed: true, Deleted: []string{"profile.json"}}); len(l) != 1 || !strings.Contains(l[0], "silindi") {
		t.Fatalf("removed: %v", l)
	}
	l := strings.Join(describeCleanup(dir, paths.CleanResult{Kept: []string{"notes.txt: not an AURA Split TR file"}}), "|")
	if !strings.Contains(l, "elle incelenmek") || !strings.Contains(l, "notes.txt") || strings.Contains(l, "Veri klasörü silindi") {
		t.Fatalf("kept: %s", l)
	}
}

// recover with the msi flag (MSI custom action, Return="check"): 0 when
// nothing is installed or everything was removed; non-zero on any failure
// that could leave Discord blocked, so the uninstall rolls back.
func TestRunRecoverExitCodes(t *testing.T) {
	notInstalled := errors.New("The specified service does not exist as an installed service.")
	ok := func() error { return nil }
	none := func() (bool, int, error) { return false, 0, nil }
	cases := []struct {
		name string
		msi  bool
		ops  recoverOps
		want int
	}{
		{"nothing installed at all", true, recoverOps{func() error { return notInstalled }, func() error { return notInstalled }, ok, none}, 0},
		{"service stopped, policy removed", true, recoverOps{ok, func() error { return service.ErrNotRunning }, ok, none}, 0},
		{"policy removal fails", true, recoverOps{ok, ok, func() error { return errors.New("wfp: open engine: 1753") }, none}, 1},
		{"policy still present", true, recoverOps{ok, ok, ok, func() (bool, int, error) { return true, 2, nil }}, 1},
		{"service cannot be stopped (msi)", true, recoverOps{ok, func() error { return errors.New("timeout") }, ok, none}, 1},
		{"service cannot be stopped (interactive)", false, recoverOps{ok, func() error { return errors.New("timeout") }, ok, none}, 0},
		{"disable fails is only a warning", true, recoverOps{func() error { return errors.New("access denied") }, ok, ok, none}, 0},
	}
	for _, c := range cases {
		if got := runRecover(c.msi, c.ops); got != c.want {
			t.Errorf("%s: exit %d, want %d", c.name, got, c.want)
		}
	}
}

func TestIsNotInstalled(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("service does not exist: not installed (kurulu değil)"), true},
		{errors.New("open service: The specified service does not exist as an installed service. (1060)"), true},
		{errors.New("access denied"), false},
	} {
		if got := isNotInstalled(c.err); got != c.want {
			t.Errorf("isNotInstalled(%v) = %v", c.err, got)
		}
	}
}

// --msi is accepted only by the commands the MSI custom actions run (and
// uninstall); never by setup, which is interactive.
func TestCheckMSIFlag(t *testing.T) {
	for cmd, ok := range map[string]bool{
		"recover": true, "kurtar": true, "start": true, "baslat": true,
		"uninstall": true, "kaldir": true,
		"recover-rollback": true,
		"setup":            false, "": false, "disable": false, "stop": false, "run": false, "service": false,
	} {
		if err := checkMSIFlag(cmd); (err == nil) != ok {
			t.Errorf("checkMSIFlag(%q) = %v", cmd, err)
		}
	}
	args, msi := takeFlag([]string{"recover", "--MSI"}, msiFlag)
	if !msi || len(args) != 1 || args[0] != "recover" {
		t.Fatalf("takeFlag(--msi) = %v %v", args, msi)
	}
}

// After an MSI upgrade/repair the service is resumed only for a configured
// installation whose persistent policy is still installed.
func TestResumeDecision(t *testing.T) {
	for _, c := range []struct {
		name      string
		profile   error
		policy    bool
		policyErr error
		want      bool
	}{
		{"configured and protected", nil, true, nil, true},
		{"never configured", os.ErrNotExist, true, nil, false},
		{"disabled or recovered", nil, false, nil, false},
		{"profile unreadable", errors.New("access denied"), true, nil, false},
		{"wfp unreadable", nil, false, errors.New("bfe"), false},
	} {
		got, why := resumeDecision(c.profile, c.policy, c.policyErr)
		if got != c.want || why == "" {
			t.Errorf("%s: resumeDecision = %v %q, want %v", c.name, got, why, c.want)
		}
	}
}

// A service stuck in START_PENDING is explained, with the timeout, the
// antivirus hint and how to check, and without suggesting to weaken AV.
func TestStartPendingMessage(t *testing.T) {
	msg := startPendingMessage(30 * time.Second)
	for _, want := range []string{"30 sn", "START_PENDING", "Antivirüs programınız", "status", "Olay Görüntüleyicisi", "kapatmayın"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message lacks %q:\n%s", want, msg)
		}
	}
}

func TestSplitArgs(t *testing.T) {
	args, elevated := splitArgs([]string{"setup", elevatedFlag})
	if !elevated || len(args) != 1 || args[0] != "setup" {
		t.Fatalf("splitArgs = %v %v", args, elevated)
	}
	if _, elevated := splitArgs([]string{"status"}); elevated {
		t.Fatal("elevated without flag")
	}
}
