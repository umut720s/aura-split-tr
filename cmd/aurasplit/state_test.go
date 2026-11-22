//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"aurasplit/internal/engine"
	"aurasplit/internal/testutil"
)

func TestStateValid(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	start := now.Add(-time.Hour)
	good := tunnelState{State: string(engine.StateTunnelStarted), PID: 1234, ProcessStart: start, Heartbeat: now.Add(-20 * time.Second)}
	same := func(uint32) (time.Time, bool) { return start, true }
	unreadable := func(uint32) (time.Time, bool) { return time.Time{}, false }
	reused := func(uint32) (time.Time, bool) { return now.Add(-time.Minute), true }

	if !stateValid(good, 1234, now, same) || !stateValid(good, 1234, now, unreadable) {
		t.Fatal("fresh state of the current service process rejected")
	}
	stale := good
	stale.Heartbeat = now.Add(-heartbeatMaxAge)
	future := good
	future.Heartbeat = now.Add(2 * heartbeatMaxAge)
	noStart := good
	noStart.ProcessStart = time.Time{}
	for name, c := range map[string]struct {
		ts  tunnelState
		pid uint32
		ps  func(uint32) (time.Time, bool)
	}{
		"other pid":        {good, 99, same},
		"not running":      {good, 0, same},
		"stale heartbeat":  {stale, 1234, same},
		"future heartbeat": {future, 1234, same},
		"pid reused":       {good, 1234, reused},
		"old format":       {noStart, 1234, same},
	} {
		if stateValid(c.ts, c.pid, now, c.ps) {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A failed state write is logged once (not on every heartbeat), and the
// recovery is logged too.
func TestStateWriterLogsFailures(t *testing.T) {
	var log bytes.Buffer
	var mu sync.Mutex
	fail := true
	var written []byte
	w := &stateWriter{
		cur: tunnelState{PID: 42, ProcessStart: time.Now()},
		log: &log,
		write: func(_ string, data []byte) error {
			mu.Lock()
			defer mu.Unlock()
			if fail {
				return errors.New("access denied")
			}
			written = append([]byte(nil), data...)
			return nil
		},
		logDegraded: func() bool { return true },
	}
	w.set(engine.StateStarting, "")
	w.heartbeat()
	w.heartbeat()
	if n := strings.Count(log.String(), "cannot write tunnel state"); n != 1 {
		t.Fatalf("failure logged %d times: %q", n, log.String())
	}
	fail = false
	w.set(engine.StateTunnelStarted, `open C:\Users\Some Name\x`)
	if !strings.Contains(log.String(), "written again") {
		t.Fatalf("recovery not logged: %q", log.String())
	}
	var ts tunnelState
	if err := json.Unmarshal(written, &ts); err != nil {
		t.Fatal(err)
	}
	if ts.State != string(engine.StateTunnelStarted) || ts.PID != 42 || ts.Heartbeat.IsZero() ||
		!ts.LogDegraded || strings.Contains(ts.Detail, "Some Name") {
		t.Fatalf("state record %+v", ts)
	}
}

// "Running from the installed copy" (setup) is decided by file identity.
func TestSameFileAsImage(t *testing.T) {
	f, err := openSelfImage()
	if err != nil {
		t.Fatal(err)
	}
	old := selfImage
	selfImage = f
	t.Cleanup(func() { f.Close(); selfImage = old })

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if same, err := sameFileAsImage(exe); err != nil || !same {
		t.Fatalf("running image not recognised: %v %v", same, err)
	}
	// Identity is decided by volume serial and file index, never by
	// content, so the "copy" need not contain the PE bytes. Writing a full
	// copy of the test executable into %TEMP% made an on-access scanner
	// hold it delete-pending and broke the TempDir cleanup (audit F-1).
	tmp := testutil.TempDir(t)
	copyPath := filepath.Join(tmp, "aurasplit.exe")
	if err := os.WriteFile(copyPath, []byte("not the running image"), 0o600); err != nil {
		t.Fatal(err)
	}
	if same, err := sameFileAsImage(copyPath); err != nil || same {
		t.Fatalf("other file treated as the running image: %v %v", same, err)
	}
	if same, err := sameFileAsImage(filepath.Join(tmp, "missing.exe")); err != nil || same {
		t.Fatalf("missing file: %v %v", same, err)
	}
}
