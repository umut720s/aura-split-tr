package wfp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func touch(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func rel(base string, ps []string) []string {
	var out []string
	for _, p := range ps {
		r, _ := filepath.Rel(base, p)
		out = append(out, filepath.ToSlash(r))
	}
	sort.Strings(out)
	return out
}

func TestDiscoverIn(t *testing.T) {
	base := t.TempDir()
	u1 := filepath.Join(base, "u1")
	u2 := filepath.Join(base, "u2")
	local := filepath.Join(u1, "AppData", "Local")
	touch(t, filepath.Join(local, "Discord", "Update.exe"))
	touch(t, filepath.Join(local, "Discord", "app-1.0.9010", "Discord.exe"))
	touch(t, filepath.Join(local, "Discord", "app-1.0.9010", "notes.txt"))
	touch(t, filepath.Join(local, "Discord", "app-1.0.9010", "modules", "Discord.exe")) // not directly inside
	touch(t, filepath.Join(local, "DiscordPTB", "app-1.0.1", "DiscordPTB.exe"))
	touch(t, filepath.Join(local, "Other", "Update.exe"))
	touch(t, filepath.Join(u2, "AppData", "Local", "DiscordCanary", "Update.exe"))
	if err := os.MkdirAll(filepath.Join(local, "Discord", "packages"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := DiscoverIn([]string{u1, u2, filepath.Join(base, "missing"), "relative"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"u1/AppData/Local/Discord/Update.exe",
		"u1/AppData/Local/Discord/app-1.0.9010/Discord.exe",
		"u1/AppData/Local/DiscordPTB/app-1.0.1/DiscordPTB.exe",
		"u2/AppData/Local/DiscordCanary/Update.exe",
	}
	sort.Strings(want)
	if g := rel(base, got); strings.Join(g, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v\nwant %v", g, want)
	}
}

// Every installed version is discovered (an older one may still run);
// there is no per-install version cap any more.
func TestDiscoverInCoversEveryVersion(t *testing.T) {
	base := t.TempDir()
	inst := filepath.Join(base, "u", "AppData", "Local", "Discord")
	const versions = 9
	for i := 1; i <= versions; i++ {
		touch(t, filepath.Join(inst, fmt.Sprintf("app-1.0.%d", i), "Discord.exe"))
	}
	got, err := DiscoverIn([]string{filepath.Join(base, "u")})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != versions {
		t.Fatalf("got %d paths, want %d: %v", len(got), versions, got)
	}
	if !strings.Contains(got[0], fmt.Sprintf("app-1.0.%d", versions)) {
		t.Fatalf("newest version not first: %v", got)
	}
}

// Hitting a cap is reported (the pass becomes add-only), never silent.
func TestDiscoverInCapIsReported(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "u", "AppData", "Local", "SquirrelTemp")
	for i := 0; i <= MaxExesPerDir; i++ {
		touch(t, filepath.Join(dir, fmt.Sprintf("DiscordSetup%02d.exe", i)))
	}
	got, err := DiscoverIn([]string{filepath.Join(base, "u")})
	if !errors.Is(err, ErrCapReached) {
		t.Fatalf("cap not reported: %v", err)
	}
	if len(got) != MaxExesPerDir {
		t.Fatalf("got %d", len(got))
	}
	many := make([]string, MaxProfiles+1)
	for i := range many {
		many[i] = filepath.Join(base, fmt.Sprintf("p%d", i))
	}
	if _, err := DiscoverIn(many); !errors.Is(err, ErrCapReached) {
		t.Fatalf("profile cap not reported: %v", err)
	}
}

func TestWatchTargetsIn(t *testing.T) {
	base := t.TempDir()
	u := filepath.Join(base, "u")
	touch(t, filepath.Join(u, "AppData", "Local", "Discord", "Update.exe"))
	touch(t, filepath.Join(u, "AppData", "Local", "DiscordPTB", "x"))
	got := WatchTargetsIn([]string{u, filepath.Join(base, "missing"), "relative"})
	want := []WatchTarget{
		{Path: filepath.Join(u, "AppData", "Local")},
		{Path: filepath.Join(u, "AppData", "Local", "Discord"), Subtree: true},
		{Path: filepath.Join(u, "AppData", "Local", "DiscordPTB"), Subtree: true},
	}
	if !equalTargets(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

// RunWatcher restarts the OS watch when the target list changes and
// forwards events (fake OS watcher).
func TestRunWatcherRefreshesTargets(t *testing.T) {
	var mu sync.Mutex
	targets := []WatchTarget{{Path: `C:\u\AppData\Local`}}
	starts := make(chan []WatchTarget, 8)
	events := make(chan func(), 8)
	old := watchFn
	t.Cleanup(func() { watchFn = old })
	watchFn = func(ctx context.Context, ts []WatchTarget, notify func(), _ func(WatchTarget, error)) error {
		starts <- ts
		events <- notify
		<-ctx.Done()
		return nil
	}
	notified := make(chan struct{}, 16)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		RunWatcher(ctx, func() ([]WatchTarget, error) {
			mu.Lock()
			defer mu.Unlock()
			return append([]WatchTarget(nil), targets...), nil
		}, time.Hour, func() {
			select {
			case notified <- struct{}{}:
			default:
			}
		}, nil)
		close(done)
	}()
	wait := func(what string, ch <-chan []WatchTarget) []WatchTarget {
		t.Helper()
		select {
		case ts := <-ch:
			return ts
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for " + what)
		}
		return nil
	}
	if ts := wait("first watch", starts); len(ts) != 1 {
		t.Fatalf("targets %v", ts)
	}
	notify := <-events
	// A new install directory appears: the event is forwarded and the
	// target list is re-read about a second later.
	mu.Lock()
	targets = append(targets, WatchTarget{Path: `C:\u\AppData\Local\Discord`, Subtree: true})
	mu.Unlock()
	notify()
	select {
	case <-notified:
	case <-time.After(5 * time.Second):
		t.Fatal("event not forwarded")
	}
	if ts := wait("restarted watch", starts); len(ts) != 2 {
		t.Fatalf("targets %v", ts)
	}
	cancel()
	<-done
}

func TestDiscoverInRejectsLinks(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "elsewhere")
	touch(t, filepath.Join(real, "Update.exe"))
	local := filepath.Join(base, "u", "AppData", "Local")
	if err := os.MkdirAll(local, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(local, "Discord")); err != nil {
		t.Skip("cannot create a symbolic link here (needs privilege or developer mode):", err)
	}
	got, err := DiscoverIn([]string{filepath.Join(base, "u")})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("followed a link: %v", got)
	}
}

func TestVersionLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"app-1.0.9", "app-1.0.10", true},
		{"app-1.0.10", "app-1.0.9", false},
		{"app-1.0", "app-1.0.1", true},
		{"APP-2.0.0", "app-10.0.0", true},
	}
	for _, c := range cases {
		if got := versionLess(c.a, c.b); got != c.want {
			t.Errorf("versionLess(%s,%s)=%v", c.a, c.b, got)
		}
	}
}

func TestNormalizePaths(t *testing.T) {
	got := normalizePaths([]string{`C:\b`, `c:\B`, "", `C:\a`})
	if strings.Join(got, ",") != `C:\a,C:\b` {
		t.Fatalf("%v", got)
	}
}

// The per-profile cap is reported and does not starve other profiles.
func TestDiscoverInPerProfileCap(t *testing.T) {
	base := t.TempDir()
	inst := filepath.Join(base, "u1", "AppData", "Local", "Discord")
	for i := 0; i <= MaxPathsPerProfile; i++ {
		touch(t, filepath.Join(inst, fmt.Sprintf("app-1.0.%d", i), "Discord.exe"))
	}
	touch(t, filepath.Join(base, "u2", "AppData", "Local", "Discord", "Update.exe"))
	got, err := DiscoverIn([]string{filepath.Join(base, "u1"), filepath.Join(base, "u2")})
	if !errors.Is(err, ErrCapReached) {
		t.Fatalf("per-profile cap not reported: %v", err)
	}
	if len(got) != MaxPathsPerProfile+1 {
		t.Fatalf("got %d paths", len(got))
	}
	if got[len(got)-1] != filepath.Join(base, "u2", "AppData", "Local", "Discord", "Update.exe") {
		t.Fatalf("other profile starved: %v", got[len(got)-1])
	}
}
