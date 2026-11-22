package wfp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakePolicy records the calls Guard makes and models the persistent set
// (add-only keeps, authoritative replaces).
type fakePolicy struct {
	mu         sync.Mutex
	events     []string
	applyErr   error
	permitErr  error
	unresolved map[string]bool // paths whose app ID fails (exist on disk)
	set        []string
	n          int
}

func (p *fakePolicy) add(e string) { p.events = append(p.events, e) }

func (p *fakePolicy) Apply(paths []string, mode ApplyMode) (ApplyResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.add(fmt.Sprintf("apply %d %s", len(paths), mode))
	if p.applyErr != nil {
		return ApplyResult{}, p.applyErr
	}
	var ok, bad []string
	for _, q := range paths {
		if p.unresolved[q] {
			bad = append(bad, q)
		} else {
			ok = append(ok, q)
		}
	}
	if mode == Authoritative && len(bad) == 0 {
		p.set = normalizePaths(ok)
	} else {
		p.set = normalizePaths(append(p.set, ok...))
	}
	res := ApplyResult{Covered: p.set, Unresolved: bad, Pruned: mode == Authoritative && len(bad) == 0}
	if len(bad) > 0 {
		return res, &IncompleteError{Unresolved: bad, Err: errors.New("app ID")}
	}
	return res, nil
}

type fakePermit struct {
	p     *fakePolicy
	name  string
	paths []string
}

func (c *fakePermit) Paths() []string { return c.paths }

func (c *fakePermit) Close() error {
	c.p.mu.Lock()
	defer c.p.mu.Unlock()
	c.p.add("close " + c.name)
	return nil
}

func (p *fakePolicy) PermitOnTunnel(luid uint64, paths []string) (Permit, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.permitErr != nil {
		p.add("permit failed")
		return nil, p.permitErr
	}
	p.n++
	name := fmt.Sprintf("permit#%d", p.n)
	var ok, bad []string
	for _, q := range paths {
		if p.unresolved[q] {
			bad = append(bad, q)
		} else {
			ok = append(ok, q)
		}
	}
	p.add(fmt.Sprintf("open %s luid=%d apps=%d", name, luid, len(ok)))
	c := &fakePermit{p: p, name: name, paths: ok}
	if len(bad) > 0 {
		return c, &IncompleteError{Unresolved: bad, Err: errors.New("app ID")}
	}
	return c, nil
}

func (p *fakePolicy) RemoveAll() error                  { p.add("remove all"); return nil }
func (p *fakePolicy) Installed() (bool, int, error)     { return len(p.set) > 0, len(p.set), nil }
func (p *fakePolicy) Snapshot() (bool, []string, error) { return false, nil, nil }

func (p *fakePolicy) get() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return strings.Join(p.events, "|")
}

func (p *fakePolicy) reset() {
	p.mu.Lock()
	p.events = nil
	p.mu.Unlock()
}

func TestGuardReconcileOnlyOnChange(t *testing.T) {
	p := &fakePolicy{}
	found := []string{`C:\a\Update.exe`}
	var derr error
	g := NewGuard(p, func() ([]string, error) { return found, derr }, nil, nil)
	for i := 0; i < 3; i++ {
		if err := g.Reconcile(); err != nil {
			t.Fatal(err)
		}
	}
	if got := p.get(); got != "apply 1 authoritative" {
		t.Fatalf("events %q", got)
	}
	found = []string{`C:\A\UPDATE.EXE`} // case-only change is no change
	_ = g.Reconcile()
	if got := p.get(); got != "apply 1 authoritative" {
		t.Fatalf("events %q", got)
	}
	// A discovery error makes the pass add-only: nothing is dropped.
	p.reset()
	found, derr = []string{`C:\b\Update.exe`}, errors.New("access denied")
	if err := g.Reconcile(); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("Reconcile = %v", err)
	}
	if got := p.get(); got != "apply 1 add-only" || len(p.set) != 2 {
		t.Fatalf("events %q set %v", got, p.set)
	}
	if st := g.Status(); st.Complete || st.Apps != 2 || !strings.Contains(st.Incomplete, "access denied") {
		t.Fatalf("status %+v", st)
	}
	// Incomplete passes are retried even with an unchanged inventory.
	p.reset()
	_ = g.Reconcile()
	if got := p.get(); got != "apply 1 add-only" {
		t.Fatalf("incomplete pass not retried: %q", got)
	}
}

func TestGuardApplyFailureIsRetried(t *testing.T) {
	p := &fakePolicy{applyErr: errors.New("bfe down")}
	var last Status
	g := NewGuard(p, func() ([]string, error) { return []string{`C:\a\Update.exe`}, nil }, nil, func(s Status) { last = s })
	if err := g.Reconcile(); err == nil {
		t.Fatal("expected error")
	}
	if last.Applied || last.Err == "" || last.Complete {
		t.Fatalf("status %+v", last)
	}
	p.applyErr = nil
	if err := g.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if !last.Applied || last.Err != "" || last.Apps != 1 || !last.Complete {
		t.Fatalf("status %+v", last)
	}
}

// Unresolved app IDs: reported as incomplete, never counted as covered,
// and retried every reconcile although the inventory is unchanged.
func TestGuardUnresolvedRetried(t *testing.T) {
	a, c := `C:\a\Update.exe`, `C:\a\app-1\Discord.exe`
	p := &fakePolicy{unresolved: map[string]bool{c: true}}
	g := NewGuard(p, func() ([]string, error) { return []string{a, c}, nil }, nil, nil)
	if err := g.Reconcile(); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("Reconcile = %v", err)
	}
	st := g.Status()
	if st.Complete || st.Unresolved != 1 || st.Apps != 1 {
		t.Fatalf("status %+v", st)
	}
	p.reset()
	p.unresolved = nil
	if err := g.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := p.get(); got != "apply 2 authoritative" {
		t.Fatalf("events %q", got)
	}
	if st := g.Status(); !st.Complete || st.Apps != 2 || st.Unresolved != 0 {
		t.Fatalf("status %+v", st)
	}
}

// The permit is only opened after TunnelUp (the engine calls it after the
// tunnel started), and closing the handle closes it.
func TestGuardTunnelPermitLifecycle(t *testing.T) {
	p := &fakePolicy{}
	g := NewGuard(p, func() ([]string, error) { return []string{`C:\a\Update.exe`}, nil }, nil, nil)
	if err := g.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p.get(), "open") {
		t.Fatal("permit opened before the tunnel is up")
	}
	h, err := g.TunnelUp(7)
	if err != nil {
		t.Fatal(err)
	}
	if st := g.Status(); !st.Permit || !st.PermitComplete || st.PermitApps != 1 {
		t.Fatalf("status %+v", st)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	_ = h.Close() // idempotent
	if got := p.get(); got != "apply 1 authoritative|open permit#1 luid=7 apps=1|close permit#1" {
		t.Fatalf("events %q", got)
	}
	if g.Status().Permit {
		t.Fatal("permit still shown after close")
	}
	if _, err := g.TunnelUp(0); err == nil {
		t.Fatal("zero LUID accepted")
	}
}

// When the set grows while the tunnel is up, the new permit is opened
// before the blocks change and the old permit is closed afterwards.
func TestGuardPermitSwapOrder(t *testing.T) {
	p := &fakePolicy{}
	found := []string{`C:\a\Update.exe`}
	g := NewGuard(p, func() ([]string, error) { return found, nil }, nil, nil)
	_ = g.Reconcile()
	h, err := g.TunnelUp(9)
	if err != nil {
		t.Fatal(err)
	}
	p.reset()
	found = []string{`C:\a\Update.exe`, `C:\a\app-2\Discord.exe`}
	if err := g.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := p.get(); got != "open permit#2 luid=9 apps=2|close permit#1|apply 2 authoritative" {
		t.Fatalf("events %q", got)
	}
	p.reset()
	_ = h.Close()
	if got := p.get(); got != "close permit#2" {
		t.Fatalf("events %q", got)
	}
}

// A failed permit extension is retried by the next reconcile although the
// inventory did not change, and the status never claims a complete permit
// meanwhile.
func TestGuardPermitFailureRetried(t *testing.T) {
	p := &fakePolicy{}
	found := []string{`C:\a\Update.exe`}
	g := NewGuard(p, func() ([]string, error) { return found, nil }, nil, nil)
	_ = g.Reconcile()
	h, err := g.TunnelUp(4)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	p.permitErr = errors.New("no session")
	found = []string{`C:\a\Update.exe`, `C:\a\app-2\Discord.exe`}
	_ = g.Reconcile()
	st := g.Status()
	if !st.Permit || st.PermitComplete || st.PermitApps != 1 || st.Apps != 2 {
		t.Fatalf("status after failed extension %+v", st)
	}
	if g.healthy() {
		t.Fatal("guard reports healthy with a missing permit")
	}
	p.permitErr = nil
	p.reset()
	if err := g.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := p.get(); !strings.Contains(got, "open permit#2 luid=4 apps=2") || !strings.Contains(got, "close permit#1") {
		t.Fatalf("permit not retried: %q", got)
	}
	if st := g.Status(); !st.PermitComplete || st.PermitApps != 2 {
		t.Fatalf("status %+v", st)
	}
}

// Without an applied policy TunnelUp opens no permit; the next successful
// reconcile adds it.
func TestGuardTunnelUpBeforeApply(t *testing.T) {
	p := &fakePolicy{applyErr: errors.New("bfe down")}
	g := NewGuard(p, func() ([]string, error) { return []string{`C:\a\Update.exe`}, nil }, nil, nil)
	_ = g.Reconcile()
	h, err := g.TunnelUp(3)
	if err != nil {
		t.Fatal(err)
	}
	p.applyErr = nil
	p.reset()
	if err := g.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := p.get(); got != "apply 1 authoritative|open permit#1 luid=3 apps=1" {
		t.Fatalf("events %q", got)
	}
	_ = h.Close()
}

// A complete permit failure on TunnelUp is returned (the engine then
// treats the tunnel start as failed and keeps Discord blocked).
func TestGuardTunnelUpPermitFailure(t *testing.T) {
	p := &fakePolicy{}
	g := NewGuard(p, func() ([]string, error) { return []string{`C:\a\Update.exe`}, nil }, nil, nil)
	_ = g.Reconcile()
	p.permitErr = errors.New("no session")
	if _, err := g.TunnelUp(5); err == nil {
		t.Fatal("expected error")
	}
	if g.Status().Permit {
		t.Fatal("permit shown after failure")
	}
}

// Run reconciles shortly after a watcher kick, well before the interval.
func TestGuardRunKick(t *testing.T) {
	p := &fakePolicy{}
	found := []string{`C:\a\Update.exe`}
	var mu sync.Mutex
	g := NewGuard(p, func() ([]string, error) { mu.Lock(); defer mu.Unlock(); return found, nil }, nil, nil)
	_ = g.Reconcile()
	kick := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { g.Run(ctx, time.Hour, kick); close(done) }()
	mu.Lock()
	found = []string{`C:\a\Update.exe`, `C:\a\app-2\Discord.exe`}
	mu.Unlock()
	kick <- struct{}{}
	deadline := time.Now().Add(3 * time.Second)
	for g.Status().Apps != 2 {
		if time.Now().After(deadline) {
			t.Fatalf("kick did not reconcile: %q", p.get())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}

// A permits, then B is added while A's app ID fails transiently: the
// partial replacement (B only) must not retire the session that permits
// A. Both stay open (status incomplete) until a complete replacement
// exists, which then retires both.
func TestGuardPartialPermitKeepsOldSession(t *testing.T) {
	a, b := `C:\a\Update.exe`, `C:\a\app-2\Discord.exe`
	p := &fakePolicy{unresolved: map[string]bool{}}
	found := []string{a}
	g := NewGuard(p, func() ([]string, error) { return found, nil }, nil, nil)
	if err := g.Reconcile(); err != nil {
		t.Fatal(err)
	}
	h, err := g.TunnelUp(6)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	p.reset()
	p.unresolved[a] = true
	found = []string{a, b}
	_ = g.Reconcile()
	ev := p.get()
	if strings.Contains(ev, "close permit#1") {
		t.Fatalf("old permit covering A closed by a partial replacement: %q", ev)
	}
	st := g.Status()
	if !st.Permit || st.PermitComplete || st.PermitSessions != 2 || st.PermitApps != 2 {
		t.Fatalf("status %+v", st)
	}
	if g.healthy() {
		t.Fatal("healthy with a split permit")
	}
	// Retries while A still fails never close permit#1 and never exceed
	// the session bound.
	for i := 0; i < 3; i++ {
		_ = g.Reconcile()
		if strings.Contains(p.get(), "close permit#1") {
			t.Fatalf("permit#1 closed while A unresolved: %q", p.get())
		}
		if st := g.Status(); st.PermitSessions > MaxPermitSessions || st.PermitApps != 2 {
			t.Fatalf("status %+v", st)
		}
	}
	// A resolves again: one complete session replaces both.
	p.unresolved[a] = false
	p.reset()
	if err := g.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if ev := p.get(); strings.Count(ev, "close permit#") != 2 || !strings.Contains(ev, "close permit#1") {
		t.Fatalf("old sessions not retired: %q", ev)
	}
	if st := g.Status(); !st.PermitComplete || st.PermitSessions != 1 || st.PermitApps != 2 {
		t.Fatalf("status %+v", st)
	}
}

// When a new session could not retire any old one, the bound keeps the
// old sessions and closes the new one: the new executable stays blocked
// (fail-closed) and the permit is reported incomplete.
func TestGuardPermitSessionBound(t *testing.T) {
	a, b, c := `C:\a\Update.exe`, `C:\a\app-2\Discord.exe`, `C:\a\app-3\Discord.exe`
	p := &fakePolicy{unresolved: map[string]bool{}}
	found := []string{a}
	g := NewGuard(p, func() ([]string, error) { return found, nil }, nil, nil)
	_ = g.Reconcile()
	h, err := g.TunnelUp(6)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	p.unresolved[a] = true
	found = []string{a, b}
	_ = g.Reconcile() // permit#1 (A) + a session for B
	if st := g.Status(); st.PermitSessions != 2 {
		t.Fatalf("status %+v", st)
	}
	p.unresolved[b] = true
	found = []string{a, b, c}
	p.reset()
	_ = g.Reconcile()
	st := g.Status()
	if st.PermitSessions != 2 || st.PermitComplete || st.PermitApps != 2 {
		t.Fatalf("status %+v", st)
	}
	if strings.Contains(p.get(), "close permit#1") {
		t.Fatalf("permit#1 closed: %q", p.get())
	}
}
