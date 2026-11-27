package wfp

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadinessRequiresEveryGate(t *testing.T) {
	p := &fakePolicy{}
	manifest := []string{`C:\Users\fixture\AppData\Local\Discord\app-1\Discord.exe`}
	g := NewGuard(p, func() ([]string, error) { return manifest, nil }, nil, nil)
	gate := false
	g.CheckOldFlows = func([]string) (bool, string) { return gate, "test" }
	if err := g.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if g.Status().Ready {
		t.Fatal("ready without TUN")
	}
	h, err := g.TunnelUp(1)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if g.Status().Ready {
		t.Fatal("ready with old processes")
	}
	gate = true
	_ = g.Reconcile()
	if !g.Status().Ready {
		t.Fatal("complete contract not ready")
	}
	p.verifyErr = errors.New("missing IPv6 layer")
	if err := g.Reconcile(); err == nil || g.Status().Ready || g.Status().Complete {
		t.Fatal("readback failure accepted")
	}
	if len(p.set) != 1 {
		t.Fatal("existing blocks lost")
	}
	p.verifyErr = nil
	_ = g.Reconcile()
	if !g.Status().Ready {
		t.Fatal("readback retry failed")
	}
}

func TestFourLayerReadback(t *testing.T) {
	b := newFake()
	f := &Firewall{b: b}
	paths := []string{`C:\Apps\Discord.exe`}
	if _, err := f.Apply(paths, AddOnly); err != nil {
		t.Fatal(err)
	}
	if err := f.Verify(paths); err != nil {
		t.Fatal(err)
	}
	for id, rec := range b.bfe.filters {
		if rec.f.Action == ActionBlock && rec.f.Layer == LayerRecvAcceptV6 {
			delete(b.bfe.filters, id)
		}
	}
	if err := f.Verify(paths); err == nil {
		t.Fatal("missing fourth layer accepted")
	}
}

func TestTrafficClasses(t *testing.T) {
	paths := []string{`C:\Users\fixture\AppData\Local\Discord\app-1\Discord.exe`, `C:\Users\fixture\AppData\Local\Discord\Update.exe`, `C:\Users\fixture\AppData\Local\Discord\app-1\updater_launcher.exe`, `C:\Users\fixture\AppData\Local\SquirrelTemp\DiscordSetup.exe`}
	for _, ready := range []bool{false, true} {
		classes := TrafficClasses(paths, ready, "pending")
		if len(classes) != 7 {
			t.Fatal(classes)
		}
		for i, c := range classes {
			want := "partial"
			if ready {
				want = "protected"
			}
			if i == 4 {
				want = "routed-not-fail-closed"
			}
			if i >= 5 {
				want = "not-covered"
			}
			if c.Coverage != want || c.Reason == "" {
				t.Fatal(c)
			}
		}
	}
}

func TestHelperAndInstallerManifest(t *testing.T) {
	u := t.TempDir()
	local := filepath.Join(u, "AppData", "Local")
	app := filepath.Join(local, "Discord", "app-1")
	for _, p := range []string{"Discord.exe", "updater_launcher.exe", "modules/discord_utils-1/discord_utils/DiscordSystemHelper.exe", "modules/discord_voice-1/discord_voice/audio_effects_helper.exe", "modules/discord_voice-1/discord_voice/gpu_encoder_helper.exe", "modules/other-1/other/extra.exe"} {
		touch(t, filepath.Join(app, filepath.FromSlash(p)))
	}
	touch(t, filepath.Join(local, "SquirrelTemp", "DiscordSetup1.exe"))
	touch(t, filepath.Join(local, "Discord", "DiscordPTBSetup.exe"))
	touch(t, filepath.Join(app, "modules", "other-1", "other", "deeper", "ignored.exe"))
	got, err := DiscoverIn([]string{u})
	if err != nil || len(got) != 8 {
		t.Fatalf("%v %v", got, err)
	}
	for i := 0; i <= MaxExesPerDir; i++ {
		touch(t, filepath.Join(local, "SquirrelTemp", fmt.Sprintf("DiscordSetup%d.exe", i)))
	}
	if _, err := DiscoverIn([]string{u}); !errors.Is(err, ErrCapReached) {
		t.Fatal("cap not reported", err)
	}
}

func TestModuleReparseExcluded(t *testing.T) {
	u := t.TempDir()
	app := filepath.Join(u, "AppData", "Local", "Discord", "app-1")
	touch(t, filepath.Join(app, "Discord.exe"))
	real := filepath.Join(t.TempDir(), "discord_voice")
	touch(t, filepath.Join(real, "audio_effects_helper.exe"))
	mod := filepath.Join(app, "modules", "discord_voice-1")
	if err := os.MkdirAll(mod, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(mod, "discord_voice")); err != nil {
		t.Skip("symlink privilege unavailable")
	}
	got, err := DiscoverIn([]string{u})
	if err != nil || len(got) != 1 {
		t.Fatalf("reparse helper enrolled: %v %v", got, err)
	}
}

func TestHelperBudgetRetainsExisting(t *testing.T) {
	b := newBudget()
	root := `C:\Users\test\AppData\Local\Discord\app-1\`
	for i := 0; i < MaxPolicyAppsPerProfile; i++ {
		if !b.take(fmt.Sprintf("%shelper%d.exe", root, i)) {
			t.Fatal("budget exhausted early")
		}
	}
	if b.take(root + "updater_launcher.exe") {
		t.Fatal("overflow admitted")
	}
	if b.total != MaxPolicyAppsPerProfile {
		t.Fatal("existing entries evicted")
	}
}

func TestCanonicalPermitsRetainLegacyBlocks(t *testing.T) {
	canonical := `C:\Users\fixture\AppData\Local\Discord\app-1\Discord.exe`
	legacy := `C:\Users\fixture\AppData\Local\DiscordCustom\app-1\utility.exe`
	p := &fakePolicy{set: []string{canonical, legacy}}
	old := &fakePermit{p: p, name: "legacy", paths: []string{canonical, legacy}}
	g := NewGuard(p, nil, nil, nil)
	g.applied, g.tunnel, g.luid = true, true, 1
	g.covered = []string{canonical, legacy}
	g.permits = []Permit{old}
	g.syncPermitLocked(g.covered)
	if got := g.permitPathsLocked(); len(got) != 1 || !strings.EqualFold(got[0], canonical) {
		t.Fatal(got)
	}
	if len(p.set) != 2 || !strings.Contains(p.get(), "close legacy") {
		t.Fatal("legacy blocks removed or permit retained", p.get())
	}
	// A failed close must stay visible and must never grant readiness.
	g.permits = []Permit{old}
	old.closeErr = errors.New("close unavailable")
	g.syncPermitLocked(g.covered)
	if len(g.permits) != 1 || !g.permitDirty || g.lastErr == "" || g.Status().Ready {
		t.Fatal("failed close hidden or accepted")
	}
	old.closeErr = nil
	// Narrowing must close an unsafe old session even if replacement fails.
	g.permits = []Permit{old}
	p.permitErr = errors.New("unavailable")
	g.syncPermitLocked(g.covered)
	if len(g.permits) != 0 || len(p.set) != 2 {
		t.Fatal("unsafe permit survived failure")
	}
	p.permitErr = nil
	g.complete = true
	h, err := g.TunnelUp(1)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if got := g.permitPathsLocked(); len(got) != 1 || !strings.EqualFold(got[0], canonical) {
		t.Fatal("TunnelUp widened permits", got)
	}
}

type repairPolicy struct {
	fakePolicy
	lost bool
}

func (p *repairPolicy) Verify([]string) error {
	if p.lost {
		p.lost = false
		return errors.New("retired policy")
	}
	return nil
}
func TestReadbackLossRetiresGenerationBeforeRepair(t *testing.T) {
	exe := `C:\Users\fixture\AppData\Local\Discord\app-1\Discord.exe`
	p := &repairPolicy{}
	g := NewGuard(p, func() ([]string, error) { return []string{exe}, nil }, nil, nil)
	var calls [][]string
	g.CheckOldFlows = func(paths []string) (bool, string) { calls = append(calls, paths); return len(paths) > 0, "test" }
	if err := g.Reconcile(); err != nil {
		t.Fatal(err)
	}
	calls = nil
	p.lost = true
	if err := g.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || len(calls[0]) != 0 || len(calls[1]) != 1 {
		t.Fatal("generation not retired before repaired enrollment", calls)
	}
	calls = nil
	g.ReportFailure("recovery")
	if len(calls) != 1 || len(calls[0]) != 0 {
		t.Fatal("recovery retained cutoff", calls)
	}
}

// Compile-only on the development host: exercises real sessionPermit ownership
// over fake BFE, without calling the native Windows backend.
func TestFailedLegacySessionClosureRetriedBeforeReady(t *testing.T) {
	canonical := `C:\Users\fixture\AppData\Local\Discord\app-1\Discord.exe`
	legacy := `C:\Users\fixture\AppData\Local\DiscordCustom\app-1\utility.exe`
	b := newFake()
	f := &Firewall{b: b, lstat: existsAll}
	if _, err := f.Apply([]string{canonical, legacy}, AddOnly); err != nil {
		t.Fatal(err)
	}
	p, err := f.PermitOnTunnel(1, []string{canonical, legacy})
	if err != nil {
		t.Fatal(err)
	}
	owned := p.(*sessionPermit)
	s := owned.s.(*fakeSession)
	s.closeErr = errors.New("injected close failure")
	g := NewGuard(f, func() ([]string, error) { return []string{canonical}, nil }, nil, nil)
	g.CheckOldFlows = func([]string) (bool, string) { return true, "test gate" }
	g.applied, g.tunnel, g.luid = true, true, 1
	g.covered, g.permits = []string{canonical, legacy}, []Permit{p}
	for i := 0; i < 2; i++ {
		calls := s.closeCalls
		if err := g.Reconcile(); err != nil {
			t.Fatal(err)
		}
		st := g.Status()
		if owned.s != s || s.closed || s.closeCalls <= calls || len(g.permits) != 1 || g.permits[0] != p || !st.PendingPermitClosure || st.Ready || st.PermitComplete || !strings.Contains(st.Err, "closure pending") {
			t.Fatalf("failed close lost or readiness granted: %+v", st)
		}
		if b.bfe.count(func(f Filter) bool { return f.Action == ActionPermit && f.Path == legacy }) == 0 {
			t.Fatal("fake did not retain legacy permits")
		}
	}
	s.closeErr = nil
	if err := g.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if st := g.Status(); owned.s != nil || !s.closed || st.PendingPermitClosure || !st.Ready {
		t.Fatalf("closure retry failed: %+v", st)
	}
	if b.bfe.count(func(f Filter) bool { return f.Action == ActionPermit && f.Path == legacy }) != 0 {
		t.Fatal("legacy permit survived closure")
	}
	if b.bfe.count(func(f Filter) bool { return f.Persistent && f.Path == legacy }) != len(Layers) {
		t.Fatal("legacy blocks removed")
	}
	_ = g.tunnelDown()
}

func TestFutureHelpersEnrolledWithoutManifestEligibility(t *testing.T) {
	base := t.TempDir()
	var unknown []string
	for _, root := range []string{"Discord", "DiscordPTB", "DiscordCanary", "DiscordDevelopment"} {
		app := filepath.Join(base, "AppData", "Local", root, "app-1")
		for _, suffix := range []string{"DiscordOther.exe", "modules/future-1/future/new_helper.EXE"} {
			p := filepath.Join(app, filepath.FromSlash(suffix))
			touch(t, p)
			unknown = append(unknown, p)
		}
	}
	got, err := DiscoverIn([]string{base})
	if err != nil || len(got) != len(unknown) {
		t.Fatal(got, err)
	}
	if len(canonicalPaths(got)) != 0 {
		t.Fatal("future helpers became canonical", got)
	}
	b := newFake()
	f := &Firewall{b: b}
	if _, err := f.Apply(got, Authoritative); err != nil {
		t.Fatal(err)
	}
	if err := f.Verify(unknown); err != nil {
		t.Fatal("future helpers lack persistent blocks", err)
	}
	classes := TrafficClasses(got, true, "")
	for _, c := range classes[:4] {
		if c.Coverage == "protected" {
			t.Fatal("unknown helper counted as verified manifest", c)
		}
	}
	if classes[4].Coverage != "routed-not-fail-closed" {
		t.Fatal(classes[4])
	}
	// Unknown names consume the same bounded discovery budget as known ones.
	for i := 0; i < MaxExesPerDir; i++ {
		touch(t, filepath.Join(base, "AppData", "Local", "Discord", "app-1", fmt.Sprintf("future%d.exe", i)))
	}
	if _, err := DiscoverIn([]string{base}); !errors.Is(err, ErrCapReached) {
		t.Fatal("future helpers bypassed discovery cap", err)
	}
}
