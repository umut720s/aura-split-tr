package wfp

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// disableApp marks every persistent filter of path as disabled in the fake
// BFE and returns how many were marked.
func disableApp(b *fakeBackend, path string) int {
	id, _ := (&fakeBackend{appIDErr: map[string]bool{}}).AppID(path)
	b.bfe.mu.Lock()
	defer b.bfe.mu.Unlock()
	n := 0
	for k, f := range b.bfe.filters {
		if f.f.Persistent && string(f.f.AppID) == string(id) {
			f.disabled = true
			b.bfe.filters[k] = f
			n++
		}
	}
	return n
}

func disabledCount(b *fakeBackend) int {
	b.bfe.mu.Lock()
	defer b.bfe.mu.Unlock()
	n := 0
	for _, f := range b.bfe.filters {
		if f.disabled {
			n++
		}
	}
	return n
}

// A disabled filter with a wanted key is not "present": Apply deletes and
// re-adds it in the same transaction, in both modes, and Installed never
// counts disabled blocks.
func TestApplyRecreatesDisabledFilters(t *testing.T) {
	for _, mode := range []ApplyMode{Authoritative, AddOnly} {
		t.Run(mode.String(), func(t *testing.T) {
			b := newFake()
			fw := &Firewall{b: b, lstat: existsAll}
			a, c := `C:\u\x\Discord\Update.exe`, `C:\u\x\Discord\app-1\Discord.exe`
			mustApply(t, fw, []string{a, c}, Authoritative)
			if n := disableApp(b, c); n != 8 {
				t.Fatalf("disabled %d", n)
			}
			if ok, n, err := fw.Installed(); err != nil || !ok || n != 1 {
				t.Fatalf("Installed counts disabled blocks: %v %d %v", ok, n, err)
			}
			b.bfe.log = nil
			res := mustApply(t, fw, []string{a, c}, mode)
			log := strings.Join(b.bfe.log, "|")
			if strings.Count(log, "begin") != 1 || !strings.Contains(log, "commit") {
				t.Fatalf("not one committed transaction: %s", log)
			}
			if strings.Count(log, "delete filter") != 8 || strings.Count(log, "add filter") != 8 {
				t.Fatalf("disabled filters not replaced: %s", log)
			}
			if disabledCount(b) != 0 || appFilters(b, c) != 8 {
				t.Fatalf("disabled=%d filters=%d", disabledCount(b), appFilters(b, c))
			}
			if !containsAll(res.Covered, []string{a, c}) {
				t.Fatalf("covered %v", res.Covered)
			}
			if ok, n, err := fw.Installed(); err != nil || !ok || n != 2 {
				t.Fatalf("Installed = %v %d %v", ok, n, err)
			}
		})
	}
}

// A disabled block that is kept (not requested, executable still exists)
// is never reported as coverage; it is re-created from its recorded path.
// If its app ID cannot be read, the pass is incomplete and it stays
// uncounted.
func TestApplyDisabledBaselineNotCoverage(t *testing.T) {
	b := newFake()
	fw := &Firewall{b: b, lstat: existsAll}
	a, c := `C:\u\x\Discord\Update.exe`, `C:\u\x\Discord\app-1\Discord.exe`
	mustApply(t, fw, []string{a, c}, Authoritative)
	disableApp(b, c)
	b.appIDErr[c] = true
	res, err := fw.Apply([]string{a}, AddOnly)
	var inc *IncompleteError
	if !errors.As(err, &inc) || len(inc.Unresolved) != 1 {
		t.Fatalf("err = %v", err)
	}
	if containsAll(res.Covered, []string{c}) {
		t.Fatalf("disabled block counted as covered: %v", res.Covered)
	}
	if appFilters(b, c) != 8 {
		t.Fatal("disabled filters of an existing executable removed")
	}
	b.appIDErr[c] = false
	res = mustApply(t, fw, []string{a}, AddOnly)
	if !containsAll(res.Covered, []string{c}) || disabledCount(b) != 0 || appFilters(b, c) != 8 {
		t.Fatalf("disabled baseline not re-created: covered %v disabled %d", res.Covered, disabledCount(b))
	}
}

func profilePath(user string, i int) string {
	return fmt.Sprintf(`C:\Users\%s\AppData\Local\Discord\app-1.0.%d\Discord.exe`, user, i)
}

// The per-profile budget counts existing plus proposed executables: once
// it is exhausted nothing more is added for that profile, the pass is
// incomplete, existing blocks are kept, and other profiles are not
// affected.
func TestApplyPerProfileBudget(t *testing.T) {
	b := newFake()
	fw := &Firewall{b: b, lstat: existsAll}
	var first []string
	for i := 0; i < MaxPolicyAppsPerProfile-2; i++ {
		first = append(first, profilePath("u1", i))
	}
	mustApply(t, fw, first, Authoritative)
	// Old versions stay on disk; discovery now returns only newer ones.
	var next []string
	for i := 1000; i < 1005; i++ {
		next = append(next, profilePath("u1", i))
	}
	other := profilePath("u2", 1)
	res, err := fw.Apply(append(next, other), Authoritative)
	var inc *IncompleteError
	if !errors.As(err, &inc) || !errors.Is(err, ErrIncomplete) || len(inc.OverBudget) != 3 || len(res.OverBudget) != 3 {
		t.Fatalf("err = %v res %+v", err, res)
	}
	for _, p := range first {
		if appFilters(b, p) != 8 {
			t.Fatalf("existing block removed to make room: %s", p)
		}
	}
	if appFilters(b, other) != 8 {
		t.Fatal("other profile affected by the budget")
	}
	if ok, n, _ := fw.Installed(); !ok || n != MaxPolicyAppsPerProfile+1 {
		t.Fatalf("installed %d", n)
	}
	if len(res.Covered) != MaxPolicyAppsPerProfile+1 {
		t.Fatalf("covered %d", len(res.Covered))
	}
	// Requested executables that already have a block never need budget.
	if _, err := fw.Apply(append(append([]string(nil), first...), other), AddOnly); err != nil {
		t.Fatal(err)
	}
}

// The global budget bounds the total over all profiles, and the dynamic
// permit uses the same budget.
func TestApplyGlobalBudgetAndPermit(t *testing.T) {
	b := newFake()
	fw := &Firewall{b: b, lstat: existsAll}
	var all []string
	for u := 0; u < MaxPolicyApps/MaxPolicyAppsPerProfile+1; u++ {
		for i := 0; i < MaxPolicyAppsPerProfile; i++ {
			all = append(all, profilePath(fmt.Sprintf("u%02d", u), i))
		}
	}
	res, err := fw.Apply(all, Authoritative)
	if !errors.Is(err, ErrIncomplete) || len(res.OverBudget) != MaxPolicyAppsPerProfile {
		t.Fatalf("err %v over %d", err, len(res.OverBudget))
	}
	if ok, n, _ := fw.Installed(); !ok || n != MaxPolicyApps {
		t.Fatalf("installed %d", n)
	}
	p, err := fw.PermitOnTunnel(3, all)
	if !errors.Is(err, ErrIncomplete) || p == nil {
		t.Fatalf("permit %v err %v", p, err)
	}
	defer p.Close()
	if len(p.Paths()) != MaxPolicyApps {
		t.Fatalf("permit covers %d", len(p.Paths()))
	}
	if n := b.bfe.count(func(f Filter) bool { return !f.Persistent }); n != MaxPolicyApps*len(Layers) {
		t.Fatalf("dynamic filters %d", n)
	}
}

func TestProfileOf(t *testing.T) {
	if got := profileOf(`C:\Users\Ab\AppData\Local\Discord\Update.exe`); got != `c:\users\ab` {
		t.Fatalf("got %q", got)
	}
	if profileOf(`C:\Users\AB\appdata\local\x`) != profileOf(`c:\users\ab\AppData\Local\y`) {
		t.Fatal("profile bucket is case-sensitive")
	}
	if got := profileOf(`C:\elsewhere\Discord.exe`); got != "" {
		t.Fatalf("got %q", got)
	}
}
