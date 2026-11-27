package oldflow

import (
	"aurasplit/internal/manifest"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeSource struct {
	procs []Process
	err   error
}

func (s fakeSource) Processes() ([]Process, error) { return s.procs, s.err }

func TestGateRetirement(t *testing.T) {
	exe := `C:\Users\fixture\AppData\Local\Discord\app-1\Discord.exe`
	entries := []string{exe}
	old := time.Now().Add(-time.Hour)
	g := &Gate{}
	tests := []struct {
		procs  []Process
		ready  bool
		reason string
	}{
		{[]Process{{PID: 1, Image: exe, Started: old}}, false, "koruma öncesi"},
		{[]Process{{PID: 3, ParentPID: 1, Name: "opaque.exe", Unresolved: true}}, false, "okunamadı"},
		{[]Process{{PID: 1, Image: exe, Started: old}}, false, "koruma öncesi"},
		{[]Process{{PID: 2, ParentPID: 1, Name: "opaque.exe", Unresolved: true}, {PID: 1, Image: exe, Started: old}}, false, "okunamadı"},
		{[]Process{{PID: 2, Name: "opaque.exe", Unresolved: true}}, false, "okunamadı"},
		{nil, true, "tamamlandı"},
		{[]Process{{PID: 1, Image: exe, Started: time.Now().Add(time.Hour)}}, true, "tamamlandı"},
		{[]Process{{PID: 9, Image: `C:\Users\fixture\AppData\Local\Discord\utility.exe`, Started: old}}, true, "tamamlandı"},
		{[]Process{{PID: 8, Name: "audio_effects_helper.exe", Unresolved: true}}, false, "okunamadı"},
		{[]Process{{PID: 10, Image: `C:\Users\fixture\AppData\Local\Discord\app-2\audio_effects_helper.exe`, Started: old}}, false, "kaydı eksik"},
	}
	for _, tc := range tests {
		ok, reason := g.Check(fakeSource{procs: tc.procs}, entries)
		if ok != tc.ready || !strings.Contains(reason, tc.reason) {
			t.Fatalf("%v %s", ok, reason)
		}
	}
	if ok, _ := g.Check(fakeSource{err: errors.New("denied")}, entries); ok {
		t.Fatal("inventory failure granted readiness")
	}
	if Matches(`C:\Users\fixture\AppData\Local\Discord\utility.exe`, entries) {
		t.Fatal("unrelated executable matched")
	}
	if Matches(`C:\Users\fixture\AppData\Local\DiscordCustom\app-1\Discord.exe`, entries) {
		t.Fatal("unsupported root matched")
	}
}

func TestUnfamiliarOrphanLifetimeAndResolution(t *testing.T) {
	exe := `C:\Users\fixture\AppData\Local\Discord\app-1\Discord.exe`
	g := &Gate{}
	old := time.Now().Add(-time.Hour)
	orphan := Process{PID: 42, ParentPID: 41, Name: "opaque.exe", Started: old, Unresolved: true}
	if ok, why := g.Check(fakeSource{procs: []Process{orphan}}, []string{exe}); ok || !strings.Contains(why, "PID 42 (opaque.exe)") {
		t.Fatal(ok, why)
	}
	// An orphan suspicion is not permanent relevance once ancestry is resolved.
	parent := Process{PID: 41, Image: `C:\Other\parent.exe`, Started: old.Add(-time.Minute)}
	if ok, why := g.Check(fakeSource{procs: []Process{orphan, parent}}, []string{exe}); !ok {
		t.Fatal(why)
	}
	if ok, why := g.Check(fakeSource{procs: []Process{orphan}}, []string{exe}); ok {
		t.Fatal("unresolved pre-cutoff orphan ignored", why)
	}
	if ok, why := g.Check(fakeSource{}, []string{exe}); !ok {
		t.Fatal("exited orphan still pending", why)
	}
	// Resolving the same identity as unrelated releases it immediately.
	resolved := orphan
	resolved.Image = `C:\Other\utility.exe`
	resolved.Unresolved = false
	if ok, why := g.Check(fakeSource{procs: []Process{resolved}}, []string{exe}); !ok {
		t.Fatal(why)
	}
	// The orphan rule is independently re-evaluated; post-cutoff orphans do not block.
	orphan.Started = time.Now().Add(time.Hour)
	if ok, why := g.Check(fakeSource{procs: []Process{orphan}}, []string{exe}); !ok {
		t.Fatal(why)
	}
	if ok, why := g.Check(fakeSource{}, []string{exe}); !ok {
		t.Fatal(why)
	}
}

func TestPIDAndParentReuseDoNotInheritRelevance(t *testing.T) {
	exe := `C:\Users\fixture\AppData\Local\Discord\app-1\Discord.exe`
	old := time.Now().Add(-time.Hour)
	g := &Gate{}
	g.Check(fakeSource{procs: []Process{{PID: 1, Image: exe, Started: old}, {PID: 2, ParentPID: 1, Name: "opaque.exe", Started: old.Add(time.Minute), Unresolved: true}}}, []string{exe})
	newOrphan := Process{PID: 2, ParentPID: 99, Name: "opaque.exe", Started: time.Now().Add(time.Hour), Unresolved: true}
	if ok, why := g.Check(fakeSource{procs: []Process{newOrphan}}, []string{exe}); !ok {
		t.Fatal("replacement inherited descendant relevance", why)
	}
	g.Check(fakeSource{procs: []Process{{PID: 1, Image: exe, Started: old}, {PID: 2, ParentPID: 1, Name: "opaque.exe", Started: old.Add(time.Minute), Unresolved: true}}}, []string{exe})
	// Same PID, confirmed different creation time, readable unrelated parent chain.
	replacement := Process{PID: 2, ParentPID: 3, Name: "opaque.exe", Started: old.Add(2 * time.Minute), Unresolved: true}
	parent := Process{PID: 3, Image: `C:\Other\parent.exe`, Started: old}
	if ok, why := g.Check(fakeSource{procs: []Process{replacement, parent}}, []string{exe}); !ok {
		t.Fatal(why)
	}
	// A recycled parent PID cannot transfer historical Discord ancestry.
	replacement.ParentPID = 1
	parent.PID = 1
	if ok, why := g.Check(fakeSource{procs: []Process{replacement, parent}}, []string{exe}); !ok {
		t.Fatal(why)
	}
}

func TestEnrollmentGenerationsRetireCutoffs(t *testing.T) {
	exe := `C:\Users\fixture\AppData\Local\Discord\app-1\Discord.exe`
	other := `C:\Users\fixture\AppData\Local\DiscordPTB\Update.exe`
	for _, retained := range [][]string{nil, {other}} {
		g := &Gate{}
		g.Check(fakeSource{}, []string{exe, other})
		first := time.Now().Add(-time.Minute)
		g.cutoffs[manifest.Normalize(exe)] = first
		between := time.Now()
		g.Check(fakeSource{}, retained)
		if _, ok := g.cutoffs[manifest.Normalize(exe)]; ok {
			t.Fatal("retired generation retained")
		}
		if ok, why := g.Check(fakeSource{procs: []Process{{PID: 1, Image: exe, Started: between}}}, []string{exe, other}); ok {
			t.Fatal(why)
		}
		if !g.cutoffs[manifest.Normalize(exe)].After(first) {
			t.Fatal("cutoff not renewed")
		}
	}
}
