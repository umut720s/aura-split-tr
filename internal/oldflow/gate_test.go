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
		{[]Process{{PID: 3, ParentPID: 1, Name: "opaque.exe", Unresolved: true}}, true, "tamamlandı"},
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

func TestUnfamiliarOrphanDoesNotBlock(t *testing.T) {
	exe := `C:\Users\fixture\AppData\Local\Discord\app-1\Discord.exe`
	g := &Gate{}
	orphan := Process{PID: 42, ParentPID: 41, Name: "Discord_helper.exe", Unresolved: true}
	if ok, why := g.Check(fakeSource{procs: []Process{orphan}}, []string{exe}); !ok {
		t.Fatal(why)
	}
}

func TestProtectedAndSessionZeroProcesses(t *testing.T) {
	exe := `C:\Users\fixture\AppData\Local\Discord\app-1\Discord.exe`
	old := time.Now().Add(-time.Hour)
	for _, name := range []string{"Secure System", "Registry", "Memory Compression", "System", "csrss.exe", "smss.exe", "wininit.exe", "services.exe", "lsass.exe"} {
		p := Process{PID: 42, ParentPID: 1, Name: name, Image: exe, Started: old, Unresolved: true}
		g := &Gate{}
		// Even a forged manifest image must never make a protected process relevant.
		if ok, why := g.Check(fakeSource{procs: []Process{p}}, []string{exe}); !ok {
			t.Fatal(name, why)
		}
	}
	for _, pid := range []uint32{0, 4} {
		if ok, why := (&Gate{}).Check(fakeSource{procs: []Process{{PID: pid, Image: exe, Unresolved: true}}}, []string{exe}); !ok {
			t.Fatal(why)
		}
	}
	p := Process{PID: 42, Name: "opaque.exe", Image: exe, Started: old, SessionKnown: true}
	if ok, why := (&Gate{}).Check(fakeSource{procs: []Process{p}}, []string{exe}); ok {
		t.Fatal(why)
	}
	p.Started = time.Now().Add(time.Hour)
	if ok, why := (&Gate{}).Check(fakeSource{procs: []Process{p}}, []string{exe}); !ok {
		t.Fatal(why)
	}
	p.Started = old
	// Session zero descendants remain relevant, independent of snapshot order.
	p.Image, p.Unresolved, p.ParentPID = "", true, 1
	parent := Process{PID: 1, Image: exe, Started: old.Add(-time.Minute), SessionKnown: true, SessionID: 1}
	if ok, why := (&Gate{}).Check(fakeSource{procs: []Process{p, parent}}, []string{exe}); ok || !strings.Contains(why, "PID 42") {
		t.Fatal(why)
	}
}

func TestUnresolvedManifestNamesWithoutAncestry(t *testing.T) {
	exe := `C:\AppData\Local\Discord\app-1\Discord.exe`
	for _, name := range []string{"Discord.exe", "DISCORDPTB.EXE", "DiscordCanary.exe", "DiscordDevelopment.exe", "Update.exe", "DiscordSetup.exe", "updater_launcher.exe", "DiscordSystemHelper.exe", "audio_effects_helper.exe", "gpu_encoder_helper.exe"} {
		t.Run(name, func(t *testing.T) {
			for _, session := range []uint32{0, 1} {
				p := Process{PID: 42, ParentPID: 99, Name: name, Unresolved: true, SessionKnown: true, SessionID: session}
				g := &Gate{}
				if ok, why := g.Check(fakeSource{procs: []Process{p}}, []string{exe}); ok || !strings.Contains(why, "okunamadı") {
					t.Fatal(why)
				}
				p.Image, p.Started, p.Unresolved = `C:\Other\unrelated.exe`, time.Now().Add(-time.Hour), false
				if ok, why := g.Check(fakeSource{procs: []Process{p}}, []string{exe}); !ok {
					t.Fatal(why)
				}
			}
		})
	}
}

func TestRememberedManifestImageAndReuse(t *testing.T) {
	exe := `C:\Users\fixture\AppData\Local\Discord\app-1\Discord.exe`
	p := Process{PID: 42, Image: exe, Started: time.Now().Add(-time.Hour)}
	g := &Gate{}
	g.Check(fakeSource{procs: []Process{p}}, []string{exe})
	p.Image, p.Unresolved = "", true
	if ok, why := g.Check(fakeSource{procs: []Process{p}}, []string{exe}); ok {
		t.Fatal(why)
	}
	p.Started = p.Started.Add(time.Minute)
	if ok, why := g.Check(fakeSource{procs: []Process{p}}, []string{exe}); !ok {
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
