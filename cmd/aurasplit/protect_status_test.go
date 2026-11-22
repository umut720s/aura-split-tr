//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"aurasplit/internal/engine"
	"aurasplit/internal/wfp"
)

// fakeCmdPolicy stands in for WFP: no real WFP call is made by these tests.
type fakeCmdPolicy struct {
	mu      sync.Mutex
	events  []string
	applied int
	modes   []wfp.ApplyMode
}

func (p *fakeCmdPolicy) add(s string) { p.mu.Lock(); p.events = append(p.events, s); p.mu.Unlock() }
func (p *fakeCmdPolicy) Apply(paths []string, mode wfp.ApplyMode) (wfp.ApplyResult, error) {
	p.add("apply")
	p.mu.Lock()
	p.modes = append(p.modes, mode)
	p.mu.Unlock()
	p.applied = len(paths)
	return wfp.ApplyResult{Covered: paths, Pruned: mode == wfp.Authoritative}, nil
}

type fakeCmdPermit struct {
	p     *fakeCmdPolicy
	paths []string
}

func (c fakeCmdPermit) Close() error    { c.p.add("permit closed"); return nil }
func (c fakeCmdPermit) Paths() []string { return c.paths }

func (p *fakeCmdPolicy) PermitOnTunnel(luid uint64, paths []string) (wfp.Permit, error) {
	if luid != 77 {
		return nil, errors.New("wrong LUID")
	}
	p.add("permit opened")
	return fakeCmdPermit{p, paths}, nil
}
func (p *fakeCmdPolicy) RemoveAll() error                  { p.add("remove"); return nil }
func (p *fakeCmdPolicy) Installed() (bool, int, error)     { return p.applied > 0, p.applied, nil }
func (p *fakeCmdPolicy) Snapshot() (bool, []string, error) { return false, nil, nil }

func withFakeProtection(t *testing.T, luidErr error) *fakeCmdPolicy {
	t.Helper()
	p := &fakeCmdPolicy{}
	oldNew, oldDisc, oldLUID, oldWatch := newPolicy, discoverDiscord, tunnelLUID, runWatcher
	t.Cleanup(func() { newPolicy, discoverDiscord, tunnelLUID, runWatcher = oldNew, oldDisc, oldLUID, oldWatch })
	runWatcher = func(ctx context.Context, _ func(), _ func(string, string)) { <-ctx.Done() }
	newPolicy = func() wfp.Policy { return p }
	discoverDiscord = func() ([]string, error) { return []string{`C:\Users\x\AppData\Local\Discord\Update.exe`}, nil }
	tunnelLUID = func(name string) (uint64, error) {
		if name != engine.TunInterfaceName {
			return 0, errors.New("wrong adapter")
		}
		return 77, luidErr
	}
	return p
}

// The persistent policy is applied when protection starts (before the
// tunnel); the permit only when the engine reports the tunnel up.
func TestStartProtectionOrder(t *testing.T) {
	p := withFakeProtection(t, nil)
	var last wfp.Status
	var mu sync.Mutex
	prot := startProtection(context.Background(), func(string, string) {}, func(s wfp.Status) { mu.Lock(); last = s; mu.Unlock() })
	defer prot.stop()
	if got := strings.Join(p.events, "|"); got != "apply" {
		t.Fatalf("events %q", got)
	}
	c, err := prot.onTunnelUp()
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if !last.Permit || !last.PermitComplete || !last.Applied || !last.Complete || last.Apps != 1 {
		t.Fatalf("status %+v", last)
	}
	mu.Unlock()
	_ = c.Close()
	prot.stop()
	prot.stop() // idempotent
	if got := strings.Join(p.events, "|"); got != "apply|permit opened|permit closed" {
		t.Fatalf("events %q", got)
	}
}

// Without the TUN adapter the permit cannot be opened: with the policy
// applied this is an error (Discord stays blocked).
func TestOnTunnelUpWithoutAdapter(t *testing.T) {
	withFakeProtection(t, errors.New("not found"))
	prot := startProtection(context.Background(), func(string, string) {}, nil)
	defer prot.stop()
	if _, err := prot.onTunnelUp(); err == nil {
		t.Fatal("expected error")
	}
}

// setup's one-shot apply is authoritative only after a complete discovery;
// an incomplete one is add-only and reported as incomplete.
func TestApplyPolicyOnceModes(t *testing.T) {
	p := withFakeProtection(t, nil)
	if n, err := applyPolicyOnce(); err != nil || n != 1 {
		t.Fatalf("applyPolicyOnce = %d, %v", n, err)
	}
	discoverDiscord = func() ([]string, error) {
		return []string{`C:\Users\x\AppData\Local\Discord\Update.exe`}, errors.New("access denied")
	}
	n, err := applyPolicyOnce()
	if !errors.Is(err, wfp.ErrIncomplete) || n != 1 {
		t.Fatalf("applyPolicyOnce = %d, %v", n, err)
	}
	if len(p.modes) != 2 || p.modes[0] != wfp.Authoritative || p.modes[1] != wfp.AddOnly {
		t.Fatalf("modes %v", p.modes)
	}
}

func TestStateWriterAsyncAndConnectivity(t *testing.T) {
	var mu sync.Mutex
	var last tunnelState
	writes := 0
	w := &stateWriter{write: func(_ string, b []byte) error {
		mu.Lock()
		defer mu.Unlock()
		writes++
		last = tunnelState{}
		return json.Unmarshal(b, &last)
	}}
	ctx, cancel := context.WithCancel(context.Background())
	done := w.startAsync(ctx)
	w.set(engine.StateTunnelStarted, "")
	w.setConnectivity(engine.ProbeResult{State: engine.ConnVerified, Time: time.Now(), Verified: time.Now()})
	w.setProtection(wfp.Status{Applied: true, Apps: 3, Permit: true})
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("writer did not stop")
	}
	mu.Lock()
	if writes == 0 || last.Connectivity != string(engine.ConnVerified) || last.Protection == nil || last.Protection.Apps != 3 || !last.Protection.Permit {
		t.Fatalf("writes %d record %+v", writes, last)
	}
	mu.Unlock()
	// Leaving the tunnel state clears the probe result.
	w.kick = nil
	w.set(engine.StateBlocking, "")
	if last.Connectivity != "" {
		t.Fatalf("connectivity kept after leaving the tunnel: %+v", last)
	}
}

func TestDescribeStatus(t *testing.T) {
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	tunnel := &tunnelState{
		State: string(engine.StateTunnelStarted), Time: now,
		Connectivity: string(engine.ConnVerified), ConnectivityTime: now, ConnectivityOK: now,
		Protection: &protectionState{Applied: true, Apps: 2, Complete: true, Permit: true, PermitApps: 2, PermitComplete: true},
	}
	partial := &tunnelState{
		State: string(engine.StateTunnelStarted), Time: now,
		Protection: &protectionState{Applied: true, Apps: 3, Incomplete: "1 executable(s) unresolved", Unresolved: 1, Permit: true, PermitApps: 2},
	}
	cases := []struct {
		name string
		in   statusInput
		want []string
		not  []string
	}{
		{"all active", statusInput{scmState: "running", scmRunning: true, state: tunnel, policyKnown: true, policyInstalled: true, policyApps: 2},
			[]string{"SERVICE_RUNNING:           EVET", "TUNNEL_INITIALIZED:        EVET", "VPN_CONNECTIVITY_VERIFIED", "PROTECTION_ACTIVE:         EVET", "tünel izni: açık (2 program)", "Kapsam:                  TAM", "TÜNELDEN (tünel dışında engelli)"}, []string{"EKSİK"}},
		{"incomplete coverage and partial permit", statusInput{scmState: "running", scmRunning: true, state: partial, policyKnown: true, policyInstalled: true, policyApps: 3},
			[]string{"tünel izni: açık, EKSİK (2/3 program", "Kapsam:                  EKSİK", "unresolved", "izni eksik"}, []string{"Kapsam:                  TAM", "TÜNELDEN (tünel dışında engelli)"}},
		{"stopped, policy installed", statusInput{scmState: "stopped", policyKnown: true, policyInstalled: true, policyApps: 2},
			[]string{"SERVICE_RUNNING:           HAYIR", "TUNNEL_INITIALIZED:        HAYIR", "denetlenmiyor", "tünel izni: kapalı", "ENGELLİ"}, []string{"VERIFIED"}},
		{"stopped, no policy", statusInput{scmState: "stopped", policyKnown: true},
			[]string{"PROTECTION_ACTIVE:         HAYIR", "DOĞRUDAN"}, nil},
		{"policy unknown", statusInput{scmState: "running", scmRunning: true, stateNote: "x"},
			[]string{"TUNNEL_INITIALIZED:        bilinmiyor", "PROTECTION_ACTIVE:         bilinmiyor"}, nil},
		{"degraded", statusInput{scmState: "running", scmRunning: true, policyKnown: true, policyInstalled: true, state: &tunnelState{
			State: string(engine.StateTunnelStarted), Time: now, Connectivity: string(engine.ConnDegraded), ConnectivityTime: now,
			ProbeFailures: 2, ConnectivityDetail: "timeout", Protection: &protectionState{Applied: true, Permit: true}}},
			[]string{"VPN_DEGRADED", "art arda 2 başarısız", "timeout"}, []string{"VERIFIED"}},
		{"not yet probed", statusInput{scmState: "running", scmRunning: true, policyKnown: true, policyInstalled: true, state: &tunnelState{
			State: string(engine.StateTunnelStarted), Time: now}},
			[]string{"henüz doğrulanmadı", "ENGELLİ"}, []string{"VERIFIED"}},
	}
	for _, c := range cases {
		out := strings.Join(describeStatus(c.in, time.UTC), "\n")
		for _, w := range c.want {
			if !strings.Contains(out, w) {
				t.Errorf("%s: missing %q in\n%s", c.name, w, out)
			}
		}
		for _, n := range c.not {
			if strings.Contains(out, n) {
				t.Errorf("%s: unexpected %q in\n%s", c.name, n, out)
			}
		}
	}
}
