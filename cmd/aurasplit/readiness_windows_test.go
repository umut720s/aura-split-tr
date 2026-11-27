//go:build windows

package main

import (
	"strings"
	"testing"
	"time"

	"aurasplit/internal/engine"
	"aurasplit/internal/wfp"
)

func TestProtectionReadyGates(t *testing.T) {
	good := protectionState{Ready: true, Applied: true, Complete: true, Permit: true, PermitComplete: true, OldFlowsComplete: true}
	for _, mutate := range []func(*protectionState){
		func(p *protectionState) { p.Ready = false }, func(p *protectionState) { p.Applied = false }, func(p *protectionState) { p.Complete = false }, func(p *protectionState) { p.Permit = false }, func(p *protectionState) { p.PermitComplete = false }, func(p *protectionState) { p.OldFlowsComplete = false }, func(p *protectionState) { p.Error = "failure" },
		func(p *protectionState) { p.PendingEnrollment = true },
		func(p *protectionState) { p.PendingPermitClosure = true },
	} {
		p := good
		mutate(&p)
		ts := tunnelState{State: string(engine.StateTunnelStarted), Protection: &p}
		if protectionReady(ts) {
			t.Fatal("missing gate accepted")
		}
	}
	ts := tunnelState{State: string(engine.StateTunnelStarted), Protection: &good}
	if !protectionReady(ts) {
		t.Fatal("complete gates rejected")
	}
	ts.State = string(engine.StateBlocking)
	if protectionReady(ts) {
		t.Fatal("blocking tunnel accepted")
	}
}

func TestStatusShowsPendingPermitClosure(t *testing.T) {
	p := &protectionState{Ready: true, Applied: true, Complete: true, Permit: true, PermitComplete: true, OldFlowsComplete: true, PendingPermitClosure: true}
	out := strings.Join(describeStatus(statusInput{scmRunning: true, state: &tunnelState{State: string(engine.StateTunnelStarted), Protection: p}}, time.UTC), "\n")
	if !strings.Contains(out, "PERMIT_CLOSURE_PENDING:    EVET") || protectionReady(tunnelState{State: string(engine.StateTunnelStarted), Protection: p}) {
		t.Fatal(out)
	}
}

func TestStatusClassesNeverPromotePendingGate(t *testing.T) {
	p := &protectionState{Applied: true, Complete: true, Permit: true, PermitComplete: true, Classes: wfp.TrafficClasses([]string{`C:\Users\fixture\AppData\Local\Discord\app-1\Discord.exe`, `C:\Users\fixture\AppData\Local\Discord\Update.exe`, `C:\Users\fixture\AppData\Local\Discord\app-1\updater_launcher.exe`, `C:\Users\fixture\AppData\Local\SquirrelTemp\DiscordSetup.exe`}, true, "")}
	out := strings.Join(describeStatus(statusInput{scmRunning: true, state: &tunnelState{State: string(engine.StateTunnelStarted), Protection: p}}, time.UTC), "\n")
	if strings.Contains(out, ": protected") || strings.Contains(out, "TÜNELDEN") {
		t.Fatal(out)
	}
	for _, class := range []string{"desktop", "updater", "helpers", "installers", "browser Discord", "DNS"} {
		if !strings.Contains(out, class+":") {
			t.Fatal(out)
		}
	}
	if !strings.Contains(out, "best-effort") {
		t.Fatal(out)
	}
}
