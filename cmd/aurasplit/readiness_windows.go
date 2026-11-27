//go:build windows

package main

import (
	"fmt"
	"strings"
	"time"

	"aurasplit/internal/engine"
	"aurasplit/internal/oldflow"
	"aurasplit/internal/service"
)

func protectionReady(ts tunnelState) bool {
	p := ts.Protection
	return ts.State == string(engine.StateTunnelStarted) && p != nil && p.Ready && p.Applied && p.Complete && !p.PendingEnrollment && !p.PendingPermitClosure && p.Permit && p.PermitComplete && p.OldFlowsComplete && p.Error == ""
}

var startupProcesses = func(entries []string) ([]oldflow.Process, error) {
	return (oldflow.WindowsSource{Manifest: entries}).Processes()
}

// finishProtectionStart waits for a fresh service-owned contract, not SCM RUNNING.
// Only this interactive path may request consent to terminate Discord processes.
func finishProtectionStart(timeout time.Duration) int {
	fmt.Println("Eski IPv6 TCP/UDP akışları kalabilir. Sistem tepsisinden Discord'dan tamamen çıkın; kapı tamamlandıktan sonra yeniden açın.")
	manifest, err := discoverDiscord()
	if err == nil && len(manifest) > 0 {
		procs, perr := startupProcesses(manifest)
		pending := perr != nil
		for _, p := range procs {
			pending = pending || oldflow.Matches(p.Image, manifest)
		}
		if pending && !inputAllowed() {
			inputGuidance()
			return exitNeedsInput
		}
		if pending && strings.EqualFold(strings.TrimSpace(readLine("Discord süreçleri kapatılsın mı? Kaydedilmemiş işler kaybolabilir. [y/N]: ")), "y") && inputAllowed() {
			if err := oldflow.CloseConsented(manifest); err != nil {
				fail("Discord süreçleri tamamen kapatılamadı; koruma kapısı bekliyor.", err)
			}
		}
	}
	deadline := time.Now().Add(timeout)
	for {
		st, pid, err := service.StatusPID()
		ts, rerr := readState()
		if err == nil && st == service.StateRunning && rerr == nil && stateValid(ts, pid, time.Now(), processStartOf) && protectionReady(ts) {
			fmt.Println("PROTECTION_READY: EVET — manifest politikası, readback, tünel izni ve eski akış kapısı tamamlandı.")
			fmt.Println("Tarayıcı Discord ve DNS: en iyi çaba; kalıcı fail-closed yok. VPN bağlantısı ayrı probe sonucudur.")
			return 0
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	fmt.Println("PROTECTION_READY: HAYIR — koruma tamamlanmadı; mevcut bloklar korunuyor, hizmet yeniden deneyecek. Ayrıntı: aurasplit.exe status")
	if !inputAllowed() {
		inputGuidance()
		return exitNeedsInput
	}
	return 1
}
