//go:build windows

// Package msiclean shares the MSI recovery and data-cleanup path without the tunnel engine.
// SPDX-License-Identifier: GPL-3.0-or-later
package msiclean

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"aurasplit/internal/paths"
	"aurasplit/internal/service"
)

// RecoverOps supplies recovery operations; tests use fakes without system changes.
type RecoverOps struct {
	Disable, Stop, Remove func() error
	Installed             func() (bool, int, error)
}

func stopOK(err error) bool { return err == nil || errors.Is(err, service.ErrNotRunning) }

func fail(msg string, err error) {
	fmt.Fprintf(os.Stderr, "\nHATA: %s\n", msg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ayrıntı: %v\n", err)
	}
}

// Recover preserves the CLI recovery result and output for MSI and interactive use.
func Recover(msi bool, ops RecoverOps) int {
	fmt.Println("Kurtarma: AURA Split TR'nin Discord engelleme kuralları (WFP) kaldırılıyor ve hizmet durduruluyor.")
	code := 0
	// Disabled first so no queued recovery restart can re-apply the policy.
	if err := ops.Disable(); err != nil && !isNotInstalled(err) {
		fmt.Println("Uyarı: hizmet devre dışı bırakılamadı (bir kurtarma yeniden başlatması kuralları yeniden uygulayabilir):", err)
	}
	switch err := ops.Stop(); {
	case stopOK(err) || isNotInstalled(err):
	case msi:
		fmt.Println("HATA: hizmet durdurulamadı; çalışan hizmet kuralları yeniden uygulayabilir:", err)
		code = 1
	default:
		fmt.Println("Uyarı: hizmet durdurulamadı:", err)
	}
	if err := ops.Remove(); err != nil {
		fail("WFP kuralları kaldırılamadı.", err)
		code = 1
	} else {
		fmt.Println("- Kurallar kaldırıldı (yoksa zaten temizdi). Discord doğrudan bağlantıyı kullanır.")
	}
	if installed, n, err := ops.Installed(); err == nil && installed {
		fmt.Println("UYARI: politika hâlâ yüklü görünüyor (", n, "program ). Bilgisayarı yeniden başlatıp tekrar deneyin.")
		code = 1
	}
	if code == 0 && !msi {
		fmt.Println("Yeniden etkinleştirmek için: aurasplit.exe start (ya da Başlat menüsünden: AURA Split TR - Yapılandır)")
	}
	if code != 0 && msi {
		fmt.Println("Kaldırma iptal ediliyor (geri alınıyor); aurasplit.exe yerinde kalır. Bilgisayarı yeniden başlatıp kaldırmayı tekrar deneyin ya da yönetici olarak çalıştırın: aurasplit.exe recover")
	}
	return code
}

// Uninstall recovers first and preserves data on failure. Cleanup refusals
// are reported without failing the commit-time action.
func Uninstall(recover func() int) int {
	return uninstall(recover, paths.DataDir, paths.CleanDataDir, QuarantineDirs)
}

// uninstall allows tests to prove the recovery gate without touching real data.
func uninstall(recover func() int, dataDir func() string, clean func(string) (paths.CleanResult, error), quarantines func() ([]string, []string)) int {
	if code := recover(); code != 0 {
		fmt.Println("Veri klasörüne dokunulmadı.")
		return code
	}
	res, err := clean(dataDir())
	if err != nil {
		res.Kept = append(res.Kept, err.Error())
	}
	for _, l := range DescribeCleanup(dataDir(), res) {
		fmt.Println(l)
	}
	if ours, foreign := quarantines(); len(ours)+len(foreign) > 0 {
		fmt.Println("Not: karantina klasörleri silinmedi (elle inceleyin):")
		for _, d := range append(ours, foreign...) {
			fmt.Println("  ", d)
		}
	}
	return 0
}

// DescribeCleanup turns a data-directory cleanup result into the lines
// printed by the cleanup command. Pure (unit-tested).
func DescribeCleanup(dir string, res paths.CleanResult) []string {
	switch {
	case res.Missing:
		return []string{"- Veri klasörü yok (temiz): " + dir}
	case res.Removed:
		return []string{fmt.Sprintf("- Veri klasörü silindi (%d AURA Split TR dosyası): %s", len(res.Deleted), dir)}
	}
	out := []string{"UYARI: veri klasörü elle incelenmek üzere bırakıldı: " + dir}
	if len(res.Deleted) > 0 {
		out = append(out, fmt.Sprintf("  Silinen AURA Split TR dosyaları: %s", strings.Join(res.Deleted, ", ")))
	}
	for _, k := range res.Kept {
		out = append(out, "  Neden: "+k)
	}
	out = append(out, "  İçinde VPN özel anahtarı (profile.json) olabilir; içeriği kontrol edip klasörü yönetici olarak elle silin.")
	return out
}

// QuarantineDirs lists the quarantine directories next to our directories.
// Anyone can create such names in %ProgramData%, so only real directories
// owned and controlled by SYSTEM/Administrators are reported as ours.
func QuarantineDirs() (ours, foreign []string) {
	for _, dir := range []string{paths.DataDir(), paths.InstallDir()} {
		m, err := filepath.Glob(dir + paths.QuarantineInfix + "*")
		if err != nil {
			continue
		}
		for _, q := range m {
			if ok, err := paths.IsTrustedAppDir(q); err == nil && ok {
				ours = append(ours, q)
			} else {
				foreign = append(foreign, q)
			}
		}
	}
	return ours, foreign
}

func isNotInstalled(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "does not exist") || strings.Contains(s, "not installed") ||
		strings.Contains(s, "kurulu değil") || strings.Contains(s, "1060")
}
