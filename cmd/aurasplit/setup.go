//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aurasplit/internal/engine"
	"aurasplit/internal/paths"
	"aurasplit/internal/profile"
	"aurasplit/internal/provider"
	"aurasplit/internal/service"
	"aurasplit/internal/wfp"
)

const (
	cloudflareTermsURL = "https://www.cloudflare.com/application/terms/"
	maxConfSize        = 64 << 10 // a WireGuard .conf is a few hundred bytes
)

// setupStartTimeout is how long setup waits for the service to report
// RUNNING. Our service handler reports RUNNING right after START_PENDING,
// so a service that is still starting after this long is held by something
// outside the program.
var setupStartTimeout = 30 * time.Second

// cmdSetup is the configuration wizard ("AURA Split TR - Yapılandır" in the
// Start Menu). It no longer installs anything: Windows Installer (the MSI
// package) owns the program file and the service. setup only runs from the
// MSI-installed copy, writes the profile, applies the WFP policy, switches
// the service to automatic start and starts it.
//
// It is the one interactive command a user launches by double-click or
// from the Start Menu, so it keeps the self-elevation through UAC
// (ShellExecute "runas", see relaunchElevated). The location check runs
// first, unelevated, so a downloaded copy never asks for administrator
// rights at all.
func cmdSetup(elevated bool) int {
	if !inputAllowed() {
		inputGuidance()
		return exitNeedsInput
	}
	if ok, err := runningFromInstalled(); !ok {
		printNotInstalled(err)
		return 1
	}
	if !service.IsAdmin() {
		if elevated {
			failMsg("Yapılandırma yönetici izni gerektiriyor ve izin alınamadı.")
			return 1
		}
		fmt.Println("Yapılandırma yönetici izni gerektiriyor; izin isteniyor...")
		if err := relaunchElevated([]string{"setup"}); err != nil {
			fail("Yönetici olarak yeniden başlatılamadı.", err)
			return 1
		}
		setupRelaunched = true
		return 0
	}

	return runSetup()
}

// runningFromInstalled reports whether this process runs from
// paths.InstalledExePath(), decided by file identity (volume serial + file
// index of the image pinned at startup), never by comparing path strings.
func runningFromInstalled() (bool, error) {
	if selfImage == nil {
		if selfImageErr == nil {
			selfImageErr = errors.New("running executable was not opened")
		}
		return false, fmt.Errorf("çalışan program dosyası doğrulanamadı: %w", selfImageErr)
	}
	same, err := sameFileAsImage(paths.InstalledExePath())
	if err != nil {
		return false, fmt.Errorf("kurulu program dosyası incelenemedi: %w", err)
	}
	return same, nil
}

func printNotInstalled(err error) {
	fmt.Printf(`
AURA Split TR %s

Bu dosya kurulu AURA Split TR değil. Program artık yalnızca Windows
Installer (MSI) paketiyle kurulur; bu dosya kendini kopyalamaz ve
hizmet oluşturmaz.

1. Sürümler (Releases) sayfasından AuraSplitTR-<sürüm>-x64.msi dosyasını
   indirip çift tıklayın ve kurulumu tamamlayın.
2. Başlat menüsünden "AURA Split TR - Yapılandır" kısayolunu açın.

Kurulu program şurada olmalıdır: %s
`, version, paths.InstalledExePath())
	if err != nil {
		fmt.Println()
		fail("Kurulum konumu doğrulanamadı.", err)
	}
}

func runSetup() int {
	fmt.Printf(`
==============================================================
  AURA Split TR %s - Yapılandırma
==============================================================

Bu araç keşfedilen Discord programları için kalıcı engeller ve
WireGuard tünel izni kurar. Tarayıcı Discord ve DNS en iyi çabadır;
bu sınıflar için kalıcı fail-closed güvencesi yoktur.

Yapılandırmadan sonra arka planda, pencere açmadan bir Windows
hizmeti olarak çalışır ve bilgisayar açılınca kendiliğinden başlar.
Hiçbir veri toplanmaz; anahtarlar yalnızca bu bilgisayarda,
yalnızca yöneticilerin okuyabildiği bir dosyada saklanır.

`, version)

	// Preflight: everything that can fail without side effects is checked
	// before the user registers with a provider, before the running service
	// is stopped and before the profile is touched.
	if err := preflight(); err != nil {
		fail("Yapılandırma ön denetimi başarısız; hiçbir şey değiştirilmedi.", err)
		return 1
	}

	wg, prov, ok := chooseProvider()
	if !ok {
		return 1
	}

	fmt.Println()
	fmt.Println("Not: Tarayıcı Discord ve DNS yalnızca en iyi çabayla yönlendirilir; kalıcı fail-closed değildir.")

	// TunnelBrowserDiscord is kept in the profile for compatibility; the
	// engine now always tunnels the Discord domains from every process.
	p := &profile.Profile{
		Version:              profile.CurrentVersion,
		Provider:             prov,
		WireGuard:            wg,
		TunnelBrowserDiscord: true,
	}
	if err := p.Validate(); err != nil {
		fail("VPN yapılandırması geçersiz. Doğru dosyayı seçtiğinizden emin olun.", err)
		return 1
	}
	if err := engine.Check(p); err != nil {
		fail("Tünel yapılandırması oluşturulamadı. Yapılandırma dosyası bu araçla uyumlu değil olabilir.", err)
		return 1
	}
	data, err := p.Marshal()
	if err != nil {
		fail("Profil hazırlanamadı.", err)
		return 1
	}

	fmt.Println()
	fmt.Println("Yapılandırılıyor...")

	// The new profile is staged next to profile.json and only moved into
	// place after the running service was stopped, so a failure before that
	// leaves the old profile untouched.
	staged, err := paths.StageSecureFile(paths.ProfilePath(), data)
	for i := range data {
		data[i] = 0
	}
	if err != nil {
		fail("Profil hazırlanamadı: "+paths.ProfilePath(), err)
		return 1
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(staged)
		}
	}()

	// A running service is stopped so it picks up the new profile.
	st, err := service.Status()
	if err != nil {
		fail("Hizmet durumu okunamadı; profil değiştirilmedi.", err)
		return 1
	}
	wasRunning := st != service.StateStopped
	if wasRunning {
		fmt.Println("- Çalışan hizmet durduruluyor")
		if err := service.Stop(); !stopOK(err) {
			fail("Hizmet durdurulamadı; profil değiştirilmedi.", err)
			return 1
		}
	}

	if err := paths.ReplaceFile(staged, paths.ProfilePath()); err != nil {
		fail("Profil kaydedilemedi: "+paths.ProfilePath(), err)
		if wasRunning {
			// The old profile was never touched: restart with it.
			if serr := service.Start(); serr != nil {
				fmt.Println("- Önceki hizmet yeniden başlatılamadı:", serr)
			} else {
				fmt.Println("- Hizmet önceki profil ile yeniden başlatıldı")
			}
		}
		return 1
	}
	committed = true
	fmt.Println("- Profil kaydedildi (yalnızca SYSTEM ve Yöneticiler okuyabilir)")

	// The fail-closed policy is applied before the service starts (the
	// service applies and reconciles it again on every start). Only a
	// complete discovery may remove existing rules.
	switch n, err := applyPolicyOnce(); {
	case err == nil:
		fmt.Printf("- Discord engelleme kuralları uygulandı (%d Discord programı bulundu)\n", n)
	case errors.Is(err, wfp.ErrIncomplete):
		fmt.Printf("- UYARI: Discord engelleme kuralları EKSİK uygulandı (%d program korunuyor; hiçbir kural silinmedi; hizmet yeniden deneyecek): %v\n", n, err)
	default:
		fmt.Println("- UYARI: Discord engelleme kuralları (WFP) şimdi uygulanamadı; hizmet yeniden deneyecek:", err)
	}

	// The MSI registers the restart-on-failure actions; the flag that also
	// runs them on a non-zero exit code is set here (see
	// service.EnableNonCrashRecovery).
	if err := service.EnableNonCrashRecovery(); err != nil {
		fmt.Println("- UYARI: hizmet kurtarma ayarı tamamlanamadı (çökme dışındaki hatalarda otomatik yeniden başlatma):", err)
	}
	// The MSI registers the service as manual start; a configured
	// installation starts at boot.
	if err := service.SetAutoStart(true); err != nil {
		fail("Hizmet otomatik başlatmaya alınamadı.", err)
		printBlockedHint()
		return 1
	}
	fmt.Println("- Hizmet otomatik başlatmaya alındı")

	fmt.Println("- Hizmet başlatılıyor (en fazla", int(setupStartTimeout/time.Second), "sn beklenir)")
	if !startAndReport(setupStartTimeout) {
		return 1
	}
	if finishProtectionStart(setupStartTimeout) != 0 {
		return 1
	}

	fmt.Printf(`
==============================================================
  Yapılandırma tamamlandı.
==============================================================

- AURA Split TR artık arka planda, pencere olmadan çalışıyor.
- Bilgisayar her açıldığında otomatik başlar.
- Manifest yolları için dört ALE katmanı, tünel izni ve eski akış
  kapısı tamamlandı. Paket izolasyonu canlı ölçülmedi.
  Tarayıcı Discord ve DNS: en iyi çaba; kalıcı fail-closed yok.
  Doğrudan bağlantıya dönmek için:  "%[1]s" disable
  Acil durumda kuralları kaldırmak:  "%[1]s" recover
- ÖNEMLİ: Discord'u tamamen kapatıp yeniden açın.
  (Sağ alttaki sistem tepsisinde Discord simgesine sağ tıklayıp
  "Discord'dan Çık" seçin, ardından Discord'u tekrar açın.)
- Başka bir VPN uygulamasının (ör. Proton VPN uygulaması) kendi
  bağlantısını açık tutmayın; çakışma olabilir.

Durum:     "%[1]s" status
Günlük:    %[2]s
Kaldırma:  Ayarlar > Uygulamalar > Yüklü uygulamalar > AURA Split TR > Kaldır
`, paths.InstalledExePath(), paths.LogPath())
	return 0
}

// startAndReport starts the service, waits until it is RUNNING and prints
// what happened. A service that stays START_PENDING is reported with a
// hint instead of being treated as a silent success.
func startAndReport(timeout time.Duration) bool {
	err := service.StartWait(timeout)
	if err == nil {
		fmt.Println("- Hizmet çalışıyor")
		return true
	}
	if errors.Is(err, service.ErrStartPending) {
		failMsg(startPendingMessage(timeout))
	} else {
		fail("Hizmet başlatılamadı. Ayrıntılar için günlüğe bakın: "+paths.LogPath(), err)
	}
	printBlockedHint()
	return false
}

// startPendingMessage explains a service that never left START_PENDING.
// The program itself reports RUNNING immediately, so the usual cause is
// that the new process is held before it runs (for example an antivirus
// product inspecting a new, unsigned executable).
func startPendingMessage(timeout time.Duration) string {
	return fmt.Sprintf(`Hizmet %d sn sonra hâlâ "başlatılıyor" (START_PENDING) durumunda.
Hizmet işlemi oluşturuldu ama çalışmaya başlamadı. Antivirüs programınız
hizmetin başlamasını engelliyor olabilir (ör. yeni ve imzasız program
dosyasını incelemek için bekletiyor).

Kontrol etmek için:
  1. Antivirüs programınızın raporlarına / karantina listesine bakın
     (aurasplit.exe veya AuraSplitTR hizmeti için bir kayıt var mı?).
  2. Olay Görüntüleyicisi > Windows Günlükleri > Sistem bölümünde
     "Service Control Manager" kaynaklı AuraSplitTR kayıtlarına bakın.
  3. Bir süre sonra durumu yeniden denetleyin:  "%s" status
     Hizmet kendiliğinden "çalışıyor" durumuna geçebilir.

Antivirüs korumasını kapatmayın ve istisna eklemeyin. Bir algılama
görürseniz bunu antivirüs üreticisine yanlış alarm olarak ve bu
projeye bildirin.`, int(timeout/time.Second), paths.InstalledExePath())
}

// printBlockedHint reminds the user that the persistent policy keeps
// Discord blocked while the service is not running.
func printBlockedHint() {
	if installed, _, err := policyInstalled(); err == nil && installed {
		fmt.Println()
		fmt.Println("Kalıcı WFP politikası mevcut; tam manifest kapsamı ve eski akışlar ayrıca doğrulanmalıdır.")
		fmt.Println("Doğrudan bağlantıya hemen dönmek için:", `"`+paths.InstalledExePath()+`" recover`)
	}
}

// chooseProvider runs the provider menu until a usable WireGuard config is
// obtained or the user gives up.
func chooseProvider() (profile.WireGuard, string, bool) {
	for {
		if !inputAllowed() {
			inputGuidance()
			return profile.WireGuard{}, "", false
		}
		fmt.Println("VPN sağlayıcısını seçin:")
		fmt.Println("  [1] Cloudflare WARP  (ücretsiz, hesap gerekmez)")
		fmt.Println("  [2] Proton VPN       (Free veya Plus; WireGuard yapılandırma dosyası ile)")
		fmt.Println("  [3] Diğer WireGuard  (herhangi bir standart .conf dosyası)")
		fmt.Println("  [0] Çıkış")
		switch readLine("Seçiminiz [1]: ") {
		case "", "1":
			if wg, ok := setupWARP(); ok {
				return wg, profile.ProviderWARP, true
			}
		case "2":
			printProtonHelp()
			if wg, ok := importConf(); ok {
				return wg, profile.ProviderProton, true
			}
		case "3":
			fmt.Println()
			fmt.Println("WireGuard sağlayıcınızdan indirdiğiniz .conf dosyasını kullanın.")
			if wg, ok := importConf(); ok {
				return wg, profile.ProviderWireGuard, true
			}
		case "0", "q":
			fmt.Println("Kurulum iptal edildi.")
			return profile.WireGuard{}, "", false
		default:
			fmt.Println("Geçersiz seçim.")
		}
		fmt.Println()
	}
}

func setupWARP() (profile.WireGuard, bool) {
	fmt.Printf(`
Cloudflare WARP
---------------
Bu seçenek Cloudflare'in ücretsiz WARP hizmetini kullanır.
Bu bilgisayarda yeni bir anahtar çifti üretilir; Cloudflare'e
yalnızca AÇIK anahtar gönderilir, özel anahtar bilgisayardan çıkmaz.
Devam etmek için Cloudflare'in kullanım koşullarını kabul etmeniz gerekir:
  %s

`, cloudflareTermsURL)
	if !askYesNo("Cloudflare WARP kullanım koşullarını kabul ediyor musunuz?", false) {
		fmt.Println("Koşullar kabul edilmedi; başka bir sağlayıcı seçebilirsiniz.")
		return profile.WireGuard{}, false
	}
	fmt.Println("Cloudflare WARP'a kaydolunuyor...")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	client := &http.Client{
		Timeout: 30 * time.Second,
		// Never follow redirects; RegisterWARP treats 3xx as an error.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	wg, err := provider.RegisterWARP(ctx, client)
	if err != nil {
		fail("Cloudflare WARP kaydı başarısız. İnternet bağlantınızı kontrol edip tekrar deneyin.", err)
		return profile.WireGuard{}, false
	}
	fmt.Println("WARP kaydı tamamlandı.")
	return wg, true
}

func printProtonHelp() {
	fmt.Print(`
Proton VPN WireGuard yapılandırması nasıl indirilir
---------------------------------------------------
1. Tarayıcıda https://account.protonvpn.com adresine girip oturum açın.
2. Soldaki menüden "Downloads" (İndirmeler) bölümüne gidin.
3. "WireGuard configuration" kısmında:
   - Platform olarak "Windows" seçin,
   - NetShield'i kapalı bırakmanız önerilir,
   - Bir sunucu seçin (Free kullanıcılar ücretsiz sunuculardan birini seçebilir),
   - "Create" / "Download" ile .conf dosyasını indirin.
4. Açılan dosya seçicide indirdiğiniz .conf dosyasını seçin.
   Alternatif: "Yol olarak kopyala" ile yolu kopyalayıp aşağıya yapıştırın.

Not: Bu araç çalışırken Proton VPN uygulamasının kendi bağlantısını açmayın.
`)
}

// importConf asks for a WireGuard .conf path and parses it.
func importConf() (profile.WireGuard, bool) {
	for attempt := 0; attempt < 3; attempt++ {
		fmt.Println()
		path := chooseConfPath(pickConfFile, readLine)
		if path == "" {
			return profile.WireGuard{}, false
		}
		if abs, err := filepath.Abs(path); err == nil {
			path = abs
		}
		data, err := readSmallFile(path, maxConfSize)
		if err != nil {
			fail("Dosya okunamadı. Dosyayı seçin veya tam yolunu yapıştırın (Yol olarak kopyala).", err)
			continue
		}
		wg, err := provider.ParseWireGuardConf(data)
		for i := range data {
			data[i] = 0
		}
		if err != nil {
			fail("Bu dosya geçerli bir WireGuard yapılandırması değil.", err)
			continue
		}
		fmt.Println("Yapılandırma okundu. Sunucu:", wg.Endpoint)
		fmt.Println()
		fmt.Println("GÜVENLİK UYARISI: İndirdiğiniz .conf dosyası özel anahtarınızı içerir.")
		fmt.Println("Kurulum bittikten sonra bu dosyayı silmeniz (ve Geri Dönüşüm Kutusunu")
		fmt.Println("boşaltmanız) önerilir:")
		fmt.Println("  ", path)
		return wg, true
	}
	return profile.WireGuard{}, false
}

func readSmallFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("dosya çok büyük; bir WireGuard .conf dosyası birkaç KB'tan küçüktür")
	}
	return data, nil
}

// preflight verifies, without changing anything the MSI owns, that this is
// a complete MSI installation that the LocalSystem service can safely run:
//
//   - this process is the installed aurasplit.exe (file identity);
//   - the install directory and aurasplit.exe are real objects (no links)
//     that only SYSTEM, Administrators or TrustedInstaller can modify (the
//     MSI sets paths.InstallSDDL on the folder);
//   - the AuraSplitTR service exists and runs exactly `"<installed exe>"
//     service` as LocalSystem with the BFE dependency;
//   - the data directory is secured (created or re-secured; this only
//     resets descriptors and moves untrusted entries into quarantine).
func preflight() error {
	ok, err := runningFromInstalled()
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("bu program kurulu kopya değil (%s); MSI paketini kurun", paths.InstalledExePath())
	}
	repair := "MSI paketini yeniden çalıştırıp onarın veya AURA Split TR'yi kaldırıp yeniden kurun"
	if ok, err := paths.IsTrustedAppDir(paths.InstallDir()); err != nil || !ok {
		return fmt.Errorf("kurulum klasörünün izinleri güvenli değil (%s); %s: %v", paths.InstallDir(), repair, err)
	}
	if ok, err := paths.IsTrustedFile(paths.InstalledExePath()); err != nil || !ok {
		return fmt.Errorf("program dosyasının izinleri güvenli değil (%s); %s: %v", paths.InstalledExePath(), repair, err)
	}
	if err := service.Verify(paths.InstalledExePath()); err != nil {
		if errors.Is(err, service.ErrNotInstalled) {
			return fmt.Errorf("AuraSplitTR hizmeti kayıtlı değil; %s", repair)
		}
		return fmt.Errorf("hizmet yapılandırması MSI kurulumuyla uyuşmuyor; %s: %w", repair, err)
	}
	if err := paths.EnsureSecureDir(paths.DataDir()); err != nil {
		return fmt.Errorf("veri klasörü güvenli hale getirilemedi (%s): %w", paths.DataDir(), err)
	}
	return nil
}

// isNotInstalled is a best-effort check used for friendlier messages.
func isNotInstalled(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "does not exist") || strings.Contains(s, "not installed") ||
		strings.Contains(s, "kurulu değil") || strings.Contains(s, "1060")
}
