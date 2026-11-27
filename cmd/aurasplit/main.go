//go:build windows

// Command aurasplit is the AURA Split TR command-line tool and Windows
// service binary. It routes only Discord (and its updater) through a
// WireGuard tunnel; everything else stays on the direct connection.
//
// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"fmt"
	"os"
	"strings"

	"aurasplit/internal/manifest"
	"aurasplit/internal/service"
)

// version is set at build time: -ldflags "-X main.version=..."
var version = "dev"

// elevatedFlag is appended when the tool relaunches itself with
// administrator rights, so the new console window waits for Enter
// before closing.
const elevatedFlag = "--elevated"

// debugFlag raises the foreground log level (aurasplit run --debug).
const debugFlag = "--debug"

// msiFlag marks a command run by Windows Installer from a deferred,
// non-impersonated custom action (LocalSystem, no desktop): it never
// prompts, never relaunches itself through UAC and never waits for Enter.
// Only recover, recover-rollback, start and uninstall accept it.
const msiFlag = "--msi"

// checkMSIFlag reports whether cmd may run with --msi.
func checkMSIFlag(cmd string) error {
	switch cmd {
	case "recover-rollback", "recover", "kurtar", "start", "baslat", "uninstall", "kaldir":
		return nil
	}
	return fmt.Errorf("%s yalnızca recover, start ve uninstall ile kullanılabilir", msiFlag)
}

func main() {
	args, elevated := splitArgs(os.Args[1:])
	args, debug := takeFlag(args, debugFlag)
	args, msi := takeFlag(args, msiFlag)
	args, saveState := takeFlag(args, "--save-state")
	if saveState && (!msi || len(args) != 1 || (args[0] != "recover" && args[0] != "kurtar")) {
		fmt.Fprintln(os.Stderr, "--save-state yalnızca recover --msi ile kullanılabilir.")
		os.Exit(2)
	}
	if msi {
		cmd := ""
		if len(args) > 0 {
			cmd = strings.ToLower(args[0])
		}
		os.Exit(runMSI(cmd, saveState))
	}

	if len(args) == 0 {
		// The Service Control Manager normally passes "service", but be
		// defensive in case the binary is started by the SCM without args.
		if isSvc, err := service.IsWindowsService(); err == nil && isSvc {
			os.Exit(cmdService())
		}
		args = []string{"setup"}
	}

	cmd := strings.ToLower(args[0])
	if cmd == "setup" || cmd == "kurulum" {
		// Pin the running image before anything else: setup decides by its
		// file identity that it runs from the MSI-installed copy, and while
		// the handle is open the file cannot be replaced.
		selfImage, selfImageErr = openSelfImage()
	}
	var code int
	switch cmd {
	case "manifest":
		if len(args) != 2 || args[1] != "--json" {
			fmt.Fprintln(os.Stderr, "Kullanım: aurasplit.exe manifest --json")
			code = 2
		} else {
			_, err := os.Stdout.Write(manifest.JSON())
			if err != nil {
				code = 1
			}
		}

	case "setup", "kurulum":
		code = cmdSetup(elevated)
	case "status", "durum":
		code = cmdStatus()
	case "start", "baslat":
		code = withAdmin([]string{cmd}, elevated, cmdStart)
	case "stop", "durdur":
		code = withAdmin([]string{cmd}, elevated, cmdStop)
	case "restart", "yenidenbaslat":
		code = withAdmin([]string{cmd}, elevated, cmdRestart)
	case "uninstall", "kaldir":
		// Only explains how to uninstall through Windows; no admin needed.
		code = cmdUninstall()
	case "disable", "devredisi":
		code = withAdmin([]string{cmd}, elevated, cmdDisable)
	case "recover", "kurtar":
		code = withAdmin([]string{cmd}, elevated, func() int { return cmdRecover(false) })
	case "run":
		relaunch := []string{cmd}
		if debug {
			relaunch = append(relaunch, debugFlag)
		}
		code = withAdmin(relaunch, elevated, func() int { return cmdRun(debug) })
	case "service":
		code = cmdService()
	case "version", "--version", "-v":
		fmt.Printf("aurasplit %s\n", version)
	case "help", "yardim", "-h", "--help", "/?":
		printHelp()
	default:
		fmt.Fprintf(os.Stderr, "Bilinmeyen komut: %q\n\n", args[0])
		printHelp()
		code = 2
	}

	if elevated && cmd != "service" {
		waitEnter()
	}
	os.Exit(code)
}

// splitArgs removes internal flags from the argument list.
func splitArgs(in []string) (args []string, elevated bool) {
	for _, a := range in {
		if a == elevatedFlag {
			elevated = true
			continue
		}
		args = append(args, a)
	}
	return args, elevated
}

// takeFlag removes every occurrence of flag from args.
func takeFlag(in []string, flag string) (args []string, found bool) {
	for _, a := range in {
		if strings.EqualFold(a, flag) {
			found = true
			continue
		}
		args = append(args, a)
	}
	return args, found
}

// runMSI runs a command for Windows Installer (see msiFlag). It requires an
// elevated token (the custom actions run as LocalSystem) and never
// prompts.
func runMSI(cmd string, saveState bool) int {
	if err := checkMSIFlag(cmd); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if !service.IsAdmin() {
		fmt.Fprintln(os.Stderr, msiFlag+" yönetici (veya SYSTEM) olarak çalıştırılmalıdır; hiçbir şey yapılmadı.")
		return 1
	}
	switch cmd {
	case "recover-rollback":
		return cmdRecoverRollback()
	case "recover", "kurtar":
		if saveState {
			return cmdSaveRecoverState()
		}
		return cmdRecover(true)
	case "start", "baslat":
		return cmdStartMSI()
	default: // uninstall, kaldir
		return cmdUninstallMSI()
	}
}

// withAdmin runs fn directly if the process is elevated; otherwise it
// relaunches the same command with administrator rights (UAC). It is used
// only for commands a user starts interactively.
func withAdmin(args []string, elevated bool, fn func() int) int {
	if service.IsAdmin() {
		return fn()
	}
	if elevated {
		// We were already relaunched but still have no admin token.
		failMsg("Bu komut yönetici izni gerektiriyor ve izin alınamadı.")
		return 1
	}
	fmt.Println("Bu komut yönetici izni gerektiriyor; izin isteniyor...")
	if err := relaunchElevated(args); err != nil {
		fail("Yönetici olarak yeniden başlatılamadı.", err)
		return 1
	}
	return 0
}

func printHelp() {
	fmt.Printf(`AURA Split TR %s
Yalnızca Discord trafiğini VPN (WireGuard) tünelinden geçirir; geri kalan her şey doğrudan bağlantıyı kullanır.

Kullanım: aurasplit.exe <komut>

Kurulum ve kaldırma Windows Installer (MSI) paketiyle yapılır:
  AuraSplitTR-<sürüm>-x64.msi; kaldırma: Ayarlar > Uygulamalar > AURA Split TR.

Komutlar:
  setup      Yapılandırma sihirbazı: sağlayıcı seçimi, profil, hizmeti başlatma
             (yalnızca kurulu kopyadan; Başlat menüsü: "AURA Split TR - Yapılandır")
  status     Hizmet ve tünel durumunu göster
  start      Hizmeti başlat (açılışta otomatik başlatmayı da açar)
  stop       Hizmeti durdur — Discord ENGELLİ kalır (fail-closed)
  restart    Hizmeti yeniden başlat
  disable    Hizmeti durdur ve Discord engelleme kurallarını kaldır
             (Discord VPN olmadan DOĞRUDAN bağlanır; onay ister)
  recover    Kurtarma: engelleme kurallarını her durumda kaldır ve hizmeti durdur
             (profil bozuk olsa da çalışır)
  uninstall  Windows üzerinden (MSI) nasıl kaldırılacağını gösterir
  run        Ön planda çalıştır (hata ayıklama; günlük konsola yazılır, Ctrl+C ile çık)
             --debug: her bağlantıyı günlüğe yaz (ziyaret edilen adresleri içerir)
  version    Sürümü göster
  manifest --json  Korunan program sözleşmesini JSON olarak göster
  help       Bu yardımı göster

Yönetici gerektiren komutlar gerekirse izin ister.
`, version)
}
