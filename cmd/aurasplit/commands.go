//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"aurasplit/internal/engine"
	"aurasplit/internal/logfile"
	"aurasplit/internal/msiclean"
	"aurasplit/internal/paths"
	"aurasplit/internal/profile"
	"aurasplit/internal/service"
)

func cmdStatus() int {
	st, pid, err := service.StatusPID()
	if err != nil {
		if isNotInstalled(err) {
			fmt.Println("Hizmet kurulu değil. AuraSplitTR-<sürüm>-x64.msi paketini kurun, ardından Başlat menüsünden \"AURA Split TR - Yapılandır\" seçin.")
		} else {
			fail("Hizmet durumu okunamadı (yönetici olarak deneyin).", err)
		}
		if installed, n, perr := policyInstalled(); perr == nil && installed {
			fmt.Println("UYARI: kalıcı Discord engelleme kuralları (WFP) hâlâ yüklü (", n, "program ). Kaldırmak için: aurasplit.exe recover")
		}
		return 1
	}
	in := statusInput{scmState: st, scmRunning: st == service.StateRunning}
	if in.scmRunning {
		ts, rerr := readState()
		switch {
		case errors.Is(rerr, os.ErrPermission):
			in.stateNote = "ayrıntı için yönetici olarak çalıştırın"
		case rerr != nil:
			in.stateNote = "hizmet henüz durum yazmadı"
		case !stateValid(ts, pid, time.Now(), processStartOf):
			in.stateNote = "durum kaydı eski veya çalışan hizmete ait değil; birkaç saniye sonra tekrar deneyin"
		default:
			in.state = &ts
		}
	}
	if installed, n, perr := policyInstalled(); perr == nil {
		in.policyKnown, in.policyInstalled, in.policyApps = true, installed, n
	} else if in.state != nil && in.state.Protection != nil {
		// No live answer (for example not elevated): use what the
		// running service reported.
		in.policyKnown, in.policyInstalled, in.policyApps = true, in.state.Protection.Applied, in.state.Protection.Apps
		in.policyFromState = true
	}

	fmt.Println("Hizmet:  ", paths.ServiceName)
	for _, l := range describeStatus(in, time.Local) {
		fmt.Println(l)
	}
	fmt.Println("Program: ", paths.InstalledExePath())
	fmt.Println("Günlük:  ", paths.LogPath())

	// The profile is readable only by SYSTEM/Administrators.
	if p, err := profile.Load(paths.ProfilePath()); err == nil {
		fmt.Println("Sağlayıcı:", providerName(p.Provider))
		fmt.Println("Sunucu:  ", p.WireGuard.Endpoint)
	} else if errors.Is(err, os.ErrNotExist) {
		fmt.Println("Profil:   bulunamadı (setup çalıştırın)")
	} else if errors.Is(err, os.ErrPermission) {
		fmt.Println("Profil:   ayrıntılar için yönetici olarak çalıştırın")
	} else {
		fmt.Println("Profil:   okunamadı:", err)
	}
	return 0
}

// statusInput is everything `status` knows; describeStatus turns it into
// lines without any system access (unit-tested).
type statusInput struct {
	scmState        string
	scmRunning      bool
	state           *tunnelState // nil: unknown (see stateNote)
	stateNote       string
	policyKnown     bool
	policyInstalled bool
	policyApps      int
	policyFromState bool
}

func yesNo(b bool) string {
	if b {
		return "EVET"
	}
	return "HAYIR"
}

// describeStatus prints each state separately. They are independent and
// can be true at the same time: SERVICE_RUNNING (SCM), TUNNEL_INITIALIZED
// (sing-box started the normal configuration), one of the VPN_* results
// (probe through the tunnel), PROTECTION_ACTIVE (persistent WFP policy).
func describeStatus(in statusInput, loc *time.Location) []string {
	var out []string
	add := func(f string, a ...any) { out = append(out, fmt.Sprintf(f, a...)) }
	ts := in.state
	when := func(t time.Time) string { return t.In(loc).Format("2006-01-02 15:04:05") }

	add("SERVICE_RUNNING:           %s (Windows hizmet yöneticisi: %s)", yesNo(in.scmRunning), in.scmState)

	tunnel := false
	switch {
	case !in.scmRunning:
		add("TUNNEL_INITIALIZED:        HAYIR (hizmet çalışmıyor)")
	case ts == nil:
		add("TUNNEL_INITIALIZED:        bilinmiyor (%s)", in.stateNote)
	default:
		switch engine.State(ts.State) {
		case engine.StateTunnelStarted:
			tunnel = true
			add("TUNNEL_INITIALIZED:        EVET — yapılandırma uygulandı (%s)", when(ts.Time))
		case engine.StateStarting:
			add("TUNNEL_INITIALIZED:        HAYIR — başlatılıyor (%s)", when(ts.Time))
		case engine.StateBlocking:
			add("TUNNEL_INITIALIZED:        HAYIR — tünel başlatılamadı, Discord engelleniyor, yeniden deneniyor (%s)", when(ts.Time))
		case engine.StateError:
			add("TUNNEL_INITIALIZED:        HAYIR — HATA (%s)", when(ts.Time))
		case engine.StateStopped:
			add("TUNNEL_INITIALIZED:        HAYIR — durduruldu (%s)", when(ts.Time))
		default:
			add("TUNNEL_INITIALIZED:        HAYIR — %s (%s)", ts.State, when(ts.Time))
		}
		if ts.Detail != "" {
			add("  Ayrıntı:                 %s", ts.Detail)
		}
	}

	switch {
	case !tunnel:
		add("VPN bağlantısı:            denetlenmiyor (tünel çalışmıyor)")
	case ts.Connectivity == "":
		add("VPN bağlantısı:            henüz doğrulanmadı (ilk deneme tünel başladıktan yaklaşık 10 saniye sonra)")
	case ts.Connectivity == string(engine.ConnConnecting):
		add("VPN bağlantısı:            VPN_CONNECTING — bağlanıyor")
	default:
		line := fmt.Sprintf("VPN bağlantısı:            %s (son deneme %s", ts.Connectivity, when(ts.ConnectivityTime))
		if !ts.ConnectivityOK.IsZero() {
			line += ", son başarılı " + when(ts.ConnectivityOK)
		}
		if ts.ProbeFailures > 0 {
			line += fmt.Sprintf(", art arda %d başarısız", ts.ProbeFailures)
		}
		if ts.ConnectivityDetail != "" {
			line += ", " + ts.ConnectivityDetail
		}
		out = append(out, line+")")
	}

	var prot *protectionState
	if ts != nil && in.scmRunning {
		prot = ts.Protection
	}
	permit := prot != nil && prot.Permit
	// The permit is only claimed for what it covers: a partial or failed
	// permit is shown as such.
	permitFull := permit && prot.PermitComplete
	switch {
	case !in.policyKnown:
		add("PROTECTION_ACTIVE:         bilinmiyor (WFP okunamadı; yönetici olarak çalıştırın)")
	case in.policyInstalled:
		src := ""
		if in.policyFromState {
			src = ", hizmetin bildirdiği"
		}
		permitText := "kapalı"
		switch {
		case permitFull:
			permitText = fmt.Sprintf("açık (%d program)", prot.PermitApps)
		case permit:
			permitText = fmt.Sprintf("açık, EKSİK (%d/%d program; yeniden deneniyor)", prot.PermitApps, prot.Apps)
		}
		add("PROTECTION_ACTIVE:         EVET — kalıcı WFP politikası yüklü (%d Discord programı%s); tünel izni: %s",
			in.policyApps, src, permitText)
	default:
		add("PROTECTION_ACTIVE:         HAYIR — kalıcı WFP politikası yok")
	}
	if prot != nil && prot.Applied {
		if prot.Complete {
			add("  Kapsam:                  TAM — bulunan %d Discord programının tümü engelleniyor (yalnızca bulunanlar)", prot.Apps)
		} else {
			reason := prot.Incomplete
			if reason == "" {
				reason = "bulma tamamlanmadı"
			}
			add("  Kapsam:                  EKSİK — %s; yalnızca %d program fail-closed, hiçbir kural silinmedi, yeniden deneniyor", reason, prot.Apps)
		}
	}
	if prot != nil && prot.Error != "" {
		add("  WFP hatası:              %s", prot.Error)
	}

	switch {
	case in.policyKnown && in.policyInstalled && tunnel && permitFull:
		add("Discord şu anda:           TÜNELDEN (tünel dışında engelli)")
	case in.policyKnown && in.policyInstalled && tunnel && permit:
		add("Discord şu anda:           TÜNELDEN, ancak bazı Discord programlarının tünel izni eksik (onlar engelli)")
	case in.policyKnown && in.policyInstalled:
		add("Discord şu anda:           ENGELLİ (fail-closed; doğrudan bağlantı için: aurasplit.exe disable)")
	case tunnel:
		add("Discord şu anda:           tünele yönlendiriliyor, ancak kalıcı koruma YOK (hizmet durursa doğrudan bağlanır)")
	case in.policyKnown && in.scmRunning && ts != nil && engine.State(ts.State) == engine.StateBlocking:
		add("Discord şu anda:           engelleniyor (yalnızca hizmet çalışırken)")
	case in.policyKnown:
		add("Discord şu anda:           DOĞRUDAN bağlantı (korunmuyor)")
	default:
		add("Discord şu anda:           bilinmiyor")
	}
	if ts != nil && ts.LogDegraded {
		add("Günlük:                    UYARI — günlük dosyası döndürülemiyor; yeni satırlar şimdilik yazılmıyor")
	}
	return out
}

func cmdStart() int {
	// Re-enables a service that disable/recover set to Disabled (and the
	// manual start type the MSI registers).
	if err := service.SetAutoStart(true); err != nil && !isNotInstalled(err) {
		fmt.Println("Uyarı: hizmet otomatik başlatmaya alınamadı:", err)
	}
	if !startAndReport(setupStartTimeout) {
		return 1
	}
	fmt.Println("Hizmet başlatıldı; Discord engelleme kuralları yeniden uygulanır.")
	fmt.Println("Discord'u tamamen kapatıp yeniden açın.")
	return 0
}

// resumeDecision decides whether `start --msi` (run by the MSI after an
// upgrade or repair, which re-register the service as manual start and
// leave it stopped) brings the service back. Only a configured
// installation whose protection was active is resumed: no profile means
// never configured; no persistent policy means the user ran disable or
// recover, or never finished setup. Pure (unit-tested).
func resumeDecision(profileErr error, policy bool, policyErr error) (bool, string) {
	switch {
	case errors.Is(profileErr, os.ErrNotExist):
		return false, "profil yok (henüz yapılandırılmadı); hizmet başlatılmadı"
	case profileErr != nil:
		return false, "profil denetlenemedi; hizmet başlatılmadı: " + profileErr.Error()
	case policyErr != nil:
		return false, "WFP politikası okunamadı; hizmet başlatılmadı: " + policyErr.Error()
	case !policy:
		return false, "kalıcı Discord politikası yok (disable/recover sonrası); hizmet başlatılmadı"
	}
	return true, "yapılandırılmış ve korumalı kurulum; hizmet yeniden başlatılıyor"
}

// cmdStartMSI is `start --msi`: non-interactive, never prompts, always
// returns 0 (the MSI custom action ignores the result; the output goes
// into the MSI log).
func cmdStartMSI() int {
	_, perr := os.Lstat(paths.ProfilePath())
	installed, _, err := policyInstalled()
	ok, why := resumeDecision(perr, installed, err)
	fmt.Println("AURA Split TR (msi):", why)
	if !ok {
		return 0
	}
	if err := service.EnableNonCrashRecovery(); err != nil {
		fmt.Println("Uyarı: kurtarma ayarı:", err)
	}
	if err := service.SetAutoStart(true); err != nil {
		fmt.Println("Uyarı: hizmet otomatik başlatmaya alınamadı:", err)
		return 0
	}
	if err := service.StartWait(setupStartTimeout); err != nil {
		fmt.Println("Uyarı: hizmet başlatılamadı:", err)
		return 0
	}
	fmt.Println("Hizmet çalışıyor.")
	return 0
}

// stopOK is true when err from service.Stop means "stopped or was not
// running".
func stopOK(err error) bool {
	return err == nil || errors.Is(err, service.ErrNotRunning)
}

func cmdStop() int {
	if err := service.Stop(); !stopOK(err) {
		fail("Hizmet durdurulamadı.", err)
		return 1
	}
	fmt.Println("Hizmet durduruldu.")
	if installed, _, err := policyInstalled(); err == nil && installed {
		fmt.Println("Discord ENGELLİ kalır (fail-closed): tünel çalışmadığı için Discord hiçbir yere bağlanamaz.")
		fmt.Println("Tekrar tünelden kullanmak için:      aurasplit.exe start")
		fmt.Println("Doğrudan bağlantıya izin vermek için: aurasplit.exe disable")
	} else {
		fmt.Println("Kalıcı engelleme kuralı bulunamadı; Discord doğrudan bağlantıyı kullanır.")
	}
	return 0
}

func cmdRestart() int {
	if err := service.Stop(); !stopOK(err) {
		fail("Hizmet durdurulamadı.", err)
		return 1
	}
	if err := service.Start(); err != nil {
		fail("Hizmet yeniden başlatılamadı (devre dışıysa: aurasplit.exe start). Günlük: "+paths.LogPath(), err)
		return 1
	}
	fmt.Println("Hizmet yeniden başlatıldı.")
	return 0
}

// cmdDisable stops the service, keeps it from starting at boot and
// removes the WFP policy: Discord then uses the direct connection.
func cmdDisable() int {
	fmt.Println("UYARI: Bu komut AURA Split TR'yi devre dışı bırakır:")
	fmt.Println("  - hizmet durdurulur ve bilgisayar açılışında başlamaz,")
	fmt.Println("  - kalıcı Discord engelleme kuralları (WFP) kaldırılır,")
	fmt.Println("  - Discord VPN OLMADAN, DOĞRUDAN bağlantınızı kullanır.")
	fmt.Println("Yeniden etkinleştirmek için: aurasplit.exe start")
	if !askYesNo("Devam edilsin mi?", false) {
		fmt.Println("İptal edildi; hiçbir şey değiştirilmedi.")
		return 1
	}
	// Disabled BEFORE the stop: a recovery restart queued by the SCM (or a
	// start at boot) can then no longer bring the service back and re-apply
	// the policy after it was removed.
	if err := service.Disable(); err != nil && !isNotInstalled(err) {
		fail("Hizmet devre dışı bırakılamadı; hiçbir kural kaldırılmadı.", err)
		return 1
	}
	if err := service.Stop(); !stopOK(err) && !isNotInstalled(err) {
		fail("Hizmet durdurulamadı; kurallar kaldırılmadı (hizmet devre dışı; yeniden etkinleştirmek için: aurasplit.exe start).", err)
		return 1
	}
	if err := removePolicy(); err != nil {
		fail("Discord engelleme kuralları kaldırılamadı. 'aurasplit.exe recover' deneyin.", err)
		return 1
	}
	fmt.Println("- Hizmet durduruldu, kurallar kaldırıldı. Discord artık doğrudan bağlantıyı kullanır")
	fmt.Println("  (Discord'u yeniden açmanız gerekebilir).")
	return 0
}

// cmdRecover is the emergency path: it works without a profile and from
// any copy of the exe (the WFP provider key is compiled in). It removes
// every WFP object of our provider and stops the service.
//
// Exit code 0 means the policy is gone (or was never there: removal is
// idempotent). With msi (the MSI uninstall custom action, Return="check")
// any failure is non-zero so Windows Installer rolls the uninstall back and
// keeps aurasplit.exe, the recovery tool, in place. In that mode a service
// that cannot be stopped is a failure too: while it runs, its policy loop
// could re-apply the persistent blocks after they were removed.
func cmdRecover(msi bool) int {
	return runRecover(msi, recoverOps{
		disable:   service.Disable,
		stop:      service.Stop,
		remove:    removePolicy,
		installed: policyInstalled,
	})
}

// recoverOps are the system operations of recover (fakes in tests).
type recoverOps struct {
	disable, stop, remove func() error
	installed             func() (bool, int, error)
}

func runRecover(msi bool, ops recoverOps) int {
	return msiclean.Recover(msi, msiclean.RecoverOps{
		Disable: ops.disable, Stop: ops.stop, Remove: ops.remove, Installed: ops.installed,
	})
}

// cmdUninstall no longer removes anything by itself when a user runs it:
// the program, the service, the Start Menu entry and the data folder
// belong to the MSI package, and only Windows Installer removes them (the
// MSI's uninstall runs `recover --msi` first, removes the service/files,
// then runs the packaged `uninstall --msi` at commit for the data folder).
func cmdUninstall() int {
	fmt.Println(`AURA Split TR, Windows Installer (MSI) ile kurulur ve kaldırılır.

Kaldırmak için:
  Ayarlar > Uygulamalar > Yüklü uygulamalar > AURA Split TR > Kaldır
  (veya Denetim Masası > Programlar ve Özellikler).

Kaldırma; Discord engelleme kurallarını (WFP), hizmeti, programı ve
%ProgramData%\AuraSplitTR içindeki AURA Split TR dosyalarını (profil = VPN
özel anahtarı, günlükler, durum) siler. Klasörde beklenmeyen bir şey varsa
ya da klasör güvenilir değilse hiçbir şey silinmez; klasör elle incelemeniz
için bırakılır. Ardından Discord doğrudan bağlantıyı kullanır.

Yalnızca Discord'u hemen doğrudan bağlantıya döndürmek için:
  aurasplit.exe recover`)
	return 1
}

// cmdUninstallMSI is `uninstall --msi`, run by the MSI on a full uninstall
// (commit, LocalSystem) from the packaged executable after `recover --msi`
// and removal of the installed files. It runs recover again (normally nothing is
// left) and only if that succeeded removes the application's own files
// from the data directory with paths.CleanDataDir: no recursive deletion,
// no link is followed, and an untrusted directory or one with unexpected
// content is left untouched for manual inspection. Data cleanup
// never fails the uninstall (exit 0); a recover failure returns 1 and is
// recorded as an action exit code (Return=ignore at commit; stdout is not
// forwarded to the MSI log). It never touches the program directory, which Windows
// Installer owns.
func cmdUninstallMSI() int {
	return msiclean.Uninstall(func() int { return cmdRecover(true) })
}

func describeCleanup(dir string, res paths.CleanResult) []string {
	return msiclean.DescribeCleanup(dir, res)
}

func quarantineDirs() (ours, foreign []string) { return msiclean.QuarantineDirs() }

func consoleLog(level, msg string) {
	fmt.Fprintf(os.Stderr, "%s %s [aurasplit] %s\n", time.Now().Format("2006-01-02 15:04:05"), level, logfile.ScrubString(msg))
}

func cmdRun(debug bool) int {
	if st, err := service.Status(); err == nil && st != service.StateStopped {
		failMsg("Hizmet çalışıyor (" + st + "). İki tünel çakışır; önce 'aurasplit.exe stop' çalıştırın.")
		return 1
	}
	if err := paths.EnsureSecureDir(paths.DataDir()); err != nil {
		fail("Veri klasörü güvenli değil veya oluşturulamadı: "+paths.DataDir(), err)
		return 1
	}
	p, err := profile.Load(paths.ProfilePath())
	if err != nil {
		fail("Profil yüklenemedi ("+paths.ProfilePath()+"). Önce setup çalıştırın.", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Println("Ön planda çalışıyor. Çıkmak için Ctrl+C.")
	fmt.Println("Sağlayıcı:", providerName(p.Provider), "| Sunucu:", p.WireGuard.Endpoint)
	if debug {
		fmt.Println("Hata ayıklama günlüğü açık: her bağlantı ve hedef adresi bu pencereye yazılır.")
		fmt.Println("Günlüğü paylaşmadan önce kullanıcı adlarını ve adresleri gizleyin.")
	}
	fmt.Println("Günlük bu pencereye yazılır (dosyaya yazılmaz).")
	// Same policy handling as the service: persistent blocks first, the
	// tunnel permit after the tunnel starts.
	prot := startProtection(ctx, consoleLog, nil)
	err = engine.Run(ctx, p, engine.RunOptions{
		Debug:      debug,
		OnTunnelUp: prot.onTunnelUp,
		OnConnectivity: func(r engine.ProbeResult) {
			consoleLog("INFO", fmt.Sprintf("connectivity: %s %s", r.State, r.Detail))
		},
	})
	prot.stop()
	if err != nil && !errors.Is(err, context.Canceled) {
		fail("Tünel çalıştırılamadı.", err)
		return 1
	}
	fmt.Println("Durduruldu. Kalıcı kurallar yüklüyse Discord şimdi engellidir; hizmeti başlatın: aurasplit.exe start")
	return 0
}

// profileRetryWait is how long the service waits after a profile error
// before the supervisor retries (Discord stays blocked meanwhile).
var profileRetryWait = 60 * time.Second

// cmdService is the SCM entry point.
func cmdService() int {
	if err := service.RunService(serviceRun); err != nil {
		fmt.Fprintln(os.Stderr, "service:", err)
		return 1
	}
	return 0
}

// serviceRun is one supervised service run. Each (re)start first
// re-verifies the data directory, so the profile and the log are only ever
// read from or written to a directory that only SYSTEM and Administrators
// control.
//
// A close timeout inside the engine is terminal for the process (see
// engine.ErrCloseTimeout): serviceRun returns service.ErrFatal, the
// supervisor stops retrying and the service stops with a non-zero exit
// code, which triggers the configured SCM restart.
//
// Order: persistent WFP policy before the tunnel; engine.Run closes the
// Discord permit before sing-box. Shutdown then stops the policy loop,
// writes the final state, joins the state writer and only then closes the
// log. Fail-closed never depends on this cleanup: the persistent filters
// stay and the dynamic permit dies with the process.
func serviceRun(ctx context.Context) error {
	if err := paths.EnsureSecureDir(paths.DataDir()); err != nil {
		// Nothing is written into a directory that is not secured.
		return fmt.Errorf("secure data directory: %w", err)
	}
	sw := newStateWriter()
	logw, err := logfile.Open(paths.DataDir(), paths.LogName, logfile.DefaultMaxSize, logfile.DefaultBackups)
	if err != nil {
		sw.set(engine.StateError, "open log: "+err.Error())
		return fmt.Errorf("open log: %w", err)
	}
	sw.log, sw.logDegraded = logw, logw.Degraded
	swCtx, stopSW := context.WithCancel(context.Background())
	swDone := sw.startAsync(swCtx)
	defer func() {
		stopSW()
		select {
		case <-swDone: // C-2: no state write after the log is closed
		case <-time.After(2 * time.Second):
		}
		// Run drained its log queue before returning.
		_ = logw.Close()
	}()
	sw.set(engine.StateStarting, "")

	prot := startProtection(ctx, sw.logf, sw.setProtection)
	defer prot.stop()

	p, err := profile.Load(paths.ProfilePath())
	if err != nil {
		msg := "load profile (run setup again; Discord stays blocked, `aurasplit recover` allows direct access): " + err.Error()
		sw.logf("ERROR", msg)
		sw.set(engine.StateError, msg)
		select {
		case <-ctx.Done():
			sw.set(engine.StateStopped, "")
			return nil
		case <-time.After(profileRetryWait):
		}
		return errors.New(msg)
	}
	err = engine.Run(ctx, p, engine.RunOptions{
		LogWriter:      logw,
		OnState:        sw.set,
		OnTunnelUp:     prot.onTunnelUp,
		OnConnectivity: sw.setConnectivity,
	})
	if errors.Is(err, engine.ErrCloseTimeout) && ctx.Err() == nil {
		// A sing-box instance did not close: it may still own the TUN,
		// routes and filters. No new instance is started in this process;
		// the service exits with a failure code so the SCM recovery action
		// restarts it in a fresh process. The persistent WFP blocks stay
		// in place meanwhile (fail-closed).
		sw.logf("ERROR", "tunnel instance did not close; exiting the service process for a clean restart: "+err.Error())
		return fmt.Errorf("%w: %w", service.ErrFatal, err)
	}
	return err
}

func providerName(id string) string {
	switch id {
	case profile.ProviderWARP:
		return "Cloudflare WARP"
	case profile.ProviderProton:
		return "Proton VPN"
	case profile.ProviderWireGuard:
		return "WireGuard"
	}
	return id
}
