//go:build windows

// Package service controls and hosts the AURA Split TR Windows service.
// The service itself is registered and removed by the MSI package.
package service

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"aurasplit/internal/logfile"
	"aurasplit/internal/paths"
)

const (
	DisplayName = "AURA Split TR (Discord tunnel)"
	Description = "Routes only Discord (app and updater) traffic through a WireGuard tunnel."

	// Status strings. They always contain the English keyword so callers
	// can match on it ("running", "stopped").
	StateRunning      = "running (çalışıyor)"
	StateStopped      = "stopped (durduruldu)"
	StateStartPending = "start pending (başlatılıyor)"
	StateStopPending  = "stop pending (durduruluyor)"
	StatePaused       = "paused (duraklatıldı)"
	StateNotInstalled = "not installed (kurulu değil)"

	pollInterval = 300 * time.Millisecond
)

// ErrFatal marks a run error after which this process must not try again
// (for example a tunnel instance that did not close and may still own the
// TUN). The supervisor then stops, the service reports a non-zero exit
// code and the SCM recovery action restarts it in a fresh process.
var ErrFatal = errors.New("fatal service error, restarting the process")

// Dependencies are the services that must run before ours: the Base
// Filtering Engine (WFP, used by sing-tun and by the fail-closed policy).
var Dependencies = []string{"BFE"}

// Variables so tests can shorten the timing and avoid the event log.
var (
	stopTimeout    = 20 * time.Second
	retryDelay     = 10 * time.Second
	reportRunError = reportRunErrorEventLog
	// reportStopTimeout is called when run did not return in time.
	reportStopTimeout = func() {
		writeEventLog(true, "service stop timed out; the process exits without a complete shutdown (Discord stays blocked by the persistent WFP policy)")
	}
	// reportFatal is called when run ended with ErrFatal.
	reportFatal = func(err error) {
		writeEventLog(true, fmt.Sprintf("service exits for a restart by the service manager: %v", err))
	}
)

// ErrNotInstalled is returned when the service does not exist.
var ErrNotInstalled = errors.New("service does not exist: " + StateNotInstalled)

// IsAdmin reports whether the current process token is elevated.
func IsAdmin() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// IsWindowsService reports whether the process was started by the SCM.
func IsWindowsService() (bool, error) {
	return svc.IsWindowsService()
}

func connect() (*mgr.Mgr, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, fmt.Errorf("connect to service manager: %w", err)
	}
	return m, nil
}

func openService(m *mgr.Mgr) (*mgr.Service, error) {
	s, err := m.OpenService(paths.ServiceName)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil, ErrNotInstalled
		}
		return nil, fmt.Errorf("open service: %w", err)
	}
	return s, nil
}

// The service is created, updated and deleted only by the Windows
// Installer package (installer/AuraSplitTR.wxs): the CLI never registers a
// service itself. The MSI registers it as manual start (an unconfigured
// service must not block Discord at boot), LocalSystem, own process,
// depending on BFE, with the command line `"<INSTALLFOLDER>aurasplit.exe"
// service`, restart-on-failure actions and the event log source.

// Verify checks that the registered service is the one the MSI package
// creates for exePath: command line exactly `"<exePath>" service`, own
// process, LocalSystem and the BFE dependency. setup refuses to configure a
// service that does not match (for example one left behind by an older
// self-installing build that pointed elsewhere).
func Verify(exePath string) error {
	if exePath == "" {
		return errors.New("empty executable path")
	}
	m, err := connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := openService(m)
	if err != nil {
		return err
	}
	defer s.Close()
	got, err := s.Config()
	if err != nil {
		return fmt.Errorf("read service config: %w", err)
	}
	return checkConfig(got, exePath)
}

// checkConfig is the pure part of Verify (unit-tested).
func checkConfig(got mgr.Config, exePath string) error {
	// Paths on Windows compare case-insensitively; the executable must be
	// quoted (an unquoted path with spaces is the classic "unquoted service
	// path" hijack) and the only argument must be "service".
	exe, args, ok := splitQuotedCommandLine(got.BinaryPathName)
	if !ok || !strings.EqualFold(exe, strings.Trim(exePath, `"`)) || args != "service" {
		return fmt.Errorf("service command line is %q, expected %q", got.BinaryPathName, quotedCommandLine(exePath))
	}
	if got.ServiceType&windows.SERVICE_WIN32_OWN_PROCESS == 0 {
		return fmt.Errorf("service type is 0x%x, expected an own-process service", got.ServiceType)
	}
	if got.ServiceStartName != "" && !strings.EqualFold(got.ServiceStartName, "LocalSystem") {
		return fmt.Errorf("service runs as %q, expected LocalSystem", got.ServiceStartName)
	}
	if !hasDependencies(got.Dependencies, Dependencies) {
		return fmt.Errorf("service dependencies are %q, expected %q", got.Dependencies, Dependencies)
	}
	return nil
}

// EnableNonCrashRecovery makes the SCM run the failure actions (restart
// after 5 s, authored by the MSI) also when the service stops with a
// non-zero exit code (service.ErrFatal), not only when the process crashes.
// The WiX v5 util extension cannot set this flag, so setup sets it.
func EnableNonCrashRecovery() error {
	m, err := connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := openService(m)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return fmt.Errorf("set recovery flag: %w", err)
	}
	return nil
}

// hasDependencies reports whether every name in want appears in got
// (case-insensitive; the SCM may return group names with a '+' prefix).
func hasDependencies(got, want []string) bool {
	for _, w := range want {
		found := false
		for _, g := range got {
			if strings.EqualFold(strings.TrimPrefix(g, "+"), w) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// SetAutoStart switches the start type to automatic (true) or manual
// (false). setup and start use it: the MSI registers the service as
// manual start, and disable/recover set it to Disabled.
func SetAutoStart(auto bool) error {
	want := uint32(mgr.StartManual)
	if auto {
		want = mgr.StartAutomatic
	}
	return setStartType(want)
}

// Disable sets the start type to SERVICE_DISABLED. disable and recover
// (also from the MSI uninstall) call it BEFORE stopping the service: the SCM cannot start a
// disabled service, so neither a recovery restart that is already queued
// nor a boot start can re-apply the WFP policy after it was removed.
// SetAutoStart(true) (start, setup) enables it again.
func Disable() error { return setStartType(mgr.StartDisabled) }

// Start types as stored by GetStartType / accepted by SetStartType (the
// SERVICE_*_START values).
const (
	StartAutomatic = mgr.StartAutomatic
	StartManual    = mgr.StartManual
	StartDisabled  = mgr.StartDisabled
)

// GetStartType returns the configured start type (SERVICE_AUTO_START,
// SERVICE_DEMAND_START or SERVICE_DISABLED; boot/system starts are returned
// as they are). `recover --msi --save-state` records it so the MSI
// rollback can restore it.
func GetStartType() (uint32, error) {
	m, err := connect()
	if err != nil {
		return 0, err
	}
	defer m.Disconnect()
	s, err := openService(m)
	if err != nil {
		return 0, err
	}
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		return 0, fmt.Errorf("read service config: %w", err)
	}
	return cfg.StartType, nil
}

// SetStartType sets one of the three start types above (used by the MSI
// rollback of recover to restore the recorded value).
func SetStartType(t uint32) error {
	switch t {
	case StartAutomatic, StartManual, StartDisabled:
		return setStartType(t)
	}
	return fmt.Errorf("unsupported start type %d", t)
}

func setStartType(want uint32) error {
	m, err := connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := openService(m)
	if err != nil {
		return err
	}
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		return fmt.Errorf("read service config: %w", err)
	}
	if cfg.StartType == want {
		return nil
	}
	cfg.StartType = want
	if err := s.UpdateConfig(cfg); err != nil {
		return fmt.Errorf("update service config: %w", err)
	}
	return nil
}

func quotedCommandLine(exePath string) string {
	return `"` + strings.Trim(exePath, `"`) + `" service`
}

// splitQuotedCommandLine splits `"<exe>" <args>` into the executable and
// the trimmed argument string. ok is false unless the executable is quoted.
func splitQuotedCommandLine(cmdline string) (exe, args string, ok bool) {
	s := strings.TrimSpace(cmdline)
	if !strings.HasPrefix(s, `"`) {
		return "", "", false
	}
	end := strings.Index(s[1:], `"`)
	if end < 1 {
		return "", "", false
	}
	exe = s[1 : end+1]
	rest := s[end+2:]
	if rest != "" && rest[0] != ' ' && rest[0] != '\t' {
		return "", "", false
	}
	return exe, strings.TrimSpace(rest), true
}

// ErrStartPending is returned by StartWait when the service is still in
// START_PENDING after the timeout: the process was created but never
// reached the service dispatcher. Our handler reports RUNNING right after
// START_PENDING, so this usually means something outside the program holds
// the new process (for example an antivirus scan of a new executable).
var ErrStartPending = errors.New("service is still start pending (başlatılıyor)")

// Start starts the service and waits up to 20 s for it to leave
// StartPending.
func Start() error { return StartWait(stopTimeout) }

// StartWait starts the service and waits up to timeout until it is
// running. It returns nil if it was already running, an error naming the
// exit codes if it stopped during the start, and an error wrapping
// ErrStartPending if it is still starting when the timeout expires.
func StartWait(timeout time.Duration) error {
	m, err := connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := openService(m)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.Start(); err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
			return nil
		}
		return fmt.Errorf("start service: %w", err)
	}
	deadline := time.Now().Add(timeout)
	last := svc.StartPending
	for time.Now().Before(deadline) {
		st, err := s.Query()
		if err != nil {
			return fmt.Errorf("query service: %w", err)
		}
		switch st.State {
		case svc.Running:
			return nil
		case svc.Stopped:
			return fmt.Errorf("service stopped during start (exit code %d/%d)", st.Win32ExitCode, st.ServiceSpecificExitCode)
		}
		last = st.State
		time.Sleep(pollInterval)
	}
	if last == svc.StartPending {
		return fmt.Errorf("%w after %s", ErrStartPending, timeout)
	}
	return fmt.Errorf("timed out waiting for service to start (state %d)", last)
}

// Stop stops the service and waits up to 20s until it is stopped. It returns
// an error if the service is not installed or already stopped.
func Stop() error {
	m, err := connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := openService(m)
	if err != nil {
		return err
	}
	defer s.Close()
	return stopService(s)
}

// ErrNotRunning is returned by Stop when the service was not running.
var ErrNotRunning = errors.New("service is not running")

func stopService(s *mgr.Service) error {
	st, err := s.Control(svc.Stop)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return ErrNotRunning
		}
		return fmt.Errorf("stop service: %w", err)
	}
	deadline := time.Now().Add(stopTimeout)
	for st.State != svc.Stopped {
		if time.Now().After(deadline) {
			return errors.New("timed out waiting for service to stop")
		}
		time.Sleep(pollInterval)
		st, err = s.Query()
		if err != nil {
			return fmt.Errorf("query service: %w", err)
		}
	}
	return nil
}

// Status returns a human-readable state. If the service is not installed it
// returns StateNotInstalled together with ErrNotInstalled.
func Status() (string, error) {
	st, _, err := StatusPID()
	return st, err
}

// StatusPID is Status plus the process ID the SCM reports for the service
// (QueryServiceStatusEx; 0 when it is not running).
func StatusPID() (string, uint32, error) {
	m, err := connect()
	if err != nil {
		return "", 0, err
	}
	defer m.Disconnect()
	s, err := openService(m)
	if errors.Is(err, ErrNotInstalled) {
		return StateNotInstalled, 0, err
	}
	if err != nil {
		return "", 0, err
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return "", 0, fmt.Errorf("query service: %w", err)
	}
	switch st.State {
	case svc.Running:
		return StateRunning, st.ProcessId, nil
	case svc.Stopped:
		return StateStopped, 0, nil
	case svc.StartPending:
		return StateStartPending, st.ProcessId, nil
	case svc.StopPending:
		return StateStopPending, st.ProcessId, nil
	case svc.Paused, svc.PausePending, svc.ContinuePending:
		return StatePaused, st.ProcessId, nil
	default:
		return fmt.Sprintf("unknown state %d", st.State), st.ProcessId, nil
	}
}

// RunService hosts run under the SCM. run is restarted every 10s after a
// failure (for example when the network is not up yet at boot) until the
// service is asked to stop. It must be called only when IsWindowsService
// reports true.
func RunService(run func(ctx context.Context) error) error {
	return svc.Run(paths.ServiceName, &handler{run: run})
}

type handler struct {
	run func(ctx context.Context) error
}

func (h *handler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- superviseLoop(ctx, h.run, retryDelay) }()

	status <- svc.Status{State: svc.Running, Accepts: accepted}
	for {
		select {
		case err := <-done:
			// Only reached without a stop request, when run returned
			// ErrFatal: report a failure so the SCM recovery action
			// restarts the service in a new process. The persistent WFP
			// filters stay in place meanwhile.
			status <- svc.Status{State: svc.StopPending}
			if err != nil {
				reportFatal(err)
				return true, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: uint32(stopTimeout / time.Millisecond)}
				cancel()
				select {
				case <-done:
					return false, 0
				case <-time.After(stopTimeout - 2*time.Second):
					// The process exits right after this; deferred cleanup
					// in run may not complete. Fail-closed does not depend
					// on it: the persistent WFP filters stay, and the
					// dynamic permit dies with the process.
					//
					// The stop was requested, so it is reported as a clean
					// stop (exit code 0): a non-zero code would make the SCM
					// run the failure actions and restart the service, for
					// example right after `disable` removed the policy. The
					// timeout is recorded in the event log instead.
					reportStopTimeout()
					return false, 0
				}
			}
		}
	}
}

// superviseLoop runs run until ctx is cancelled, retrying after delay when
// run returns (with or without an error) before cancellation. An error
// wrapping ErrFatal ends the loop and is returned.
func superviseLoop(ctx context.Context, run func(ctx context.Context) error, delay time.Duration) error {
	for {
		err := safeRun(ctx, run)
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, ErrFatal) {
			return err
		}
		reportRunError(err, delay)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}
	}
}

func safeRun(ctx context.Context, run func(ctx context.Context) error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return run(ctx)
}

// reportRunErrorEventLog writes a warning to the Application event log,
// which interactive users can read. Errors coming from the engine are
// already stripped of key material; user paths and line breaks are
// scrubbed here.
func reportRunErrorEventLog(err error, delay time.Duration) {
	if err == nil {
		err = errors.New("tunnel stopped unexpectedly")
	}
	writeEventLog(true, fmt.Sprintf("tunnel failed, retrying in %s: %v", delay, err))
}

// userDirRe matches the user-name component of profile paths.
var userDirRe = regexp.MustCompile(`(?i)(\\users\\)[^\\/:*?"<>|\r\n]+`)

// ScrubEventText removes user names from paths, line breaks and excess
// length from text destined for the event log.
func ScrubEventText(s string) string {
	s = logfile.ScrubString(s)
	s = userDirRe.ReplaceAllString(s, `${1}<user>`)
	s = strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
	if len(s) > 1000 {
		s = s[:1000] + "..."
	}
	return s
}

func writeEventLog(warning bool, msg string) {
	l, err := eventlog.Open(paths.ServiceName)
	if err != nil {
		return
	}
	defer l.Close()
	msg = ScrubEventText(msg)
	if warning {
		_ = l.Warning(1, msg)
	} else {
		_ = l.Info(1, msg)
	}
}
