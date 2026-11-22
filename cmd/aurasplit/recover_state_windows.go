//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"aurasplit/internal/paths"
	"aurasplit/internal/service"
	"aurasplit/internal/wfp"
)

type recoverState struct {
	Version         int      `json:"version"`
	Exists          bool     `json:"exists"`
	StartType       uint32   `json:"start_type"`
	Running         bool     `json:"running"`
	PolicyInstalled bool     `json:"policy_installed"`
	ProtectedPaths  []string `json:"protected_paths"`
}

type recoverStateOps struct {
	startType    func() (uint32, error)
	status       func() (string, error)
	write        func([]byte) error
	read         func() ([]byte, error)
	setStartType func(uint32) error
	start, stop  func() error
	snapshot     func() (bool, []string, error)
	apply        func([]string, wfp.ApplyMode) (wfp.ApplyResult, error)
}

func systemRecoverStateOps() recoverStateOps {
	return recoverStateOps{
		startType: service.GetStartType, status: service.Status,
		write: func(b []byte) error { return paths.WriteSecureFile(paths.RecoverStatePath(), b) },
		read: func() ([]byte, error) {
			if err := paths.EnsureSecureDir(paths.DataDir()); err != nil {
				return nil, err
			}
			ok, err := paths.IsTrustedFile(paths.RecoverStatePath())
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, errors.New("kurtarma kaydı güvenilir değil")
			}
			return os.ReadFile(paths.RecoverStatePath())
		},
		setStartType: service.SetStartType, start: service.Start, stop: service.Stop,
		snapshot: func() (bool, []string, error) { return newPolicy().Snapshot() },
		apply:    func(p []string, mode wfp.ApplyMode) (wfp.ApplyResult, error) { return newPolicy().Apply(p, mode) },
	}
}

// Saving is a separate deferred action, completed before rollback is armed
// and before recover changes the service or WFP. Never reuse an old record.
func saveRecoverState(ops recoverStateOps) error {
	typ, err := ops.startType()
	s := recoverState{Version: 2}
	if !isNotInstalled(err) {
		if err != nil {
			return err
		}
		st, err := ops.status()
		if err != nil {
			return err
		}
		if st != service.StateRunning && st != service.StateStopped {
			return fmt.Errorf("hizmet geçiş durumunda: %s; tekrar deneyin", st)
		}
		s.Exists, s.StartType, s.Running = true, typ, st == service.StateRunning
	}
	s.PolicyInstalled, s.ProtectedPaths, err = ops.snapshot()
	if err != nil {
		return err
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return ops.write(b)
}

// Native MSI rollback first restores the service registration and files.
// This action then reverses recover's changes, including persistent policy
// only when it was captured as installed, independently of the profile.
// Attempt all restorations even if one fails; Return=ignore lets the
// remaining MSI rollback continue.
func restoreRecoverState(ops recoverStateOps) error {
	b, err := ops.read()
	if err != nil {
		return err
	}
	var s recoverState
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if s.Version != 2 || (!s.PolicyInstalled && len(s.ProtectedPaths) != 0) || (s.Exists && s.StartType != service.StartAutomatic && s.StartType != service.StartManual && s.StartType != service.StartDisabled) {
		return errors.New("geçersiz kurtarma kaydı")
	}
	for _, p := range s.ProtectedPaths {
		if p == "" {
			return errors.New("geçersiz kurtarma kaydı: boş uygulama yolu")
		}
	}
	var errs []error
	if s.PolicyInstalled {
		// Recovery may have failed partway through removal. Keep surviving
		// blocks and restore captured paths without pruning or discovery.
		_, err := ops.apply(s.ProtectedPaths, wfp.AddOnly)
		errs = append(errs, err)
	}
	if !s.Exists {
		return errors.Join(errs...)
	}
	// A disabled service may have been running. Temporarily allow Start,
	// then restore Disabled without stopping that originally running service.
	typ := s.StartType
	if s.Running && typ == service.StartDisabled {
		typ = service.StartManual
	}
	errs = append(errs, ops.setStartType(typ))
	if s.Running {
		errs = append(errs, ops.start())
	} else if err := ops.stop(); !stopOK(err) && !isNotInstalled(err) {
		errs = append(errs, err)
	}
	if typ != s.StartType {
		errs = append(errs, ops.setStartType(s.StartType))
	}
	return errors.Join(errs...)
}

func cmdSaveRecoverState() int {
	if err := saveRecoverState(systemRecoverStateOps()); err != nil {
		fail("Kurtarma öncesi hizmet ve WFP durumu kaydedilemedi; hizmet ve WFP değiştirilmedi.", err)
		return 1
	}
	return 0
}

// Hidden MSI command: never shown in interactive help or relaunched via UAC.
func cmdRecoverRollback() int {
	if err := restoreRecoverState(systemRecoverStateOps()); err != nil {
		fail("Kurtarma geri alınamadı; hizmeti ve WFP durumunu kontrol edin.", err)
		return 1
	}
	return 0
}
