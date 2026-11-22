//go:build windows

package main

import (
	"errors"
	"os"
	"reflect"
	"testing"

	"aurasplit/internal/service"
	"aurasplit/internal/wfp"
)

func TestRecoverStateRoundTrip(t *testing.T) {
	for _, typ := range []uint32{service.StartAutomatic, service.StartManual, service.StartDisabled} {
		for _, running := range []bool{false, true} {
			var saved []byte
			var calls []string
			actualType, actualRunning := typ, running
			ops := recoverStateOps{
				startType: func() (uint32, error) { return typ, nil },
				status: func() (string, error) {
					if running {
						return service.StateRunning, nil
					}
					return service.StateStopped, nil
				},
				write:        func(b []byte) error { saved = append([]byte(nil), b...); return nil },
				read:         func() ([]byte, error) { return saved, nil },
				setStartType: func(v uint32) error { actualType = v; calls = append(calls, "type"); return nil },
				start: func() error {
					if actualType == service.StartDisabled {
						t.Fatal("starting disabled service")
					}
					actualRunning = true
					calls = append(calls, "start")
					return nil
				},
				stop:     func() error { actualRunning = false; calls = append(calls, "stop"); return service.ErrNotRunning },
				snapshot: func() (bool, []string, error) { return true, []string{`C:\Apps\Discord.exe`}, nil },
				apply: func(paths []string, mode wfp.ApplyMode) (wfp.ApplyResult, error) {
					if !reflect.DeepEqual(paths, []string{`C:\Apps\Discord.exe`}) || mode != wfp.AddOnly {
						t.Fatalf("unexpected restore: %v %v", paths, mode)
					}
					calls = append(calls, "policy")
					return wfp.ApplyResult{}, nil
				},
			}
			if err := saveRecoverState(ops); err != nil {
				t.Fatal(err)
			}
			if len(calls) != 0 {
				t.Fatal("saving changed system state")
			}
			// Recover disables/stops the service and removes policy; emulate it.
			actualType, actualRunning = service.StartDisabled, false
			if err := restoreRecoverState(ops); err != nil {
				t.Fatal(err)
			}
			if actualType != typ || actualRunning != running || calls[0] != "policy" {
				t.Fatalf("restored %d/%v calls %v; want %d/%v", actualType, actualRunning, calls, typ, running)
			}
		}
	}
}

func TestSaveRecoverStateFailures(t *testing.T) {
	errFake := errors.New("injected")
	for _, stage := range []string{"config", "status", "pending", "snapshot", "write", "absent"} {
		t.Run(stage, func(t *testing.T) {
			writes := 0
			ops := recoverStateOps{
				startType: func() (uint32, error) {
					if stage == "config" {
						return 0, errFake
					}
					if stage == "absent" {
						return 0, service.ErrNotInstalled
					}
					return service.StartAutomatic, nil
				},
				status: func() (string, error) {
					if stage == "status" {
						return "", errFake
					}
					if stage == "pending" {
						return service.StateStartPending, nil
					}
					return service.StateRunning, nil
				},
				write: func([]byte) error {
					writes++
					if stage == "write" {
						return errFake
					}
					return nil
				},
				snapshot: func() (bool, []string, error) {
					if stage == "snapshot" {
						return false, nil, errFake
					}
					return false, nil, nil
				},
			}
			if err := saveRecoverState(ops); (err == nil) != (stage == "absent") {
				t.Fatalf("save: %v", err)
			}
			want := 0
			if stage == "write" || stage == "absent" {
				want = 1
			}
			if writes != want {
				t.Fatalf("writes %d want %d", writes, want)
			}
		})
	}
}

func TestRestoreRecoverStateFailures(t *testing.T) {
	for _, data := range []string{`broken`, `{}`, `{"version":1}`, `{"version":99}`, `{"version":2,"exists":true,"start_type":99}`, `{"version":2,"protected_paths":["unexpected"]}`} {
		ops := recoverStateOps{read: func() ([]byte, error) { return []byte(data), nil }}
		if err := restoreRecoverState(ops); err == nil {
			t.Fatalf("accepted %q", data)
		}
	}
	if err := restoreRecoverState(recoverStateOps{read: func() ([]byte, error) { return nil, os.ErrNotExist }}); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	for _, installed := range []bool{false, true} {
		var calls []string
		ops := recoverStateOps{
			read: func() ([]byte, error) {
				policy := "false"
				if installed {
					policy = "true"
				}
				return []byte(`{"version":2,"exists":true,"start_type":2,"running":true,"policy_installed":` + policy + `}`), nil
			},
			apply: func([]string, wfp.ApplyMode) (wfp.ApplyResult, error) {
				calls = append(calls, "policy")
				return wfp.ApplyResult{}, errors.New("WFP failure")
			},
			setStartType: func(uint32) error { calls = append(calls, "type"); return errors.New("SCM failure") },
			start:        func() error { calls = append(calls, "start"); return nil },
		}
		if err := restoreRecoverState(ops); err == nil {
			t.Fatal("failures hidden")
		}
		want := []string{"type", "start"}
		if installed {
			want = append([]string{"policy"}, want...)
		}
		if !reflect.DeepEqual(calls, want) {
			t.Fatalf("calls %v want %v", calls, want)
		}
	}
}

// No profile/discovery operation exists in recoverStateOps. A removed profile
// therefore cannot prevent restoration of the captured policy inventory.
func TestRestorePolicyWithoutProfileOrService(t *testing.T) {
	for _, installed := range []bool{false, true} {
		applied := false
		var saved []byte
		ops := recoverStateOps{
			startType: func() (uint32, error) { return 0, service.ErrNotInstalled },
			snapshot: func() (bool, []string, error) {
				if installed {
					return true, []string{`C:\Apps\Discord.exe`, `C:\Apps\Update.exe`}, nil
				}
				return false, nil, nil
			},
			write: func(b []byte) error { saved = b; return nil },
			read:  func() ([]byte, error) { return saved, nil },
			apply: func(paths []string, mode wfp.ApplyMode) (wfp.ApplyResult, error) {
				if !reflect.DeepEqual(paths, []string{`C:\Apps\Discord.exe`, `C:\Apps\Update.exe`}) || mode != wfp.AddOnly {
					t.Fatalf("unexpected inventory/mode: %v %v", paths, mode)
				}
				applied = true
				return wfp.ApplyResult{}, nil
			},
		}
		if err := saveRecoverState(ops); err != nil {
			t.Fatal(err)
		}
		if err := restoreRecoverState(ops); err != nil {
			t.Fatal(err)
		}
		if applied != installed {
			t.Fatalf("policy applied=%v, captured=%v", applied, installed)
		}
	}
}

func TestRollbackDisabledStoppedWithoutPolicy(t *testing.T) {
	var saved []byte
	typ, running := uint32(service.StartDisabled), false
	ops := recoverStateOps{
		startType:    func() (uint32, error) { return typ, nil },
		status:       func() (string, error) { return service.StateStopped, nil },
		snapshot:     func() (bool, []string, error) { return false, nil, nil },
		write:        func(b []byte) error { saved = b; return nil },
		read:         func() ([]byte, error) { return saved, nil },
		setStartType: func(v uint32) error { typ = v; return nil },
		stop:         func() error { running = false; return nil },
		start:        func() error { t.Fatal("started disabled/stopped service"); return nil },
		apply: func([]string, wfp.ApplyMode) (wfp.ApplyResult, error) {
			t.Fatal("created previously absent policy")
			return wfp.ApplyResult{}, nil
		},
	}
	if err := saveRecoverState(ops); err != nil {
		t.Fatal(err)
	}
	if err := restoreRecoverState(ops); err != nil {
		t.Fatal(err)
	}
	if typ != service.StartDisabled || running {
		t.Fatalf("restored %d/%v", typ, running)
	}
}
