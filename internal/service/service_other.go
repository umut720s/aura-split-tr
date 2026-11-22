//go:build !windows

// Package service controls and hosts the AURA Split TR Windows service. On
// other platforms every operation fails.
package service

import (
	"context"
	"errors"
	"time"
)

var errUnsupported = errors.New("windows service is only supported on Windows")

func IsAdmin() bool                                    { return false }
func IsWindowsService() (bool, error)                  { return false, nil }
func Verify(string) error                              { return errUnsupported }
func EnableNonCrashRecovery() error                    { return errUnsupported }
func Start() error                                     { return errUnsupported }
func StartWait(time.Duration) error                    { return errUnsupported }
func Stop() error                                      { return errUnsupported }
func Status() (string, error)                          { return "", errUnsupported }
func StatusPID() (string, uint32, error)               { return "", 0, errUnsupported }
func RunService(func(ctx context.Context) error) error { return errUnsupported }
func SetAutoStart(bool) error                          { return errUnsupported }
func Disable() error                                   { return errUnsupported }
func GetStartType() (uint32, error)                    { return 0, errUnsupported }
func SetStartType(uint32) error                        { return errUnsupported }

// Start types (SERVICE_*_START values), as on Windows.
const (
	StartAutomatic = 2
	StartManual    = 3
	StartDisabled  = 4
)

var (
	ErrNotInstalled = errors.New("service does not exist")
	ErrNotRunning   = errors.New("service is not running")
	ErrStartPending = errors.New("service is still start pending")
	ErrFatal        = errors.New("fatal service error, restarting the process")
)
