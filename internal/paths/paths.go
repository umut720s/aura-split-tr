// Package paths centralises every filesystem location the app uses.
// Nothing here is user-specific at build time. On Windows the base folders
// are resolved through the Known Folder API at runtime, never from
// environment variables a caller could manipulate.
package paths

import (
	"path/filepath"
)

const (
	AppDirName  = "AuraSplitTR"
	ServiceName = "AuraSplitTR"
	ExeName     = "aurasplit.exe"
	LogName     = "service.log"
	StateName   = "tunnel-state.json"
	ProfileName = "profile.json"
	// RecoverStateName holds the service state captured by
	// `recover --msi --save-state` (MSI uninstall) for the rollback action
	// `recover-rollback --msi`.
	RecoverStateName = "recover-state.json"
)

// QuarantineInfix is inserted between a directory name and a timestamp
// when untrusted content is moved aside instead of being deleted, for
// example %ProgramData%\AuraSplitTR.quarantine-20260101T120000Z-1a2b3c.
const QuarantineInfix = ".quarantine-"

// DataDir is %ProgramData%\AuraSplitTR (profile, logs, tunnel state).
// ACL: SYSTEM + Administrators only.
func DataDir() string { return filepath.Join(programDataDir(), AppDirName) }

// InstallDir is %ProgramFiles%\AuraSplitTR (service binary).
func InstallDir() string { return filepath.Join(programFilesDir(), AppDirName) }

func ProfilePath() string      { return filepath.Join(DataDir(), ProfileName) }
func LogPath() string          { return filepath.Join(DataDir(), LogName) }
func StatePath() string        { return filepath.Join(DataDir(), StateName) }
func InstalledExePath() string { return filepath.Join(InstallDir(), ExeName) }
func RecoverStatePath() string { return filepath.Join(DataDir(), RecoverStateName) }
