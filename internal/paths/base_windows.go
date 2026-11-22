//go:build windows

package paths

import (
	"path/filepath"
	"sync"

	"golang.org/x/sys/windows"
)

var (
	baseOnce     sync.Once
	programData  string
	programFiles string
)

func resolveBases() {
	programData = knownFolder(windows.FOLDERID_ProgramData, "ProgramData")
	programFiles = knownFolder(windows.FOLDERID_ProgramFiles, "Program Files")
}

// knownFolder returns the Known Folder path, or <system drive>\fallback if
// the shell API is unavailable (for example very early at boot).
func knownFolder(id *windows.KNOWNFOLDERID, fallback string) string {
	if p, err := windows.KnownFolderPath(id, windows.KF_FLAG_DEFAULT); err == nil && filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Join(systemDrive(), fallback)
}

func systemDrive() string {
	if sys, err := windows.GetSystemDirectory(); err == nil && len(sys) >= 2 && sys[1] == ':' {
		return sys[:2] + `\`
	}
	return `C:\`
}

func programDataDir() string  { baseOnce.Do(resolveBases); return programData }
func programFilesDir() string { baseOnce.Do(resolveBases); return programFiles }
