//go:build !windows

package paths

import "os"

// The app only targets Windows; these environment-based fallbacks exist so
// the package builds and its tests run elsewhere.
func programDataDir() string {
	if v := os.Getenv("ProgramData"); v != "" {
		return v
	}
	return "/var/lib"
}

func programFilesDir() string {
	if v := os.Getenv("ProgramFiles"); v != "" {
		return v
	}
	return "/opt"
}
