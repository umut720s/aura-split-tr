//go:build windows

package wfp

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const profileListKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`

func isLinkLike(fi fs.FileInfo) bool {
	if fi.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
		return true
	}
	if d, ok := fi.Sys().(*syscall.Win32FileAttributeData); ok {
		return d.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
	}
	return false
}

// userSID reports whether a ProfileList entry belongs to a real user
// account (local/domain S-1-5-21-…, Microsoft Entra ID S-1-12-1-…), not
// to SYSTEM, LocalService or NetworkService.
func userSID(sid string) bool {
	s := strings.ToUpper(sid)
	return strings.HasPrefix(s, "S-1-5-21-") || strings.HasPrefix(s, "S-1-12-1-")
}

// ProfileDirs lists user profile directories from the ProfileList key
// (HKLM, writable only by administrators), capped at MaxProfiles. A user
// entry that cannot be read, or the cap, makes the error non-nil (the
// partial list is still returned).
func ProfileDirs() ([]string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, profileListKey, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}
	var out []string
	var errs []error
	for _, n := range names {
		if !userSID(n) || strings.HasSuffix(strings.ToLower(n), ".bak") {
			continue
		}
		if len(out) >= MaxProfiles {
			errs = append(errs, fmt.Errorf("%w: more than %d profiles", ErrCapReached, MaxProfiles))
			break
		}
		sk, err := registry.OpenKey(k, n, registry.QUERY_VALUE)
		if err != nil {
			errs = append(errs, fmt.Errorf("profile list entry: %w", err))
			continue
		}
		v, _, err := sk.GetStringValue("ProfileImagePath")
		sk.Close()
		if err != nil || v == "" {
			continue
		}
		if x, err := registry.ExpandString(v); err == nil {
			v = x
		}
		v = filepath.Clean(v)
		if !filepath.IsAbs(v) {
			continue
		}
		out = append(out, v)
	}
	return out, errors.Join(errs...)
}

// Discover returns the Discord executables of every user profile. A
// non-nil error means the result may be incomplete.
func Discover() ([]string, error) {
	dirs, err := ProfileDirs()
	if len(dirs) == 0 && err != nil {
		return nil, err
	}
	found, derr := DiscoverIn(dirs)
	return found, errors.Join(err, derr)
}

// WatchTargets returns the directories to watch for every user profile.
func WatchTargets() ([]WatchTarget, error) {
	dirs, err := ProfileDirs()
	return WatchTargetsIn(dirs), err
}
