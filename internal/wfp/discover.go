package wfp

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// InstallDirNames are the per-user Discord install directories under
// %LOCALAPPDATA%.
var InstallDirNames = []string{"Discord", "DiscordPTB", "DiscordCanary", "DiscordDevelopment"}

// Discovery caps: a hostile or broken profile cannot make the policy grow
// without bound. Every app-* version directory that exists is covered
// (newest first) up to MaxPaths; hitting any cap is reported as
// ErrCapReached, which makes the pass incomplete (add-only, never prunes)
// instead of silently leaving executables out.
//
// MaxPathsPerProfile matches the per-profile policy budget
// (MaxPolicyAppsPerProfile); the policy additionally bounds existing plus
// proposed executables (see Firewall.Apply), so keeping old versions on
// disk cannot grow the persistent policy without bound.
const (
	MaxProfiles        = 64
	MaxExesPerDir      = 16
	MaxPaths           = 256
	MaxPathsPerProfile = MaxPolicyAppsPerProfile
)

// ErrCapReached is joined into the discovery error when a cap truncated
// the result.
var ErrCapReached = errors.New("wfp: discovery cap reached, inventory incomplete")

// errSkip marks entries that are deliberately ignored (links, wrong type).
var errSkip = errors.New("skipped")

// lstatPlain returns the entry's info if it exists and is neither a
// symbolic link, a junction nor any other reparse point.
func lstatPlain(p string) (fs.FileInfo, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if isLinkLike(fi) {
		return nil, errSkip
	}
	return fi, nil
}

// DiscoverIn finds Discord executables in the given user profile
// directories: <profile>\AppData\Local\<install>\Update.exe and
// <profile>\AppData\Local\<install>\app-*\Discord*.exe. No component of
// a returned path is a reparse point. Missing directories are not errors;
// other errors are joined and returned together with the partial result.
func DiscoverIn(profileDirs []string) ([]string, error) {
	var out []string
	var errs []error
	note := func(err error) {
		if err != nil && !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, errSkip) {
			errs = append(errs, err)
		}
	}
	// add returns false when the global cap is hit (stop) and sets
	// profileFull when the per-profile cap is hit (next profile).
	inProfile, profileFull := 0, false
	add := func(p string) bool {
		if len(out) >= MaxPaths {
			errs = append(errs, fmt.Errorf("%w: more than %d executables", ErrCapReached, MaxPaths))
			return false
		}
		if inProfile >= MaxPathsPerProfile {
			errs = append(errs, fmt.Errorf("%w: more than %d executables in one profile", ErrCapReached, MaxPathsPerProfile))
			profileFull = true
			return true
		}
		inProfile++
		out = append(out, p)
		return true
	}
	if len(profileDirs) > MaxProfiles {
		errs = append(errs, fmt.Errorf("%w: more than %d profiles", ErrCapReached, MaxProfiles))
		profileDirs = profileDirs[:MaxProfiles]
	}
profiles:
	for _, prof := range profileDirs {
		if prof == "" || !filepath.IsAbs(prof) {
			continue
		}
		inProfile, profileFull = 0, false
		local := prof
		for _, part := range []string{"", "AppData", "Local"} {
			if part != "" {
				local = filepath.Join(local, part)
			}
			fi, err := lstatPlain(local)
			if err != nil {
				note(err)
				continue profiles
			}
			if !fi.IsDir() {
				continue profiles
			}
		}
		for _, name := range InstallDirNames {
			inst := filepath.Join(local, name)
			fi, err := lstatPlain(inst)
			if err != nil || !fi.IsDir() {
				note(err)
				continue
			}
			if upd := filepath.Join(inst, "Update.exe"); isPlainFile(upd, note) {
				if !add(upd) {
					break profiles
				}
				if profileFull {
					continue profiles
				}
			}
			for _, dir := range appDirs(inst, note) {
				for _, exe := range discordExes(dir, note) {
					if !add(exe) {
						break profiles
					}
					if profileFull {
						continue profiles
					}
				}
			}
		}
	}
	return out, errors.Join(errs...)
}

func isPlainFile(p string, note func(error)) bool {
	fi, err := lstatPlain(p)
	if err != nil {
		note(err)
		return false
	}
	return fi.Mode().IsRegular()
}

// appDirs returns every app-* directory, newest version first.
func appDirs(inst string, note func(error)) []string {
	ents, err := os.ReadDir(inst)
	if err != nil {
		note(err)
		return nil
	}
	var names []string
	for _, e := range ents {
		n := e.Name()
		if !strings.HasPrefix(strings.ToLower(n), "app-") {
			continue
		}
		fi, err := lstatPlain(filepath.Join(inst, n))
		if err != nil || !fi.IsDir() {
			note(err)
			continue
		}
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool { return versionLess(names[j], names[i]) })
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = filepath.Join(inst, n)
	}
	return out
}

// discordExes returns Discord*.exe files directly inside dir.
func discordExes(dir string, note func(error)) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		note(err)
		return nil
	}
	var out []string
	for _, e := range ents {
		n := strings.ToLower(e.Name())
		if !strings.HasPrefix(n, "discord") || !strings.HasSuffix(n, ".exe") {
			continue
		}
		p := filepath.Join(dir, e.Name())
		if !isPlainFile(p, note) {
			continue
		}
		if len(out) >= MaxExesPerDir {
			note(fmt.Errorf("%w: more than %d Discord executables in one directory", ErrCapReached, MaxExesPerDir))
			break
		}
		out = append(out, p)
	}
	return out
}

// WatchTarget is a directory the watcher observes.
type WatchTarget struct {
	Path    string
	Subtree bool
}

// WatchTargetsIn returns, for every profile, its AppData\Local directory
// (direct children only: a new Discord install directory) and every
// existing Discord install directory (whole subtree: new app-* versions
// and executables). Reparse points are never watched.
func WatchTargetsIn(profileDirs []string) []WatchTarget {
	var out []WatchTarget
	if len(profileDirs) > MaxProfiles {
		profileDirs = profileDirs[:MaxProfiles]
	}
profiles:
	for _, prof := range profileDirs {
		if prof == "" || !filepath.IsAbs(prof) {
			continue
		}
		local := prof
		for _, part := range []string{"", "AppData", "Local"} {
			if part != "" {
				local = filepath.Join(local, part)
			}
			if fi, err := lstatPlain(local); err != nil || !fi.IsDir() {
				continue profiles
			}
		}
		out = append(out, WatchTarget{Path: local})
		for _, name := range InstallDirNames {
			inst := filepath.Join(local, name)
			if fi, err := lstatPlain(inst); err == nil && fi.IsDir() {
				out = append(out, WatchTarget{Path: inst, Subtree: true})
			}
		}
	}
	return out
}

func equalTargets(a, b []WatchTarget) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Subtree != b[i].Subtree || !strings.EqualFold(a[i].Path, b[i].Path) {
			return false
		}
	}
	return true
}

// versionLess compares "app-1.0.9010"-style names numerically per dot
// component; non-numeric parts compare as strings.
func versionLess(a, b string) bool {
	pa := strings.Split(strings.TrimPrefix(strings.ToLower(a), "app-"), ".")
	pb := strings.Split(strings.TrimPrefix(strings.ToLower(b), "app-"), ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		var na, nb int
		_, ea := fmt.Sscanf(pa[i], "%d", &na)
		_, eb := fmt.Sscanf(pb[i], "%d", &nb)
		if ea == nil && eb == nil {
			if na != nb {
				return na < nb
			}
			continue
		}
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return len(pa) < len(pb)
}
