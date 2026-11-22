//go:build !windows

package paths

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// The app only targets Windows; these exist so the packages build, vet and
// test elsewhere. They approximate the Windows semantics with POSIX modes.

// EnsureSecureDir creates dir with owner-only permissions.
func EnsureSecureDir(dir string) error { return ensureDirMode(dir, 0o700) }

func ensureDirMode(dir string, mode os.FileMode) error {
	if dir == "" {
		return errors.New("empty directory path")
	}
	if st, err := os.Lstat(dir); err == nil && st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symbolic link; refusing to use it", dir)
	}
	if err := os.MkdirAll(dir, mode); err != nil {
		return err
	}
	return os.Chmod(dir, mode)
}

// ReplaceFile atomically renames src over dst.
func ReplaceFile(src, dst string) error { return os.Rename(src, dst) }

// WriteSecureFile atomically writes data with owner-only permissions.
func WriteSecureFile(path string, data []byte) error {
	if err := EnsureSecureDir(filepath.Dir(path)); err != nil {
		return err
	}
	return WriteSecureFileInDir(path, data)
}

// WriteSecureFileInDir is WriteSecureFile without re-securing the directory.
func WriteSecureFileInDir(path string, data []byte) error {
	tmp, err := stageSecure(path, data)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// StageSecureFile writes data to a new temporary file next to path and
// returns its name; the caller moves it into place with ReplaceFile.
func StageSecureFile(path string, data []byte) (string, error) {
	if err := EnsureSecureDir(filepath.Dir(path)); err != nil {
		return "", err
	}
	return stageSecure(path, data)
}

func stageSecure(path string, data []byte) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	fail := func(err error) (string, error) {
		f.Close()
		_ = os.Remove(tmp)
		return "", err
	}
	if err := f.Chmod(0o600); err != nil {
		return fail(err)
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return tmp, nil
}

// OpenSecureAppend opens path for appending after refusing symbolic links.
func OpenSecureAppend(path string) (*os.File, int64, error) {
	if st, err := os.Lstat(path); err == nil && !st.Mode().IsRegular() {
		if err := os.Remove(path); err != nil {
			return nil, 0, err
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, 0, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	return f, st.Size(), nil
}

// IsTrustedAppDir reports whether path is a real directory (not a link).
func IsTrustedAppDir(path string) (bool, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	return fi.IsDir() && fi.Mode()&os.ModeSymlink == 0, nil
}

// IsTrustedFile reports whether path is a regular file not writable by
// group or others.
func IsTrustedFile(path string) (bool, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	return fi.Mode().IsRegular() && fi.Mode().Perm()&0o022 == 0, nil
}
