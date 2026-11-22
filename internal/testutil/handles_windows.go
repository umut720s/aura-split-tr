//go:build windows

package testutil

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// AssertNoOpenHandles fails t if any regular file directly inside dir is
// still open. Each file is opened with share mode 0 (exclusive); that fails
// with ERROR_SHARING_VIOLATION while any handle to the file exists, in this
// process or another. A short retry window tolerates a scanner that opens a
// file for a moment; a handle leaked by the code under test persists and is
// reported.
func AssertNoOpenHandles(t testing.TB, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("AssertNoOpenHandles: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		if err := openExclusive(path, time.Second); err != nil {
			t.Errorf("%s is still open after the code under test released it: %v", path, err)
		}
	}
}

func openExclusive(path string, timeout time.Duration) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	for {
		h, err := windows.CreateFile(p, windows.GENERIC_READ, 0, nil,
			windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err == nil {
			windows.CloseHandle(h)
			return nil
		}
		if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(20 * time.Millisecond)
	}
}
