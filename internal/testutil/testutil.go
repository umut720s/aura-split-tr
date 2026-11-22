// Package testutil holds helpers shared by the test files. It is imported
// only from *_test.go files and is never linked into the aurasplit binary.
package testutil

import (
	"os"
	"testing"
	"time"
)

// CleanupTimeout bounds how long TempDir's cleanup retries. A handle leaked
// by the code under test keeps the directory busy indefinitely and still
// fails the test; only transient holders (an on-access scanner inspecting a
// freshly renamed file or a newly written executable) are waited out.
const CleanupTimeout = 5 * time.Second

// TempDir is t.TempDir with a bounded, retrying cleanup.
//
// On this Windows machine t.TempDir's own cleanup fails intermittently with
// ERROR_DIR_NOT_EMPTY ("Dizin boş değil") right after files in the directory
// were renamed or a PE file was written: every file deletion succeeds and
// the directory listing is already empty, but the final rmdir still sees a
// delete-pending entry held by a file-system filter driver. testing's
// removeAll retries only ERROR_ACCESS_DENIED and ERROR_SHARING_VIOLATION, so
// the test is reported as failed although nothing in the test process holds
// a handle (see docs/audits/phase3_reliability.md, F-1).
func TempDir(t testing.TB) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "aurasplit-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := RemoveAllRetry(dir, CleanupTimeout); err != nil {
			t.Errorf("TempDir cleanup %s: %v", dir, err)
		}
	})
	return dir
}

// RemoveAllRetry calls os.RemoveAll until it succeeds or timeout elapses.
func RemoveAllRetry(dir string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	delay := 10 * time.Millisecond
	for {
		err := os.RemoveAll(dir)
		if err == nil || time.Now().After(deadline) {
			return err
		}
		time.Sleep(delay)
		if delay < 200*time.Millisecond {
			delay *= 2
		}
	}
}
