package testutil

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// recorder captures Errorf so the detector itself can be tested.
type recorder struct {
	testing.TB
	errors []string
}

func (r *recorder) Helper() {}
func (r *recorder) Errorf(format string, args ...any) {
	r.errors = append(r.errors, fmt.Sprintf(format, args...))
}

// The detector must report a file the code under test left open and stay
// quiet once it is closed; otherwise it proves nothing about leaks.
func TestAssertNoOpenHandlesDetectsLeak(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("handle check is Windows only")
	}
	dir := TempDir(t)
	f, err := os.Create(filepath.Join(dir, "leaked.log"))
	if err != nil {
		t.Fatal(err)
	}
	r := &recorder{TB: t}
	AssertNoOpenHandles(r, dir)
	if len(r.errors) != 1 {
		t.Fatalf("open handle not reported: %v", r.errors)
	}
	f.Close()
	r.errors = nil
	AssertNoOpenHandles(r, dir)
	if len(r.errors) != 0 {
		t.Fatalf("closed file reported: %v", r.errors)
	}
}

func TestTempDirIsRemoved(t *testing.T) {
	var dir string
	t.Run("inner", func(t *testing.T) {
		dir = TempDir(t)
		os.WriteFile(filepath.Join(dir, "a"), []byte("x"), 0o600)
		os.Rename(filepath.Join(dir, "a"), filepath.Join(dir, "b"))
	})
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("temp dir survived cleanup: %v", err)
	}
}
