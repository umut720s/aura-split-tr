package logfile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aurasplit/internal/testutil"
)

// plainFiles replaces the secure opener with ordinary file operations; the
// Windows descriptor checks are covered by the paths package tests.
func plainFiles(t *testing.T) {
	t.Helper()
	oldOpen, oldReplace := openAppend, replaceFile
	openAppend = func(path string) (*os.File, int64, error) {
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
	replaceFile = func(src, dst string) error {
		os.Remove(dst)
		return os.Rename(src, dst)
	}
	t.Cleanup(func() { openAppend, replaceFile = oldOpen, oldReplace })
}

func TestRotation(t *testing.T) {
	plainFiles(t)
	dir := testutil.TempDir(t)
	w, err := Open(dir, "service.log", 100, 2)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.Repeat("x", 39) + "\n" // 40 bytes
	for i := 0; i < 20; i++ {
		if _, err := w.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	// Rotation closes every file it moves away; Close releases the last one.
	testutil.AssertNoOpenHandles(t, dir)
	for _, name := range []string{"service.log", "service.log.1", "service.log.2"} {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if st.Size() > 100 {
			t.Fatalf("%s is %d bytes, limit 100", name, st.Size())
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "service.log.3")); !os.IsNotExist(err) {
		t.Fatal("more backups than configured")
	}
}

func TestReopenAppends(t *testing.T) {
	plainFiles(t)
	dir := testutil.TempDir(t)
	for _, s := range []string{"a\n", "b\n"} {
		w, err := Open(dir, "x.log", 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(s))
		w.Close()
	}
	b, _ := os.ReadFile(filepath.Join(dir, "x.log"))
	if string(b) != "a\nb\n" {
		t.Fatalf("content %q", b)
	}
}

func TestRejectsPathName(t *testing.T) {
	if _, err := Open(testutil.TempDir(t), `..\x.log`, 0, 0); err == nil {
		t.Fatal("expected error for non-plain name")
	}
}

// If the full log cannot be rotated, nothing more is appended (the cap is
// hard); rotation is retried after RetryInterval and the number of dropped
// lines is then logged.
func TestRotationFailureStopsWriting(t *testing.T) {
	plainFiles(t)
	clock := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	oldNow := now
	now = func() time.Time { return clock }
	t.Cleanup(func() { now = oldNow })
	broken := true
	okReplace := replaceFile
	replaceFile = func(src, dst string) error {
		if broken {
			return errors.New("sharing violation")
		}
		return okReplace(src, dst)
	}

	dir := testutil.TempDir(t)
	w, err := Open(dir, "service.log", 100, 2)
	if err != nil {
		t.Fatal(err)
	}
	line := []byte(strings.Repeat("x", 39) + "\n") // 40 bytes
	for i := 0; i < 10; i++ {
		w.Write(line)
	}
	if !w.Degraded() {
		t.Fatal("writer not degraded after failed rotation")
	}
	st, err := os.Stat(filepath.Join(dir, "service.log"))
	if err != nil || st.Size() > 100 {
		t.Fatalf("log grew past the cap: %v %v", st.Size(), err)
	}

	broken = false
	clock = clock.Add(RetryInterval / 2)
	w.Write(line)
	if !w.Degraded() {
		t.Fatal("rotation retried before RetryInterval")
	}
	clock = clock.Add(RetryInterval)
	w.Write([]byte("after\n"))
	if w.Degraded() {
		t.Fatal("writer still degraded after successful rotation")
	}
	w.Close()
	b, _ := os.ReadFile(filepath.Join(dir, "service.log"))
	if !strings.Contains(string(b), "9 log lines dropped") || !strings.HasSuffix(string(b), "after\n") {
		t.Fatalf("content after recovery: %q", b)
	}
}

func TestScrubUserPaths(t *testing.T) {
	plainFiles(t)
	dir := testutil.TempDir(t)
	w, err := Open(dir, "x.log", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte(`open d:\users\Some Name\AppData\x.conf: denied; C:\Users\bob` + "\n"))
	w.Close()
	b, _ := os.ReadFile(filepath.Join(dir, "x.log"))
	got := string(b)
	if strings.Contains(got, "Some Name") || strings.Contains(got, "bob") ||
		!strings.Contains(got, `C:\Users\<user>\AppData\x.conf: denied`) {
		t.Fatalf("scrubbed line %q", got)
	}
}
