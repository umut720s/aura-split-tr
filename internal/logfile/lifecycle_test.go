package logfile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"aurasplit/internal/testutil"
)

// Close is idempotent, releases the file, and later writes are discarded
// without error (the service may still log while shutting down).
func TestCloseIsIdempotentAndDiscards(t *testing.T) {
	plainFiles(t)
	dir := testutil.TempDir(t)
	w, err := Open(dir, "service.log", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("before\n"))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if n, err := w.Write([]byte("after\n")); err != nil || n != 6 {
		t.Fatalf("Write after Close = %d, %v", n, err)
	}
	if w.Degraded() {
		t.Fatal("closed writer reports degraded")
	}
	testutil.AssertNoOpenHandles(t, dir)
	b, _ := os.ReadFile(filepath.Join(dir, "service.log"))
	if string(b) != "before\n" {
		t.Fatalf("content %q", b)
	}
}

// Concurrent writers never exceed the cap, never interleave inside a line
// and leave no handle open after Close.
func TestConcurrentWritesRespectCap(t *testing.T) {
	plainFiles(t)
	dir := testutil.TempDir(t)
	const limit = 1000
	w, err := Open(dir, "service.log", limit, 2)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.Repeat("y", 39) + "\n"
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				w.Write([]byte(line))
			}
		}()
	}
	wg.Wait()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	testutil.AssertNoOpenHandles(t, dir)
	for _, name := range []string{"service.log", "service.log.1", "service.log.2"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(b) > limit {
			t.Fatalf("%s is %d bytes, limit %d", name, len(b), limit)
		}
		for _, l := range strings.SplitAfter(string(b), "\n") {
			if l != "" && l != line {
				t.Fatalf("%s: torn line %q", name, l)
			}
		}
	}
}

// A full log that cannot be rotated at startup must not stop the service:
// Open succeeds, the writer starts degraded and holds no file open.
func TestOpenFullUnrotatableStartsDegraded(t *testing.T) {
	plainFiles(t)
	dir := testutil.TempDir(t)
	if err := os.WriteFile(filepath.Join(dir, "service.log"), []byte(strings.Repeat("z", 200)), 0o600); err != nil {
		t.Fatal(err)
	}
	replaceFile = func(src, dst string) error { return errors.New("sharing violation") }
	w, err := Open(dir, "service.log", 100, 2)
	if err != nil {
		t.Fatalf("Open failed instead of degrading: %v", err)
	}
	if !w.Degraded() {
		t.Fatal("writer not degraded")
	}
	// Degraded: no file is held, so another process (or the next rotation
	// attempt) can move service.log.
	testutil.AssertNoOpenHandles(t, dir)
	w.Write([]byte("dropped\n"))
	w.Close()
	b, _ := os.ReadFile(filepath.Join(dir, "service.log"))
	if len(b) != 200 {
		t.Fatalf("degraded writer wrote to the full log: %d bytes", len(b))
	}
}

// If the fresh file cannot be opened after rotation, the writer degrades and
// the rotated-away file is not kept open.
func TestReopenFailureAfterRotationDegrades(t *testing.T) {
	plainFiles(t)
	dir := testutil.TempDir(t)
	w, err := Open(dir, "service.log", 100, 2)
	if err != nil {
		t.Fatal(err)
	}
	okOpen := openAppend
	openAppend = func(string) (*os.File, int64, error) { return nil, 0, errors.New("access denied") }
	t.Cleanup(func() { openAppend = okOpen })
	line := []byte(strings.Repeat("x", 39) + "\n")
	for i := 0; i < 4; i++ {
		w.Write(line)
	}
	if !w.Degraded() {
		t.Fatal("writer not degraded after failed reopen")
	}
	testutil.AssertNoOpenHandles(t, dir)
	w.Close()
}
