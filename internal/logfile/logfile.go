// Package logfile is a size-bounded, rotating log writer for the service.
//
// All paths are derived from one directory and one base name; the caller
// must have secured that directory with paths.EnsureSecureDir first. Every
// (re)open goes through paths.OpenSecureAppend, which refuses links,
// reparse points and files whose owner or ACL is not SYSTEM/Administrators
// only.
//
// The size cap is hard: if the file cannot be rotated (for example another
// process holds service.log.1 open), lines are dropped and counted instead
// of growing the file, and rotation is retried at most every 30 seconds.
// User-profile paths are scrubbed from every line, including lines written
// by dependencies such as sing-box.
package logfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"

	"aurasplit/internal/paths"
)

// Defaults used by the service.
const (
	DefaultMaxSize = 2 << 20 // bytes per file
	DefaultBackups = 2       // service.log.1, service.log.2
	// RetryInterval is the minimum time between two rotation (or reopen)
	// attempts while the writer is degraded.
	RetryInterval = 30 * time.Second
)

// userPathRe matches a user-profile directory such as C:\Users\Some Name.
// The name ends at the next path separator or a character that cannot
// appear in a file name.
var userPathRe = regexp.MustCompile(`(?i)[A-Z]:\\Users\\[^\\/:*?"<>|\r\n]+`)

// Scrub replaces user-profile paths with C:\Users\<user>.
func Scrub(p []byte) []byte {
	return userPathRe.ReplaceAll(p, []byte(`C:\Users\<user>`))
}

// ScrubString is Scrub for strings.
func ScrubString(s string) string {
	return userPathRe.ReplaceAllString(s, `C:\Users\<user>`)
}

// Writer appends to dir/name and rotates it to name.1 … name.N when the
// next write would exceed MaxSize. It is safe for concurrent use.
type Writer struct {
	dir     string
	name    string
	maxSize int64
	backups int

	mu          sync.Mutex
	f           *os.File
	size        int64
	closed      bool
	degraded    bool      // rotation or open failed; lines are dropped
	lastAttempt time.Time // last rotation/open attempt while degraded
	dropped     uint64    // lines dropped while degraded
}

// Open opens dir/name for appending. maxSize <= 0 and backups < 1 select the
// defaults. If the existing file is already full and cannot be rotated, the
// writer starts degraded instead of failing.
func Open(dir, name string, maxSize int64, backups int) (*Writer, error) {
	if name == "" || filepath.Base(name) != name {
		return nil, errors.New("log name must be a plain file name")
	}
	if maxSize <= 0 {
		maxSize = DefaultMaxSize
	}
	if backups < 1 {
		backups = DefaultBackups
	}
	w := &Writer{dir: filepath.Clean(dir), name: name, maxSize: maxSize, backups: backups}
	if err := w.open(); err != nil {
		return nil, err
	}
	if w.size >= w.maxSize {
		_ = w.rotate()
	}
	return w, nil
}

func (w *Writer) path(n int) string {
	if n == 0 {
		return filepath.Join(w.dir, w.name)
	}
	return filepath.Join(w.dir, w.name+"."+strconv.Itoa(n))
}

// Indirections so the rotation logic can be tested without the Windows
// descriptor checks (which need an elevated process).
var (
	openAppend  = paths.OpenSecureAppend
	replaceFile = paths.ReplaceFile
	now         = time.Now
)

func (w *Writer) open() error {
	f, size, err := openAppend(w.path(0))
	if err != nil {
		return err
	}
	w.f, w.size = f, size
	return nil
}

// rotate shifts name.(N-1) → name.N … name → name.1 and opens a fresh
// file. If name cannot be moved away or the fresh file cannot be opened,
// the writer becomes degraded (no file open, lines dropped).
func (w *Writer) rotate() error {
	w.lastAttempt = now()
	if w.f != nil {
		_ = w.f.Close()
		w.f = nil
	}
	for i := w.backups - 1; i >= 1; i-- {
		if _, err := os.Lstat(w.path(i)); err == nil {
			// A failed shift only costs the oldest backup.
			_ = replaceFile(w.path(i), w.path(i+1))
		}
	}
	if err := replaceFile(w.path(0), w.path(1)); err != nil && !errors.Is(err, os.ErrNotExist) {
		w.degraded = true
		return err
	}
	if err := w.open(); err != nil {
		w.degraded = true
		return err
	}
	w.degraded = false
	return nil
}

// recover retries rotation (or the reopen) of a degraded writer, at most
// once per RetryInterval. It reports whether a file is open afterwards.
func (w *Writer) recover() bool {
	if now().Sub(w.lastAttempt) < RetryInterval {
		return false
	}
	return w.rotate() == nil
}

// Write appends p, rotating first if needed. User-profile paths are
// scrubbed. Lines that cannot be written within the size cap are dropped,
// counted and reported as written, so logging can never stop the tunnel;
// the count is logged once writing works again.
func (w *Writer) Write(p []byte) (int, error) {
	n := len(p)
	line := Scrub(p)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return n, nil
	}
	if w.f == nil || w.degraded {
		if !w.recover() {
			w.dropped++
			return n, nil
		}
	} else if w.size > 0 && w.size+int64(len(line)) > w.maxSize {
		if err := w.rotate(); err != nil {
			w.dropped++
			return n, nil
		}
	}
	if w.dropped > 0 {
		notice := fmt.Sprintf("%s WARN [aurasplit] %d log lines dropped (log file could not be rotated)\n",
			now().Format("-0700 2006-01-02 15:04:05"), w.dropped)
		w.dropped = 0
		if m, err := w.f.Write([]byte(notice)); err == nil {
			w.size += int64(m)
		}
	}
	m, err := w.f.Write(line)
	w.size += int64(m)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// Degraded reports whether the writer is currently dropping lines because
// the log could not be rotated or reopened.
func (w *Writer) Degraded() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return !w.closed && (w.degraded || w.f == nil)
}

// Close closes the current file. Later writes are discarded.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}
