//go:build windows

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/windows"

	"aurasplit/internal/engine"
	"aurasplit/internal/logfile"
	"aurasplit/internal/paths"
	"aurasplit/internal/wfp"
)

// tunnelState is persisted by the service in paths.StatePath() so that
// `status` can show the tunnel state separately from the SCM state. The
// file has the data-directory ACL (SYSTEM + Administrators only).
//
// A record is only believed if it was written by the process the SCM
// currently reports for the service (PID and process start time) and its
// heartbeat is fresh; see stateValid.
type tunnelState struct {
	State        string    `json:"state"`
	Detail       string    `json:"detail,omitempty"`
	Time         time.Time `json:"time"` // last state change
	PID          int       `json:"pid"`
	ProcessStart time.Time `json:"process_start"`
	Heartbeat    time.Time `json:"heartbeat"`
	LogDegraded  bool      `json:"log_degraded,omitempty"`

	// Connectivity is the last tunnel probe result (engine.Connectivity),
	// empty until a probe completed after the tunnel started. Never
	// contains an IP address.
	Connectivity       string    `json:"connectivity,omitempty"`
	ConnectivityDetail string    `json:"connectivity_detail,omitempty"`
	ConnectivityTime   time.Time `json:"connectivity_time,omitempty"`
	ConnectivityOK     time.Time `json:"connectivity_verified,omitempty"`
	ProbeFailures      int       `json:"probe_failures,omitempty"`

	// Protection is what the service established for the WFP policy.
	Protection *protectionState `json:"protection,omitempty"`
}

// protectionState mirrors wfp.Status.
type protectionState struct {
	PendingEnrollment    bool              `json:"pending_enrollment"`
	Ready                bool              `json:"ready"`
	OldFlowsComplete     bool              `json:"old_flows_complete"`
	OldFlowsReason       string            `json:"old_flows_reason"`
	Classes              []wfp.ClassStatus `json:"classes"`
	Applied              bool              `json:"applied"`
	Apps                 int               `json:"apps"`
	Complete             bool              `json:"complete"`
	Incomplete           string            `json:"incomplete,omitempty"`
	Unresolved           int               `json:"unresolved,omitempty"`
	Permit               bool              `json:"permit"`
	PermitApps           int               `json:"permit_apps,omitempty"`
	PermitComplete       bool              `json:"permit_complete"`
	PendingPermitClosure bool              `json:"pending_permit_closure"`
	Error                string            `json:"error,omitempty"`
}

const (
	maxStateDetail = 400
	// heartbeatInterval is how often a running service refreshes the
	// state file; heartbeatMaxAge is when `status` stops believing it.
	heartbeatInterval = 30 * time.Second
	heartbeatMaxAge   = 90 * time.Second
)

// userPathRe matches the user-name component of profile paths that carry
// no drive letter (the log sink already handles C:\Users\name).
var userPathRe = regexp.MustCompile(`(?i)(\\users\\)[^\\/:*?"<>|\r\n]+`)

// scrubDetail removes user names from paths, line breaks and excess length.
// Key material is already removed by the engine.
func scrubDetail(s string) string {
	s = logfile.ScrubString(s)
	s = userPathRe.ReplaceAllString(s, `${1}<user>`)
	s = strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
	if len(s) > maxStateDetail {
		n := maxStateDetail
		for n > 0 && !utf8.RuneStart(s[n]) {
			n--
		}
		s = s[:n] + "…"
	}
	return s
}

// stateWriter owns the service's state record and rewrites it on every
// state change and every heartbeatInterval.
type stateWriter struct {
	mu          sync.Mutex
	cur         tunnelState
	log         io.Writer   // where failed writes are reported; may be nil
	logDegraded func() bool // may be nil
	write       func(path string, data []byte) error
	path        string
	failing     bool

	// kick is non-nil once startAsync runs: state changes then only update
	// memory and wake the writer goroutine, so callers (the engine
	// goroutine) never wait for the disk or the log mutex.
	kick chan struct{}
}

// startAsync starts the writer goroutine, which writes after every change
// (coalesced) and every heartbeatInterval, and once more when ctx ends.
// The returned channel is closed when the goroutine has exited.
func (w *stateWriter) startAsync(ctx context.Context) <-chan struct{} {
	w.mu.Lock()
	w.kick = make(chan struct{}, 1)
	kick := w.kick
	w.mu.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(heartbeatInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				w.heartbeat()
				return
			case <-kick:
				w.heartbeat()
			case <-t.C:
				w.heartbeat()
			}
		}
	}()
	return done
}

// changedLocked writes now (synchronous mode) or wakes the writer.
func (w *stateWriter) changedLocked() {
	if w.kick == nil {
		w.flushLocked()
		return
	}
	select {
	case w.kick <- struct{}{}:
	default:
	}
}

// newStateWriter is used by the service after the data directory has been
// secured, so the state file is written without sweeping it again.
func newStateWriter() *stateWriter {
	return &stateWriter{
		cur:   tunnelState{PID: os.Getpid(), ProcessStart: processStart()},
		write: paths.WriteSecureFileInDir,
		path:  paths.StatePath(),
	}
}

// set records a state change. It never fails: state reporting must never
// stop the tunnel; a failed write is logged (once until it works again).
func (w *stateWriter) set(state engine.State, detail string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.cur.State = string(state)
	w.cur.Detail = scrubDetail(detail)
	w.cur.Time = time.Now().UTC()
	if state != engine.StateTunnelStarted {
		// A probe result describes one running tunnel only.
		w.cur.Connectivity, w.cur.ConnectivityDetail = "", ""
		w.cur.ConnectivityTime, w.cur.ConnectivityOK, w.cur.ProbeFailures = time.Time{}, time.Time{}, 0
	}
	w.changedLocked()
}

// setConnectivity records a probe result (engine.RunOptions.OnConnectivity).
func (w *stateWriter) setConnectivity(r engine.ProbeResult) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.cur.Connectivity = string(r.State)
	w.cur.ConnectivityDetail = scrubDetail(r.Detail)
	w.cur.ConnectivityTime = r.Time
	w.cur.ConnectivityOK = r.Verified
	w.cur.ProbeFailures = r.Failures
	w.changedLocked()
}

// setProtection records the WFP guard status.
func (w *stateWriter) setProtection(st wfp.Status) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.cur.Protection = &protectionState{
		PendingEnrollment: st.PendingEnrollment,
		Ready:             st.Ready, OldFlowsComplete: st.OldFlowsComplete, OldFlowsReason: scrubDetail(st.OldFlowsReason), Classes: st.Classes,
		Applied: st.Applied, Apps: st.Apps, Complete: st.Complete, Incomplete: scrubDetail(st.Incomplete),
		Unresolved: st.Unresolved, Permit: st.Permit, PermitApps: st.PermitApps, PermitComplete: st.PermitComplete,
		PendingPermitClosure: st.PendingPermitClosure,
		Error:                scrubDetail(st.Err),
	}
	w.cur.Protection.Classes = append([]wfp.ClassStatus(nil), st.Classes...)
	for i := range w.cur.Protection.Classes {
		w.cur.Protection.Classes[i].Reason = scrubDetail(w.cur.Protection.Classes[i].Reason)
	}
	if w.cur.State != "" {
		w.changedLocked()
	}
}

func (w *stateWriter) heartbeat() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cur.State != "" {
		w.flushLocked()
	}
}

func (w *stateWriter) flushLocked() {
	w.cur.Heartbeat = time.Now().UTC()
	if w.logDegraded != nil {
		w.cur.LogDegraded = w.logDegraded()
	}
	data, err := json.Marshal(w.cur)
	if err == nil {
		err = w.write(w.path, data)
	}
	if err != nil {
		if !w.failing {
			w.logf("WARN", "cannot write tunnel state, `status` will show it as unknown: "+err.Error())
		}
		w.failing = true
		return
	}
	if w.failing {
		w.logf("INFO", "tunnel state written again")
	}
	w.failing = false
}

func (w *stateWriter) logf(level, msg string) {
	if w.log != nil {
		fmt.Fprintf(w.log, "%s %s [aurasplit] %s\n", time.Now().Format("-0700 2006-01-02 15:04:05"), level, scrubDetail(msg))
	}
}

// runHeartbeat refreshes the record until ctx is cancelled.
func (w *stateWriter) runHeartbeat(ctx context.Context) {
	t := time.NewTicker(heartbeatInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.heartbeat()
		}
	}
}

func readState() (tunnelState, error) {
	var st tunnelState
	b, err := os.ReadFile(paths.StatePath())
	if err != nil {
		return st, err
	}
	err = json.Unmarshal(b, &st)
	return st, err
}

// stateValid reports whether ts describes the service process the SCM
// reports right now (scmPID, from QueryServiceStatusEx) and is fresh.
// procStart returns a process's creation time when it can be read.
func stateValid(ts tunnelState, scmPID uint32, now time.Time, procStart func(pid uint32) (time.Time, bool)) bool {
	if scmPID == 0 || ts.PID <= 0 || uint32(ts.PID) != scmPID || ts.ProcessStart.IsZero() {
		return false
	}
	age := now.Sub(ts.Heartbeat)
	if ts.Heartbeat.IsZero() || age >= heartbeatMaxAge || age < -heartbeatMaxAge {
		return false
	}
	if start, ok := procStart(scmPID); ok {
		d := start.Sub(ts.ProcessStart)
		if d < -time.Second || d > time.Second {
			return false // the PID was reused by a newer process
		}
	}
	return true
}

func filetimeToTime(ft windows.Filetime) time.Time { return time.Unix(0, ft.Nanoseconds()).UTC() }

// processStart returns the creation time of the current process.
func processStart() time.Time {
	var c, e, k, u windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &c, &e, &k, &u); err != nil {
		return time.Now().UTC()
	}
	return filetimeToTime(c)
}

// processStartOf returns the creation time of process pid, if readable.
func processStartOf(pid uint32) (time.Time, bool) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return time.Time{}, false
	}
	defer windows.CloseHandle(h)
	var c, e, k, u windows.Filetime
	if err := windows.GetProcessTimes(h, &c, &e, &k, &u); err != nil {
		return time.Time{}, false
	}
	return filetimeToTime(c), true
}
