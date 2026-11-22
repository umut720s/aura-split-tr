package wfp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultRescanInterval is how often Guard.Run rediscovers Discord
	// executables when nothing else triggers it (backstop for the
	// directory watcher). Discovery is a handful of directory listings.
	DefaultRescanInterval = 60 * time.Second
	// DefaultRetryInterval is used instead while protection is incomplete
	// (discovery error, unresolved app IDs, permit missing or failed).
	DefaultRetryInterval = 10 * time.Second
	// WatchDebounce is how long Run waits after a watcher event before it
	// reconciles, so a burst of file operations costs one reconcile.
	WatchDebounce = 300 * time.Millisecond
	// MaxPermitSessions bounds how many dynamic permit sessions may be
	// open at once. More than one exists only while a replacement is
	// partial: an old session is closed only when the others permit every
	// still-relevant path it permitted.
	MaxPermitSessions = 2
)

// Status is a snapshot of what Guard has established.
type Status struct {
	// Applied: the persistent policy was written successfully at least
	// once by this Guard (provider, sublayer and blocks are in place).
	Applied bool
	// Apps is the number of executables with a persistent block.
	Apps int
	// Complete: the last discovery finished without error, every
	// executable was resolved and stale blocks were pruned. When false,
	// Incomplete says why; protection covers only the Apps listed.
	Complete   bool
	Incomplete string
	// Unresolved is the number of executables whose app ID could not be
	// read (their existing blocks were kept; retried every reconcile).
	Unresolved int
	// OverBudget is the number of executables left out because the policy
	// budget (MaxPolicyApps / MaxPolicyAppsPerProfile) is exhausted.
	OverBudget int
	// Permit: a dynamic tunnel permit session is open. PermitApps is the
	// number of executables the open sessions cover together;
	// PermitSessions how many sessions are open (more than one while a
	// partial replacement keeps the old session). PermitComplete is true
	// only if one session covers every blocked executable and no retry is
	// pending.
	Permit         bool
	PermitApps     int
	PermitSessions int
	PermitComplete bool
	// Err is the last hard error, empty after a successful write.
	Err string
}

// Guard owns the policy for one service run: it reconciles the persistent
// set with the discovered executables and keeps the dynamic tunnel permit
// in step with the blocked set.
//
// Deletion rule: only a reconcile whose discovery returned no error (no
// cap hit, every directory readable) is authoritative, and Policy.Apply
// additionally refuses to delete when an app ID is unresolved or when the
// recorded executable still exists. Every other reconcile is add-only, so
// the filters already in WFP (also those of a previous process) are the
// baseline that is never shrunk by an incomplete inventory.
type Guard struct {
	policy   Policy
	discover func() ([]string, error)
	logf     func(level, msg string)
	onChange func(Status)

	mu         sync.Mutex
	applied    bool
	complete   bool
	incomplete string
	unresolved int
	overBudget int
	inventory  []string // last discovered set
	covered    []string // executables with a persistent block
	tunnel     bool
	luid       uint64
	// permits are the open dynamic permit sessions, oldest first (at most
	// MaxPermitSessions).
	permits []Permit
	// permitDirty: the permit failed, is partial or is split over several
	// sessions and must be retried even if the inventory does not change.
	permitDirty bool
	lastErr     string
}

// NewGuard returns a Guard. discover returns the current Discord
// executables (partial results with an error are allowed; the error makes
// the pass add-only). logf and onChange may be nil.
func NewGuard(p Policy, discover func() ([]string, error), logf func(level, msg string), onChange func(Status)) *Guard {
	return &Guard{policy: p, discover: discover, logf: logf, onChange: onChange}
}

func (g *Guard) log(level, msg string) {
	if g.logf != nil {
		g.logf(level, msg)
	}
}

func equalPaths(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !strings.EqualFold(a[i], b[i]) {
			return false
		}
	}
	return true
}

// permitPathsLocked is the union of the paths of every open permit.
func (g *Guard) permitPathsLocked() []string {
	var all []string
	for _, p := range g.permits {
		all = append(all, p.Paths()...)
	}
	return normalizePaths(all)
}

func (g *Guard) permitCompleteLocked() bool {
	return len(g.permits) == 1 && !g.permitDirty && containsAll(g.permits[0].Paths(), g.covered)
}

// closePermitsLocked closes every open permit session.
func (g *Guard) closePermitsLocked() error {
	var errs []error
	for _, p := range g.permits {
		if err := p.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	g.permits = nil
	return errors.Join(errs...)
}

// statusLocked builds the snapshot; g.mu must be held.
func (g *Guard) statusLocked() Status {
	st := Status{
		Applied: g.applied, Apps: len(g.covered), Complete: g.applied && g.complete,
		Incomplete: g.incomplete, Unresolved: g.unresolved, OverBudget: g.overBudget,
		Permit: len(g.permits) > 0, PermitSessions: len(g.permits),
		PermitComplete: g.permitCompleteLocked(), Err: g.lastErr,
	}
	if len(g.permits) > 0 {
		st.PermitApps = len(g.permitPathsLocked())
	}
	if !g.applied && st.Incomplete == "" {
		st.Incomplete = "policy not applied yet"
	}
	return st
}

func (g *Guard) notifyLocked() {
	if g.onChange != nil {
		g.onChange(g.statusLocked())
	}
}

// Status returns the current snapshot.
func (g *Guard) Status() Status {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.statusLocked()
}

// healthy: nothing needs a quick retry.
func (g *Guard) healthy() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.applied && g.complete && !g.permitNeedsSyncLocked() && g.lastErr == ""
}

// permitNeedsSyncLocked: the tunnel runs and the permit is missing,
// failed, partial, split over several sessions or does not cover every
// blocked executable.
func (g *Guard) permitNeedsSyncLocked() bool {
	if !g.tunnel || !g.applied {
		return false
	}
	return len(g.permits) != 1 || g.permitDirty || !containsAll(g.permits[0].Paths(), g.covered)
}

// intersectPaths returns the paths of a that are also in b
// (case-insensitive).
func intersectPaths(a, b []string) []string {
	set := make(map[string]bool, len(b))
	for _, p := range b {
		set[strings.ToLower(p)] = true
	}
	var out []string
	for _, p := range a {
		if set[strings.ToLower(p)] {
			out = append(out, p)
		}
	}
	return out
}

// syncPermitLocked makes the permits cover set. The new session is opened
// before any old one is closed, and an old session is closed only when
// the remaining sessions permit every path of it that is still in set: a
// partial replacement (an executable's app ID failed transiently) extends
// coverage without retiring the old session, so a running Discord never
// loses a working permit. At most MaxPermitSessions stay open; a new
// session that cannot retire any old one beyond that bound is closed
// again (its new executables stay blocked, fail-closed). Anything but a
// single complete session marks the permit dirty, so it is retried.
func (g *Guard) syncPermitLocked(set []string) {
	if !g.tunnel {
		return
	}
	set = normalizePaths(set)
	if len(g.permits) == 1 && !g.permitDirty && containsAll(g.permits[0].Paths(), set) {
		return
	}
	p, err := g.policy.PermitOnTunnel(g.luid, set)
	if p == nil {
		// Fail closed: the blocks stay; a new executable stays blocked
		// until the retry succeeds.
		g.permitDirty = true
		if err == nil {
			err = errors.New("no permit returned")
		}
		g.log("ERROR", "wfp: cannot open the tunnel permit (retrying): "+err.Error())
		return
	}
	if err != nil {
		g.log("WARN", "wfp: tunnel permit incomplete (retrying): "+err.Error())
	}
	keep := append(append([]Permit(nil), g.permits...), p)
	for i := 0; i < len(keep)-1; { // the new session is never retired here
		var others []string
		for j, q := range keep {
			if j != i {
				others = append(others, q.Paths()...)
			}
		}
		if containsAll(others, intersectPaths(keep[i].Paths(), set)) {
			_ = keep[i].Close()
			keep = append(keep[:i:i], keep[i+1:]...)
			continue
		}
		i++
	}
	dirty := err != nil
	if len(keep) > MaxPermitSessions {
		g.log("WARN", fmt.Sprintf("wfp: tunnel permit would need more than %d sessions; the old sessions are kept, the new executables stay blocked (retrying)", MaxPermitSessions))
		_ = p.Close()
		keep = keep[:len(keep)-1]
		dirty = true
	}
	g.permits = keep
	g.permitDirty = dirty || len(keep) > 1
}

// Reconcile rediscovers the executables and applies them: authoritatively
// after a complete discovery, add-only otherwise. It is skipped only when
// the last pass was complete, the inventory is unchanged and the permit
// needs nothing, so unresolved executables and a failed permit are
// retried on every call.
func (g *Guard) Reconcile() error {
	found, derr := g.discover()
	g.mu.Lock()
	defer g.mu.Unlock()
	want := normalizePaths(found)
	if derr == nil && g.applied && g.complete && g.lastErr == "" && equalPaths(want, g.inventory) && !g.permitNeedsSyncLocked() {
		return nil
	}
	mode := Authoritative
	if derr != nil {
		mode = AddOnly
		g.log("WARN", "wfp: Discord discovery incomplete, adding only (no filter is removed): "+derr.Error())
	}

	// Extend the permit before the block set grows (Firewall bounds the
	// permit set by the policy budget).
	if g.applied {
		g.syncPermitLocked(append(append([]string(nil), want...), g.covered...))
	}
	res, err := g.policy.Apply(want, mode)
	var inc *IncompleteError
	if err != nil && !errors.As(err, &inc) {
		g.lastErr = err.Error()
		g.notifyLocked()
		return err
	}
	g.applied = true
	g.inventory = want
	g.covered = res.Covered
	g.unresolved = len(res.Unresolved)
	g.overBudget = len(res.OverBudget)
	g.lastErr = ""
	var reasons []string
	if derr != nil {
		reasons = append(reasons, "discovery: "+derr.Error())
	}
	if inc != nil && len(inc.Unresolved) > 0 {
		reasons = append(reasons, fmt.Sprintf("%d executable(s) unresolved", len(inc.Unresolved)))
	}
	if inc != nil && len(inc.OverBudget) > 0 {
		reasons = append(reasons, fmt.Sprintf("%d executable(s) over the policy budget (%d total, %d per profile)",
			len(inc.OverBudget), MaxPolicyApps, MaxPolicyAppsPerProfile))
	}
	g.complete = len(reasons) == 0
	g.incomplete = strings.Join(reasons, "; ")
	// Make the permit cover everything that is blocked now (also blocks of
	// a previous process found in WFP). Unresolved and over-budget
	// executables have no new block, so they are not part of the set.
	g.syncPermitLocked(g.covered)
	g.notifyLocked()
	if !g.complete {
		return fmt.Errorf("%w: %s", ErrIncomplete, g.incomplete)
	}
	return nil
}

type permitHandle struct {
	g    *Guard
	once sync.Once
}

func (h *permitHandle) Close() error {
	var err error
	h.once.Do(func() { err = h.g.tunnelDown() })
	return err
}

// TunnelUp records that the tunnel runs on interface luid and opens the
// dynamic permit for the blocked set. If no persistent policy was applied
// by this Guard yet, no permit is opened now; a later successful Reconcile
// adds it. A permit that fails completely is returned as an error (the
// engine then treats the tunnel start as failed and keeps Discord
// blocked); a partial permit is kept and retried by Reconcile. Closing
// the returned handle closes the permit.
func (g *Guard) TunnelUp(luid uint64) (io.Closer, error) {
	if luid == 0 {
		return nil, errors.New("wfp: tunnel interface LUID is zero")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	_ = g.closePermitsLocked()
	g.permitDirty = false
	if g.applied {
		p, err := g.policy.PermitOnTunnel(luid, g.covered)
		if p == nil {
			if err == nil {
				err = errors.New("no permit returned")
			}
			g.lastErr = err.Error()
			g.notifyLocked()
			return nil, err
		}
		g.permits = []Permit{p}
		if err != nil {
			g.permitDirty = true
			g.log("WARN", "wfp: tunnel permit incomplete (retrying): "+err.Error())
		}
	}
	g.tunnel, g.luid = true, luid
	g.notifyLocked()
	return &permitHandle{g: g}, nil
}

func (g *Guard) tunnelDown() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.tunnel, g.luid = false, 0
	g.permitDirty = false
	err := g.closePermitsLocked()
	g.notifyLocked()
	return err
}

// Run reconciles until ctx is cancelled: every interval, every
// DefaultRetryInterval (at most interval) while protection is incomplete,
// and WatchDebounce after each signal on kick (directory watcher; may be
// nil). The first reconcile is expected to have been done by the caller.
func (g *Guard) Run(ctx context.Context, interval time.Duration, kick <-chan struct{}) {
	if interval <= 0 {
		interval = DefaultRescanInterval
	}
	retry := DefaultRetryInterval
	if retry > interval {
		retry = interval
	}
	next := func() time.Duration {
		if g.healthy() {
			return interval
		}
		return retry
	}
	t := time.NewTimer(next())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-kick:
			d := time.NewTimer(WatchDebounce)
			select {
			case <-ctx.Done():
				d.Stop()
				return
			case <-d.C:
			}
			select { // coalesce events that arrived meanwhile
			case <-kick:
			default:
			}
		case <-t.C:
		}
		if err := g.Reconcile(); err != nil {
			g.log("ERROR", "wfp: reconcile: "+err.Error())
		}
		if !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
		t.Reset(next())
	}
}
