// Package wfp keeps Discord fail-closed with Windows Filtering Platform
// filters that do not depend on the AURA Split TR service running.
//
// Objects (all owned by one provider with a fixed key, see ProviderKey):
//
//   - a persistent provider and a persistent sublayer (weight SubLayerWeight,
//     always below sing-tun's dynamic sublayer at 0xFFFF);
//   - persistent filters, per Discord application ID and per layer
//     (ALE_AUTH_CONNECT_V4/V6, ALE_AUTH_RECV_ACCEPT_V4/V6):
//     weight 15 PERMIT for loopback traffic, weight 1 BLOCK for everything
//     else. BFE loads them at boot, before any user can log on. Each one
//     records the executable path in its provider data;
//   - dynamic filters (a FWPM_SESSION_FLAG_DYNAMIC session owned by the
//     running service): weight 10 PERMIT per application ID when the local
//     interface is the AuraSplit TUN. They vanish when the session handle is
//     closed or the process dies, so Discord is blocked again at once.
//
// Within one sublayer the highest-weight matching filter decides, so the
// result is: loopback permit > TUN permit > block.
//
// ALE_APP_ID is matched with FWP_MATCH_EQUAL. FWP_MATCH_PREFIX is not
// documented as supported for FWPM_CONDITION_ALE_APP_ID (a byte blob), so
// every Discord executable is listed exactly. Fail-closed therefore covers
// only the executables that were discovered and resolved (the inventory);
// see ARCHITECTURE.md for the remaining update race.
//
// Persistent filters have deterministic keys derived from (kind, layer,
// app ID). Reconciliation enumerates the provider's filters inside the
// same read-write transaction that changes them, so the snapshot and the
// diff cannot be overtaken by another session. Deletions are only ever
// made by an authoritative Apply (complete discovery, every path resolved)
// and never for a filter whose recorded executable still exists on disk.
// Dynamic filters get keys from BFE, so an overlapping replacement session
// never collides with the old one.
//
// The provider deliberately has no service name: BFE would then treat the
// policy as disabled while the service is disabled, which would defeat the
// fail-closed purpose.
package wfp

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"
	"sync"
)

// Key is a GUID with the in-memory layout of the Windows GUID structure.
type Key struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

func (k Key) String() string {
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		k.Data1, k.Data2, k.Data3, k.Data4[0], k.Data4[1],
		k.Data4[2], k.Data4[3], k.Data4[4], k.Data4[5], k.Data4[6], k.Data4[7])
}

// IsZero reports whether k is the nil GUID.
func (k Key) IsZero() bool { return k == Key{} }

var (
	// ProviderKey identifies every WFP object of AURA Split TR.
	// 4699124e-3633-487f-90c5-77e86738322c
	ProviderKey = Key{0x4699124e, 0x3633, 0x487f, [8]byte{0x90, 0xc5, 0x77, 0xe8, 0x67, 0x38, 0x32, 0x2c}}
	// SubLayerKey is our persistent sublayer.
	// 58005a25-e04f-4367-9093-bbaeca5dd4f3
	SubLayerKey = Key{0x58005a25, 0xe04f, 0x4367, [8]byte{0x90, 0x93, 0xbb, 0xae, 0xca, 0x5d, 0xd4, 0xf3}}
)

const (
	// SubLayerWeight must stay below sing-tun's 0xFFFF; equal weights would
	// make the evaluation order of the two sublayers undefined.
	SubLayerWeight uint16 = 0xF000

	WeightLoopbackPermit uint8 = 15
	WeightTunnelPermit   uint8 = 10
	WeightBlock          uint8 = 1

	ProviderName = "AURA Split TR"
	SubLayerName = "AURA Split TR Discord fail-closed"
)

// Layer is one of the four ALE layers we filter.
type Layer uint8

const (
	LayerConnectV4 Layer = iota
	LayerConnectV6
	LayerRecvAcceptV4
	LayerRecvAcceptV6
)

// Layers lists every layer a policy covers.
var Layers = []Layer{LayerConnectV4, LayerConnectV6, LayerRecvAcceptV4, LayerRecvAcceptV6}

func (l Layer) String() string {
	switch l {
	case LayerConnectV4:
		return "ale-connect-v4"
	case LayerConnectV6:
		return "ale-connect-v6"
	case LayerRecvAcceptV4:
		return "ale-recv-accept-v4"
	case LayerRecvAcceptV6:
		return "ale-recv-accept-v6"
	}
	return fmt.Sprintf("layer-%d", uint8(l))
}

// Action is a terminating filter action.
type Action uint8

const (
	ActionBlock Action = iota + 1
	ActionPermit
)

// Filter is the backend-neutral description of one filter.
type Filter struct {
	Key        Key // zero: BFE assigns one (dynamic filters)
	Name       string
	Layer      Layer
	Action     Action
	Weight     uint8
	Persistent bool
	AppID      []byte // FwpmGetAppIdFromFileName0 blob
	// Path is the executable path, stored as the filter's provider data.
	Path string
	// Loopback adds FWPM_CONDITION_FLAGS has FWP_CONDITION_FLAG_IS_LOOPBACK.
	Loopback bool
	// LocalInterface, when non-zero, adds FWPM_CONDITION_IP_LOCAL_INTERFACE
	// == LocalInterface (an interface LUID).
	LocalInterface uint64
}

// FilterRecord is an existing filter found by enumerating our provider.
type FilterRecord struct {
	ID         uint64
	Key        Key
	Layer      Layer
	Action     Action
	Persistent bool
	// Disabled: BFE reports the filter as disabled (FWPM_FILTER_FLAG_DISABLED).
	// A disabled filter enforces nothing: it never counts as coverage, and
	// a wanted filter found disabled is deleted and re-added.
	Disabled bool
	// Path is the executable path from the provider data ("" for filters
	// written by an older version).
	Path string
}

// Policy budget: the persistent policy (existing plus proposed) never
// covers more than MaxPolicyApps executables in total and
// MaxPolicyAppsPerProfile per user profile. Executables beyond it are not
// added (reported as OverBudget, the pass is incomplete); existing blocks
// are never removed to make room. The dynamic tunnel permit uses the same
// budget.
const (
	MaxPolicyApps           = 1024
	MaxPolicyAppsPerProfile = 128
)

// profileOf returns the budget bucket of an executable path: the user
// profile directory (the part before \AppData\Local\, lower case), or ""
// for any other path.
func profileOf(p string) string {
	l := strings.ToLower(strings.ReplaceAll(p, "/", `\`))
	if i := strings.Index(l, `\appdata\local\`); i > 0 {
		return l[:i]
	}
	return ""
}

// budget counts admitted executables.
type budget struct {
	total      int
	perProfile map[string]int
}

func newBudget() *budget { return &budget{perProfile: map[string]int{}} }

// take admits p if the budget allows it.
func (b *budget) take(p string) bool {
	prof := profileOf(p)
	if b.total >= MaxPolicyApps || b.perProfile[prof] >= MaxPolicyAppsPerProfile {
		return false
	}
	b.count(p)
	return true
}

// count records p unconditionally (existing policy may exceed the budget).
func (b *budget) count(p string) {
	b.total++
	b.perProfile[profileOf(p)]++
}

// session is one open BFE engine handle.
type session interface {
	// Begin opens a read-write transaction; BFE serialises them across
	// sessions and processes.
	Begin() error
	Commit() error
	Abort() error
	// AddProvider / AddSubLayer succeed when the object already exists.
	AddProvider() error
	AddSubLayer() error
	HasProvider() (bool, error)
	HasSubLayer() (bool, error)
	// Filters lists every filter of ProviderKey on every layer in Layers,
	// disabled filters included.
	Filters() ([]FilterRecord, error)
	// AddFilter succeeds when a filter with the same non-zero key exists.
	AddFilter(f *Filter) error
	// The Delete methods succeed when the object does not exist.
	DeleteFilter(id uint64) error
	DeleteSubLayer() error
	DeleteProvider() error
	Close() error
}

// backend opens sessions and converts paths to application IDs.
type backend interface {
	Open(dynamic bool) (session, error)
	AppID(path string) ([]byte, error)
}

// ApplyMode selects whether Apply may delete filters.
type ApplyMode int

const (
	// AddOnly adds missing filters and never deletes one. It is used
	// whenever the inventory may be incomplete (discovery error, cap hit,
	// first start with an unreadable profile).
	AddOnly ApplyMode = iota
	// Authoritative also removes stale persistent filters. Apply downgrades
	// it to AddOnly when any path cannot be resolved, and it never removes
	// a filter whose recorded executable still exists.
	Authoritative
)

func (m ApplyMode) String() string {
	if m == Authoritative {
		return "authoritative"
	}
	return "add-only"
}

// ApplyResult describes the persistent policy after a successful Apply.
type ApplyResult struct {
	// Covered lists the executables with a persistent block after the
	// call: the resolved requested paths plus every kept filter whose path
	// is recorded (normalised).
	Covered []string
	// Unresolved lists requested paths that exist (or could not be
	// checked) but whose app ID could not be read. Their existing filters
	// were kept; they are retried by the next Apply.
	Unresolved []string
	// OverBudget lists resolved executables that were not added because
	// the policy budget (MaxPolicyApps / MaxPolicyAppsPerProfile) is
	// exhausted. They are retried by the next Apply.
	OverBudget []string
	// Pruned is true when stale filters were allowed to be removed.
	Pruned bool
}

// ErrIncomplete marks a result that does not cover every executable.
var ErrIncomplete = errors.New("wfp: protection incomplete")

// IncompleteError is returned (together with a valid result) when some
// executables could not be resolved. Whatever could be applied was
// committed.
type IncompleteError struct {
	Unresolved []string
	// OverBudget lists executables left out because of the policy budget.
	OverBudget []string
	Err        error
}

func (e *IncompleteError) Error() string {
	return fmt.Sprintf("wfp: protection incomplete: %d executable(s) unresolved, %d over the policy budget: %v",
		len(e.Unresolved), len(e.OverBudget), e.Err)
}

// errBudget is the cause recorded for executables left out by the budget.
var errBudget = fmt.Errorf("policy budget exhausted (%d executables, %d per profile)", MaxPolicyApps, MaxPolicyAppsPerProfile)

func incompleteErr(unresolved, overBudget []string, errs []error) error {
	if len(unresolved) == 0 && len(overBudget) == 0 {
		return nil
	}
	if len(overBudget) > 0 {
		errs = append(errs, errBudget)
	}
	return &IncompleteError{Unresolved: unresolved, OverBudget: overBudget, Err: errors.Join(errs...)}
}

func (e *IncompleteError) Unwrap() []error { return []error{ErrIncomplete, e.Err} }

// Permit is an open dynamic tunnel permit.
type Permit interface {
	io.Closer
	// Paths lists the executables the permit covers: those with a permit
	// filter, plus those that no longer exist (nothing to permit).
	Paths() []string
}

// Policy is what the service and the CLI use; Firewall implements it and
// tests use a fake.
type Policy interface {
	// Apply adds the persistent filters for paths and, in Authoritative
	// mode with every path resolved, removes stale ones, in one
	// transaction. An *IncompleteError comes with a valid result.
	Apply(paths []string, mode ApplyMode) (ApplyResult, error)
	// PermitOnTunnel opens a dynamic session that permits the given
	// executables on the interface luid; closing it removes the permits.
	// An *IncompleteError comes with a valid (partial) permit.
	PermitOnTunnel(luid uint64, paths []string) (Permit, error)
	// RemoveAll deletes every filter of our provider, then the sublayer,
	// then the provider, in one transaction.
	RemoveAll() error
	// Installed reports whether provider and sublayer exist and how many
	// executables have a persistent block.
	Installed() (bool, int, error)
	// Snapshot captures policy presence and protected paths without discovery.
	Snapshot() (bool, []string, error)
}

// ErrUnsupported is returned on non-Windows platforms.
var ErrUnsupported = errors.New("wfp: only supported on Windows")

// lifecycleMu serialises every write operation of this process (Apply,
// PermitOnTunnel, RemoveAll). Between processes (the service and a CLI
// command) BFE serialises the read-write transactions themselves; the CLI
// commands that remove the policy disable and stop the service first.
var lifecycleMu sync.Mutex

// Firewall implements Policy on a backend.
type Firewall struct {
	b backend
	// Logf receives non-fatal problems. May be nil.
	Logf func(level, msg string)
	// lstat checks whether a path exists (nil: os.Lstat); tests replace it.
	lstat func(string) error
}

// New returns a Firewall on the real WFP backend (Windows only).
func New() *Firewall { return &Firewall{b: platformBackend()} }

type app struct {
	path string
	id   []byte
}

func (f *Firewall) logf(level, msg string) {
	if f.Logf != nil {
		f.Logf(level, msg)
	}
}

// exists reports whether p may still exist: false only when the file
// system says it does not.
func (f *Firewall) exists(p string) bool {
	st := f.lstat
	if st == nil {
		st = func(p string) error { _, err := os.Lstat(p); return err }
	}
	return !errors.Is(st(p), fs.ErrNotExist)
}

type resolved struct {
	apps       []app
	missing    []string // gone from disk: nothing to protect
	unresolved []string // exist (or unknown) but no app ID
	errs       []error
}

// resolve converts paths to unique app IDs. A path whose app ID cannot be
// read is "missing" if the file is gone, otherwise "unresolved".
func (f *Firewall) resolve(paths []string) resolved {
	var r resolved
	seen := map[string]bool{}
	for _, p := range normalizePaths(paths) {
		id, err := f.b.AppID(p)
		if err == nil && len(id) == 0 {
			err = errors.New("empty app ID")
		}
		if err != nil {
			if !f.exists(p) {
				r.missing = append(r.missing, p)
				continue
			}
			r.unresolved = append(r.unresolved, p)
			r.errs = append(r.errs, fmt.Errorf("%s: %w", p, err))
			f.logf("WARN", fmt.Sprintf("wfp: app ID unavailable, executable kept as unresolved: %s: %v", p, err))
			continue
		}
		k := string(id)
		if seen[k] {
			continue
		}
		seen[k] = true
		r.apps = append(r.apps, app{path: p, id: id})
	}
	sort.Slice(r.apps, func(i, j int) bool { return string(r.apps[i].id) < string(r.apps[j].id) })
	return r
}

// filterKey derives the deterministic key of a persistent filter.
func filterKey(kind string, l Layer, appID []byte) Key {
	h := sha256.New()
	h.Write([]byte("aurasplit-wfp-v1|" + kind + "|" + l.String() + "|"))
	h.Write(appID)
	s := h.Sum(nil)
	var k Key
	k.Data1 = uint32(s[0])<<24 | uint32(s[1])<<16 | uint32(s[2])<<8 | uint32(s[3])
	k.Data2 = uint16(s[4])<<8 | uint16(s[5])
	k.Data3 = (uint16(s[6])<<8|uint16(s[7]))&0x0fff | 0x5000 // name-based GUID
	copy(k.Data4[:], s[8:16])
	k.Data4[0] = k.Data4[0]&0x3f | 0x80 // RFC 4122 variant
	return k
}

// persistentFilters is the wanted persistent set for apps.
func persistentFilters(apps []app) []Filter {
	var out []Filter
	for _, a := range apps {
		for _, l := range Layers {
			out = append(out,
				Filter{
					Key: filterKey("loopback-permit", l, a.id), Name: "AURA Split TR: Discord loopback permit",
					Layer: l, Action: ActionPermit, Weight: WeightLoopbackPermit, Persistent: true,
					AppID: a.id, Path: a.path, Loopback: true,
				},
				Filter{
					Key: filterKey("block", l, a.id), Name: "AURA Split TR: Discord block (fail-closed)",
					Layer: l, Action: ActionBlock, Weight: WeightBlock, Persistent: true,
					AppID: a.id, Path: a.path,
				})
		}
	}
	return out
}

// tunnelFilters is the dynamic permit set for apps on interface luid.
func tunnelFilters(apps []app, luid uint64) []Filter {
	var out []Filter
	for _, a := range apps {
		for _, l := range Layers {
			out = append(out, Filter{
				Name: "AURA Split TR: Discord permit on tunnel", Layer: l, Action: ActionPermit,
				Weight: WeightTunnelPermit, AppID: a.id, Path: a.path, LocalInterface: luid,
			})
		}
	}
	return out
}

// diff returns the wanted filters that must be added, our persistent
// filters that are not wanted (stale) and the wanted filters that exist
// only disabled (redo: they are deleted and re-added in the same
// transaction, because adding a filter whose key exists is a no-op). A
// disabled filter never counts as present. Dynamic filters are never
// touched.
func diff(existing []FilterRecord, want []Filter) (add []Filter, stale, redo []FilterRecord) {
	have := map[Key]bool{}
	wantKeys := map[Key]bool{}
	for _, w := range want {
		wantKeys[w.Key] = true
	}
	for _, r := range existing {
		if !r.Persistent {
			continue
		}
		if wantKeys[r.Key] {
			if r.Disabled {
				redo = append(redo, r)
				continue
			}
			if !have[r.Key] {
				have[r.Key] = true
				continue
			}
		}
		stale = append(stale, r)
	}
	added := map[Key]bool{}
	for _, w := range want {
		if !have[w.Key] && !added[w.Key] {
			added[w.Key] = true
			add = append(add, w)
		}
	}
	return add, stale, redo
}

// errNoChange makes inTxn abort a transaction that found nothing to do.
var errNoChange = errors.New("no change")

// inTxn runs fn inside a transaction on s, aborting on error.
func inTxn(s session, fn func() error) error {
	if err := s.Begin(); err != nil {
		return fmt.Errorf("wfp: begin transaction: %w", err)
	}
	if err := fn(); err != nil {
		aerr := s.Abort()
		if errors.Is(err, errNoChange) {
			if aerr != nil {
				return fmt.Errorf("wfp: abort transaction: %w", aerr)
			}
			return nil
		}
		if aerr != nil {
			return errors.Join(err, fmt.Errorf("wfp: abort transaction: %w", aerr))
		}
		return err
	}
	if err := s.Commit(); err != nil {
		return fmt.Errorf("wfp: commit transaction: %w", err)
	}
	return nil
}

// Apply implements Policy.
func (f *Firewall) Apply(paths []string, mode ApplyMode) (ApplyResult, error) {
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()
	r := f.resolve(paths)
	prune := mode == Authoritative && len(r.unresolved) == 0
	if mode == Authoritative && !prune {
		f.logf("WARN", "wfp: unresolved executables, no filter is removed in this pass")
	}
	s, err := f.b.Open(false)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("wfp: open engine: %w", err)
	}
	defer s.Close()

	res := ApplyResult{Pruned: prune}
	var extraUnresolved, over []string
	var extraErrs []error
	err = inTxn(s, func() error {
		// Snapshot and diff inside the write transaction.
		hasP, err := s.HasProvider()
		if err != nil {
			return err
		}
		hasS, err := s.HasSubLayer()
		if err != nil {
			return err
		}
		var existing []FilterRecord
		if hasP {
			if existing, err = s.Filters(); err != nil {
				return fmt.Errorf("wfp: list filters: %w", err)
			}
		}
		// split separates stale filters into deletable and kept ones:
		// never remove a block whose executable still exists, and nothing
		// at all unless the inventory is authoritative.
		split := func(stale []FilterRecord) (del []uint64, kept []FilterRecord) {
			for _, rec := range stale {
				if prune && (rec.Path == "" || !f.exists(rec.Path)) {
					del = append(del, rec.ID)
					continue
				}
				kept = append(kept, rec)
			}
			return del, kept
		}
		present := map[Key]bool{}
		for _, rec := range existing {
			if rec.Persistent {
				present[rec.Key] = true
			}
		}
		_, stale, _ := diff(existing, persistentFilters(r.apps))
		del, kept := split(stale)

		// Budget: every executable that keeps a persistent block counts
		// first (also beyond the budget: nothing is removed to make room),
		// then new executables are admitted while the budget allows.
		deleted := make(map[uint64]bool, len(del))
		for _, id := range del {
			deleted[id] = true
		}
		b := newBudget()
		for _, rec := range existing {
			if rec.Persistent && rec.Action == ActionBlock && rec.Layer == LayerConnectV4 && !deleted[rec.ID] {
				b.count(rec.Path)
			}
		}
		over = nil
		apps := make([]app, 0, len(r.apps))
		for _, a := range r.apps {
			if present[filterKey("block", LayerConnectV4, a.id)] || b.take(a.path) {
				apps = append(apps, a)
				continue
			}
			over = append(over, a.path)
		}
		if len(over) > 0 {
			f.logf("WARN", fmt.Sprintf("wfp: policy budget exhausted, %d executable(s) not added", len(over)))
		}
		// Kept filters that BFE reports disabled are re-created from their
		// recorded path (they already count against the budget).
		var revive []string
		for _, rec := range kept {
			if rec.Disabled && rec.Path != "" {
				revive = append(revive, rec.Path)
			}
		}
		extraUnresolved, extraErrs = nil, nil
		if len(revive) > 0 {
			x := f.resolve(revive)
			apps = append(apps, x.apps...)
			extraUnresolved, extraErrs = x.unresolved, x.errs
		}

		add, stale, redo := diff(existing, persistentFilters(apps))
		del, kept = split(stale)
		covered := make([]string, 0, len(apps))
		for _, a := range apps {
			covered = append(covered, a.path)
		}
		for _, rec := range kept {
			// A disabled block enforces nothing and is not coverage.
			if rec.Action == ActionBlock && rec.Path != "" && !rec.Disabled {
				covered = append(covered, rec.Path)
			}
		}
		res.Covered = normalizePaths(covered)
		if hasP && hasS && len(add) == 0 && len(del) == 0 && len(redo) == 0 {
			return errNoChange
		}
		if err := s.AddProvider(); err != nil {
			return fmt.Errorf("wfp: add provider: %w", err)
		}
		if err := s.AddSubLayer(); err != nil {
			return fmt.Errorf("wfp: add sublayer: %w", err)
		}
		// Disabled copies of wanted filters go first, so the re-add below
		// creates an enabled filter with the same deterministic key.
		for _, rec := range redo {
			if err := s.DeleteFilter(rec.ID); err != nil {
				return fmt.Errorf("wfp: delete disabled filter %d: %w", rec.ID, err)
			}
		}
		// Blocks for new executables are added before stale ones are
		// removed; inside a transaction the order is not observable, but
		// it keeps a partial failure (aborted anyway) on the safe side.
		for i := range add {
			if err := s.AddFilter(&add[i]); err != nil {
				return fmt.Errorf("wfp: add filter (%s): %w", add[i].Layer, err)
			}
		}
		for _, id := range del {
			if err := s.DeleteFilter(id); err != nil {
				return fmt.Errorf("wfp: delete stale filter %d: %w", id, err)
			}
		}
		return nil
	})
	if err != nil {
		return ApplyResult{}, err
	}
	res.Unresolved = normalizePaths(append(append([]string(nil), r.unresolved...), extraUnresolved...))
	res.OverBudget = over
	return res, incompleteErr(res.Unresolved, over, append(append([]error(nil), r.errs...), extraErrs...))
}

type sessionPermit struct {
	s     session
	paths []string
}

func (c *sessionPermit) Paths() []string { return c.paths }

func (c *sessionPermit) Close() error {
	if c.s == nil {
		return nil
	}
	if err := c.s.Close(); err != nil {
		return err
	}
	c.s = nil
	return nil
}

// PermitOnTunnel implements Policy.
func (f *Firewall) PermitOnTunnel(luid uint64, paths []string) (Permit, error) {
	if luid == 0 {
		return nil, errors.New("wfp: tunnel interface LUID is zero")
	}
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()
	r := f.resolve(paths)
	s, err := f.b.Open(true)
	if err != nil {
		return nil, fmt.Errorf("wfp: open dynamic session: %w", err)
	}
	// The dynamic permit set stays within the same budget as the
	// persistent policy.
	b := newBudget()
	var apps []app
	var over []string
	for _, a := range r.apps {
		if b.take(a.path) {
			apps = append(apps, a)
		} else {
			over = append(over, a.path)
		}
	}
	filters := tunnelFilters(apps, luid)
	err = inTxn(s, func() error {
		for i := range filters {
			if err := s.AddFilter(&filters[i]); err != nil {
				return fmt.Errorf("wfp: add tunnel permit (%s): %w", filters[i].Layer, err)
			}
		}
		return nil
	})
	if err != nil {
		_ = s.Close()
		return nil, err
	}
	covered := append([]string(nil), r.missing...)
	for _, a := range apps {
		covered = append(covered, a.path)
	}
	return &sessionPermit{s: s, paths: normalizePaths(covered)}, incompleteErr(r.unresolved, over, r.errs)
}

// RemoveAll implements Policy. It is idempotent.
func (f *Firewall) RemoveAll() error {
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()
	s, err := f.b.Open(false)
	if err != nil {
		return fmt.Errorf("wfp: open engine: %w", err)
	}
	defer s.Close()
	return inTxn(s, func() error {
		hasP, err := s.HasProvider()
		if err != nil {
			return err
		}
		var recs []FilterRecord
		if hasP {
			if recs, err = s.Filters(); err != nil {
				return fmt.Errorf("wfp: list filters: %w", err)
			}
		}
		for _, r := range recs {
			if err := s.DeleteFilter(r.ID); err != nil {
				return fmt.Errorf("wfp: delete filter %d: %w", r.ID, err)
			}
		}
		if err := s.DeleteSubLayer(); err != nil {
			return fmt.Errorf("wfp: delete sublayer: %w", err)
		}
		if err := s.DeleteProvider(); err != nil {
			return fmt.Errorf("wfp: delete provider: %w", err)
		}
		return nil
	})
}

// Installed implements Policy. The count is the number of executables
// with an enabled persistent block (counted on the IPv4 connect layer);
// disabled filters enforce nothing and are not counted.
func (f *Firewall) Installed() (bool, int, error) {
	s, err := f.b.Open(false)
	if err != nil {
		return false, 0, fmt.Errorf("wfp: open engine: %w", err)
	}
	defer s.Close()
	hasP, err := s.HasProvider()
	if err != nil || !hasP {
		return false, 0, err
	}
	hasS, err := s.HasSubLayer()
	if err != nil {
		return false, 0, err
	}
	recs, err := s.Filters()
	if err != nil {
		return false, 0, fmt.Errorf("wfp: list filters: %w", err)
	}
	n := 0
	for _, r := range recs {
		if r.Persistent && !r.Disabled && r.Action == ActionBlock && r.Layer == LayerConnectV4 {
			n++
		}
	}
	return hasS, n, nil
}

// Snapshot reads a consistent policy inventory in a BFE transaction. Unknown
// block paths make recovery unsafe, so callers must not save a partial record.
func (f *Firewall) Snapshot() (bool, []string, error) {
	s, err := f.b.Open(false)
	if err != nil {
		return false, nil, fmt.Errorf("wfp: open engine: %w", err)
	}
	defer s.Close()
	var installed bool
	var paths []string
	err = inTxn(s, func() error {
		hasP, err := s.HasProvider()
		if err != nil || !hasP {
			return err
		}
		hasS, err := s.HasSubLayer()
		if err != nil {
			return err
		}
		if !hasS {
			return errors.New("wfp: provider without sublayer; cannot capture policy")
		}
		recs, err := s.Filters()
		if err != nil {
			return err
		}
		installed = true
		for _, rec := range recs {
			if rec.Persistent && !rec.Disabled && rec.Action == ActionBlock {
				if rec.Path == "" {
					return errors.New("wfp: block path missing; cannot capture policy")
				}
				paths = append(paths, rec.Path)
			}
		}
		return nil
	})
	if err != nil {
		return false, nil, err
	}
	return installed, normalizePaths(paths), nil
}

// normalizePaths returns a sorted, de-duplicated (case-insensitive) copy.
func normalizePaths(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range in {
		k := strings.ToLower(p)
		if p == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i]) < strings.ToLower(out[j]) })
	return out
}

// containsAll reports whether every path of want is in have
// (case-insensitive).
func containsAll(have, want []string) bool {
	set := make(map[string]bool, len(have))
	for _, p := range have {
		set[strings.ToLower(p)] = true
	}
	for _, p := range want {
		if !set[strings.ToLower(p)] {
			return false
		}
	}
	return true
}
