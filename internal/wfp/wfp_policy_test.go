package wfp

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"testing"
)

// fakeBFE is an in-memory BFE shared by all sessions of a fakeBackend.
type fakeBFE struct {
	mu       sync.Mutex
	nextID   uint64
	provider bool
	sublayer bool
	filters  map[uint64]fakeFilter
	log      []string
	failAdd  int // fail the n-th AddFilter (1-based), 0 = never
	adds     int
}

type fakeFilter struct {
	f        Filter
	session  int
	disabled bool // BFE reports the filter disabled
}

type fakeBackend struct {
	bfe      *fakeBFE
	sessions int
	appIDErr map[string]bool
}

func newFake() *fakeBackend {
	return &fakeBackend{bfe: &fakeBFE{filters: map[uint64]fakeFilter{}}, appIDErr: map[string]bool{}}
}

func (b *fakeBackend) Open(dynamic bool) (session, error) {
	b.sessions++
	b.bfe.mu.Lock()
	defer b.bfe.mu.Unlock()
	b.bfe.log = append(b.bfe.log, fmt.Sprintf("open dynamic=%v", dynamic))
	return &fakeSession{bfe: b.bfe, id: b.sessions, dynamic: dynamic}, nil
}

func (b *fakeBackend) AppID(path string) ([]byte, error) {
	if b.appIDErr[path] {
		return nil, errors.New("file not found")
	}
	return []byte(`\device\harddiskvolume1` + strings.ToLower(path)), nil
}

// fakeSession applies changes to a copy during a transaction and commits
// them atomically.
type fakeSession struct {
	bfe        *fakeBFE
	id         int
	dynamic    bool
	inTxn      bool
	snap       *fakeBFE
	closed     bool
	closeErr   error
	closeCalls int
}

func (s *fakeSession) logf(f string, a ...any) { s.bfe.log = append(s.bfe.log, fmt.Sprintf(f, a...)) }

func (s *fakeSession) Begin() error {
	s.bfe.mu.Lock()
	defer s.bfe.mu.Unlock()
	s.logf("begin")
	cp := map[uint64]fakeFilter{}
	for k, v := range s.bfe.filters {
		cp[k] = v
	}
	s.snap = &fakeBFE{provider: s.bfe.provider, sublayer: s.bfe.sublayer, filters: cp, nextID: s.bfe.nextID}
	s.inTxn = true
	return nil
}

func (s *fakeSession) Commit() error {
	s.bfe.mu.Lock()
	defer s.bfe.mu.Unlock()
	s.logf("commit")
	s.inTxn, s.snap = false, nil
	return nil
}

func (s *fakeSession) Abort() error {
	s.bfe.mu.Lock()
	defer s.bfe.mu.Unlock()
	s.logf("abort")
	s.bfe.provider, s.bfe.sublayer, s.bfe.filters, s.bfe.nextID = s.snap.provider, s.snap.sublayer, s.snap.filters, s.snap.nextID
	s.inTxn, s.snap = false, nil
	return nil
}

func (s *fakeSession) AddProvider() error {
	s.bfe.mu.Lock()
	defer s.bfe.mu.Unlock()
	s.logf("add provider")
	s.bfe.provider = true
	return nil
}

func (s *fakeSession) AddSubLayer() error {
	s.bfe.mu.Lock()
	defer s.bfe.mu.Unlock()
	if !s.bfe.provider {
		return errors.New("provider missing")
	}
	s.logf("add sublayer")
	s.bfe.sublayer = true
	return nil
}

func (s *fakeSession) HasProvider() (bool, error) { return s.bfe.provider, nil }
func (s *fakeSession) HasSubLayer() (bool, error) { return s.bfe.sublayer, nil }

func (s *fakeSession) Filters() ([]FilterRecord, error) {
	s.bfe.mu.Lock()
	defer s.bfe.mu.Unlock()
	s.logf("list filters txn=%v", s.inTxn)
	var out []FilterRecord
	for id, f := range s.bfe.filters {
		out = append(out, FilterRecord{ID: id, Key: f.f.Key, Layer: f.f.Layer, Action: f.f.Action, Persistent: f.f.Persistent, Disabled: f.disabled, Path: f.f.Path})
	}
	return out, nil
}

func (s *fakeSession) AddFilter(f *Filter) error {
	s.bfe.mu.Lock()
	defer s.bfe.mu.Unlock()
	if !s.inTxn {
		return errors.New("AddFilter outside a transaction")
	}
	if !s.bfe.sublayer {
		return errors.New("sublayer missing")
	}
	if f.Persistent && s.dynamic {
		return errors.New("persistent filter in a dynamic session")
	}
	s.bfe.adds++
	if s.bfe.failAdd != 0 && s.bfe.adds == s.bfe.failAdd {
		return errors.New("injected add failure")
	}
	if !f.Key.IsZero() {
		for _, e := range s.bfe.filters {
			if e.f.Key == f.Key {
				return nil
			}
		}
	}
	s.bfe.nextID++
	s.bfe.filters[s.bfe.nextID] = fakeFilter{f: *f, session: s.id}
	s.logf("add filter %s w=%d", f.Layer, f.Weight)
	return nil
}

func (s *fakeSession) DeleteFilter(id uint64) error {
	s.bfe.mu.Lock()
	defer s.bfe.mu.Unlock()
	s.logf("delete filter")
	delete(s.bfe.filters, id)
	return nil
}

func (s *fakeSession) DeleteSubLayer() error {
	s.bfe.mu.Lock()
	defer s.bfe.mu.Unlock()
	if len(s.bfe.filters) > 0 {
		return errors.New("FWP_E_IN_USE")
	}
	s.logf("delete sublayer")
	s.bfe.sublayer = false
	return nil
}

func (s *fakeSession) DeleteProvider() error {
	s.bfe.mu.Lock()
	defer s.bfe.mu.Unlock()
	if s.bfe.sublayer {
		return errors.New("FWP_E_IN_USE")
	}
	s.logf("delete provider")
	s.bfe.provider = false
	return nil
}

func (s *fakeSession) Close() error {
	s.bfe.mu.Lock()
	defer s.bfe.mu.Unlock()
	s.closeCalls++
	if s.closed {
		return nil
	}
	if s.closeErr != nil {
		return s.closeErr
	}
	s.closed = true
	s.logf("close dynamic=%v", s.dynamic)
	if s.dynamic {
		for id, f := range s.bfe.filters {
			if f.session == s.id {
				delete(s.bfe.filters, id)
			}
		}
	}
	return nil
}

func (b *fakeBFE) count(pred func(Filter) bool) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, f := range b.filters {
		if pred(f.f) {
			n++
		}
	}
	return n
}

func persistentOnly(f Filter) bool { return f.Persistent }

func TestSubLayerWeightBelowSingTun(t *testing.T) {
	if uint32(SubLayerWeight) >= 0xFFFF {
		t.Fatalf("sublayer weight %#x must be below sing-tun's 0xFFFF", SubLayerWeight)
	}
	if !(WeightLoopbackPermit > WeightTunnelPermit && WeightTunnelPermit > WeightBlock) {
		t.Fatal("weights must order loopback permit > tunnel permit > block")
	}
}

func mustApply(t *testing.T, fw *Firewall, paths []string, mode ApplyMode) ApplyResult {
	t.Helper()
	res, err := fw.Apply(paths, mode)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// existsAll makes every path look present on disk.
func existsAll(string) error { return nil }

func appFilters(b *fakeBackend, path string) int {
	id, _ := (&fakeBackend{appIDErr: map[string]bool{}}).AppID(path)
	return b.bfe.count(func(f Filter) bool { return f.Persistent && string(f.AppID) == string(id) })
}

func TestApplyCreatesProviderSublayerAndFilters(t *testing.T) {
	b := newFake()
	fw := &Firewall{b: b}
	paths := []string{`C:\u\a\Discord\Update.exe`, `C:\u\a\Discord\app-1\Discord.exe`}
	res := mustApply(t, fw, paths, Authoritative)
	if !b.bfe.provider || !b.bfe.sublayer {
		t.Fatal("provider/sublayer missing")
	}
	// 2 apps × 4 layers × (loopback permit + block)
	if n := b.bfe.count(persistentOnly); n != 16 {
		t.Fatalf("persistent filters = %d, want 16", n)
	}
	blocks := b.bfe.count(func(f Filter) bool { return f.Action == ActionBlock && f.Weight == WeightBlock && !f.Loopback })
	loop := b.bfe.count(func(f Filter) bool {
		return f.Action == ActionPermit && f.Weight == WeightLoopbackPermit && f.Loopback && f.LocalInterface == 0
	})
	if blocks != 8 || loop != 8 {
		t.Fatalf("blocks=%d loopback permits=%d", blocks, loop)
	}
	if b.bfe.count(func(f Filter) bool { return f.Path == "" }) != 0 {
		t.Fatal("filter without recorded path")
	}
	for _, l := range Layers {
		if b.bfe.count(func(f Filter) bool { return f.Layer == l }) != 4 {
			t.Fatalf("layer %s not covered", l)
		}
	}
	if len(res.Covered) != 2 || !res.Pruned || len(res.Unresolved) != 0 {
		t.Fatalf("result %+v", res)
	}
	if ok, n, err := fw.Installed(); err != nil || !ok || n != 2 {
		t.Fatalf("Installed = %v %d %v", ok, n, err)
	}
}

// The snapshot is taken inside the write transaction, and an unchanged set
// commits nothing.
func TestApplySnapshotInsideTransactionAndIdempotent(t *testing.T) {
	b := newFake()
	fw := &Firewall{b: b}
	a, c, d := `C:\u\x\Discord\Update.exe`, `C:\u\x\Discord\app-1\Discord.exe`, `C:\u\x\Discord\app-2\Discord.exe`
	mustApply(t, fw, []string{a, c}, Authoritative)
	b.bfe.log = nil
	mustApply(t, fw, []string{c, a, a}, Authoritative)
	log := strings.Join(b.bfe.log, "|")
	if strings.Contains(log, "commit") || strings.Contains(log, "add filter") || !strings.Contains(log, "abort") {
		t.Fatalf("unchanged set wrote something: %s", log)
	}
	if strings.Contains(log, "list filters txn=false") || !strings.Contains(log, "list filters txn=true") {
		t.Fatalf("snapshot taken outside the transaction: %s", log)
	}
	// app-1 replaced by app-2 (app-1 deleted from disk): one transaction
	// adds the new and removes the old.
	b.bfe.log = nil
	mustApply(t, fw, []string{a, d}, Authoritative)
	if got := strings.Count(strings.Join(b.bfe.log, "|"), "begin"); got != 1 {
		t.Fatalf("transactions = %d: %v", got, b.bfe.log)
	}
	if appFilters(b, c) != 0 {
		t.Fatal("stale app still filtered")
	}
	if appFilters(b, d) != 8 {
		t.Fatal("new app not filtered")
	}
}

// Add-only never deletes, and reports the filters already in WFP as
// covered (the baseline of a previous process).
func TestApplyAddOnlyNeverDeletes(t *testing.T) {
	b := newFake()
	a, c := `C:\u\x\Discord\Update.exe`, `C:\u\x\Discord\app-1\Discord.exe`
	mustApply(t, &Firewall{b: b}, []string{a, c}, Authoritative)
	fresh := &Firewall{b: b} // e.g. the next service process
	res := mustApply(t, fresh, nil, AddOnly)
	if n := b.bfe.count(persistentOnly); n != 16 {
		t.Fatalf("add-only removed filters: %d left", n)
	}
	if res.Pruned || len(res.Covered) != 2 {
		t.Fatalf("result %+v", res)
	}
}

// An authoritative apply never removes the block of an executable that
// still exists, even if discovery no longer lists it.
func TestApplyKeepsBlocksOfExistingExecutables(t *testing.T) {
	b := newFake()
	fw := &Firewall{b: b, lstat: existsAll}
	a, c := `C:\u\x\Discord\Update.exe`, `C:\u\x\Discord\app-1\Discord.exe`
	mustApply(t, fw, []string{a, c}, Authoritative)
	res := mustApply(t, fw, []string{a}, Authoritative)
	if appFilters(b, c) != 8 {
		t.Fatal("block of an existing executable removed")
	}
	if !containsAll(res.Covered, []string{a, c}) {
		t.Fatalf("covered %v", res.Covered)
	}
}

// App-ID failures are reported, keep the existing blocks and suppress
// every deletion in that pass.
func TestApplyUnresolvedKeepsBlocksAndReports(t *testing.T) {
	b := newFake()
	exists := map[string]bool{}
	fw := &Firewall{b: b, lstat: func(p string) error {
		if exists[p] {
			return nil
		}
		return fs.ErrNotExist
	}}
	a, c, old := `C:\u\x\Discord\Update.exe`, `C:\u\x\Discord\app-1\Discord.exe`, `C:\u\x\Discord\app-0\Discord.exe`
	mustApply(t, fw, []string{a, c, old}, Authoritative)
	exists[c] = true
	b.appIDErr[c] = true // transient FwpmGetAppIdFromFileName0 failure
	res, err := fw.Apply([]string{a, c}, Authoritative)
	var inc *IncompleteError
	if !errors.As(err, &inc) || !errors.Is(err, ErrIncomplete) || len(inc.Unresolved) != 1 {
		t.Fatalf("err = %v", err)
	}
	if appFilters(b, c) != 8 {
		t.Fatal("blocks of the unresolved executable removed")
	}
	if appFilters(b, old) != 8 {
		t.Fatal("stale filter deleted although the pass was incomplete")
	}
	if res.Pruned || len(res.Unresolved) != 1 {
		t.Fatalf("result %+v", res)
	}
	// Once it resolves again the pass is authoritative.
	b.appIDErr[c] = false
	if _, err := fw.Apply([]string{a, c}, Authoritative); err != nil {
		t.Fatal(err)
	}
	if appFilters(b, old) != 0 {
		t.Fatal("stale filter of a deleted executable kept")
	}
}

// A path that vanished (app ID unavailable and file gone) is not an
// incompleteness: there is nothing to protect.
func TestApplyMissingIsNotIncomplete(t *testing.T) {
	b := newFake()
	fw := &Firewall{b: b}
	a, gone := `C:\u\x\Discord\Update.exe`, `C:\u\x\Discord\app-0\Discord.exe`
	b.appIDErr[gone] = true
	res := mustApply(t, fw, []string{a, gone}, Authoritative)
	if len(res.Covered) != 1 || len(res.Unresolved) != 0 {
		t.Fatalf("result %+v", res)
	}
	permit, err := fw.PermitOnTunnel(42, []string{a, gone})
	if err != nil {
		t.Fatal(err)
	}
	defer permit.Close()
	if !containsAll(permit.Paths(), []string{a, gone}) {
		t.Fatalf("permit paths %v", permit.Paths())
	}
	mustApply(t, fw, nil, Authoritative)
	if n := b.bfe.count(persistentOnly); n != 0 {
		t.Fatalf("persistent filters after empty apply: %d", n)
	}
	if n := b.bfe.count(func(f Filter) bool { return !f.Persistent }); n != 4 {
		t.Fatalf("dynamic permits touched by reconcile: %d left", n)
	}
}

func TestApplyFailureAborts(t *testing.T) {
	b := newFake()
	b.bfe.failAdd = 3
	fw := &Firewall{b: b}
	if _, err := fw.Apply([]string{`C:\u\x\Discord\Update.exe`}, Authoritative); err == nil {
		t.Fatal("expected error")
	}
	if b.bfe.provider || b.bfe.sublayer || len(b.bfe.filters) != 0 {
		t.Fatal("aborted transaction left objects behind")
	}
}

func TestPermitOnTunnel(t *testing.T) {
	b := newFake()
	fw := &Firewall{b: b}
	a := `C:\u\x\Discord\Update.exe`
	mustApply(t, fw, []string{a}, Authoritative)
	if _, err := fw.PermitOnTunnel(0, []string{a}); err == nil {
		t.Fatal("zero LUID accepted")
	}
	c, err := fw.PermitOnTunnel(0x1234, []string{a})
	if err != nil {
		t.Fatal(err)
	}
	dyn := func(f Filter) bool {
		return !f.Persistent && f.Action == ActionPermit && f.Weight == WeightTunnelPermit && f.LocalInterface == 0x1234 && f.Key.IsZero()
	}
	if n := b.bfe.count(dyn); n != 4 {
		t.Fatalf("tunnel permits = %d, want 4", n)
	}
	if !strings.Contains(strings.Join(b.bfe.log, "|"), "open dynamic=true") {
		t.Fatal("permit not in a dynamic session")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if n := b.bfe.count(dyn); n != 0 {
		t.Fatalf("permits survived session close: %d", n)
	}
	if n := b.bfe.count(persistentOnly); n != 8 {
		t.Fatalf("persistent filters changed: %d", n)
	}
}

// An unresolved executable yields a partial permit plus IncompleteError.
func TestPermitOnTunnelPartial(t *testing.T) {
	b := newFake()
	fw := &Firewall{b: b, lstat: existsAll}
	a, c := `C:\u\x\Discord\Update.exe`, `C:\u\x\Discord\app-1\Discord.exe`
	mustApply(t, fw, []string{a}, Authoritative)
	b.appIDErr[c] = true
	p, err := fw.PermitOnTunnel(9, []string{a, c})
	if !errors.Is(err, ErrIncomplete) || p == nil {
		t.Fatalf("permit %v err %v", p, err)
	}
	defer p.Close()
	if containsAll(p.Paths(), []string{c}) || !containsAll(p.Paths(), []string{a}) {
		t.Fatalf("paths %v", p.Paths())
	}
}

func TestRemoveAllOrder(t *testing.T) {
	b := newFake()
	fw := &Firewall{b: b}
	mustApply(t, fw, []string{`C:\u\x\Discord\Update.exe`}, Authoritative)
	b.bfe.log = nil
	if err := fw.RemoveAll(); err != nil {
		t.Fatal(err)
	}
	log := strings.Join(b.bfe.log, "|")
	iBegin, iList, iFilter := strings.Index(log, "begin"), strings.Index(log, "list filters txn=true"), strings.LastIndex(log, "delete filter")
	iSub, iProv, iCommit := strings.Index(log, "delete sublayer"), strings.Index(log, "delete provider"), strings.Index(log, "commit")
	if !(iBegin >= 0 && iBegin < iList && iList < iFilter && iFilter < iSub && iSub < iProv && iProv < iCommit) {
		t.Fatalf("wrong order: %s", log)
	}
	if b.bfe.provider || b.bfe.sublayer || len(b.bfe.filters) != 0 {
		t.Fatal("objects left after RemoveAll")
	}
	if ok, n, err := fw.Installed(); err != nil || ok || n != 0 {
		t.Fatalf("Installed after RemoveAll = %v %d %v", ok, n, err)
	}
	// Idempotent.
	if err := fw.RemoveAll(); err != nil {
		t.Fatal(err)
	}
}

// A fresh Guard (new service process) with an incomplete first discovery
// keeps the filters of the previous process, but cannot activate a tunnel
// permit until discovery and whole-manifest readback complete.
func TestGuardFreshBaselineFromWFP(t *testing.T) {
	b := newFake()
	a, c := `C:\Users\fixture\AppData\Local\Discord\Update.exe`, `C:\Users\fixture\AppData\Local\Discord\app-1\Discord.exe`
	mustApply(t, &Firewall{b: b}, []string{a, c}, Authoritative)
	var found []string
	derr := errors.New("access denied")
	g := NewGuard(&Firewall{b: b}, func() ([]string, error) { return found, derr }, nil, nil)
	if err := g.Reconcile(); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("Reconcile = %v", err)
	}
	if n := b.bfe.count(persistentOnly); n != 16 {
		t.Fatalf("incomplete first reconcile removed filters: %d left", n)
	}
	st := g.Status()
	if !st.Applied || st.Complete || st.Apps != 2 || st.Incomplete == "" {
		t.Fatalf("status %+v", st)
	}
	if h, err := g.TunnelUp(5); err == nil || h != nil {
		t.Fatal("incomplete discovery accepted for tunnel activation")
	}
	if n := b.bfe.count(func(f Filter) bool { return !f.Persistent }); n != 0 {
		t.Fatalf("incomplete discovery created %d dynamic permits", n)
	}
	// A successful retry must read back both executables before activation.
	found, derr = []string{a, c}, nil
	if err := g.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if st := g.Status(); !st.Complete || st.Ready || st.Apps != 2 {
		t.Fatalf("status after discovery retry %+v", st)
	}
	h, err := g.TunnelUp(5)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if n := b.bfe.count(func(f Filter) bool { return !f.Persistent && f.LocalInterface == 5 }); n != 8 {
		t.Fatalf("baseline executables not permitted on the tunnel: %d permits", n)
	}
	if st := g.Status(); !st.PermitComplete || st.PermitApps != 2 {
		t.Fatalf("status %+v", st)
	}
}

func TestFilterKeysDeterministicAndDistinct(t *testing.T) {
	seen := map[Key]bool{}
	for _, id := range [][]byte{[]byte("a"), []byte("b")} {
		for _, l := range Layers {
			for _, kind := range []string{"block", "loopback-permit"} {
				k := filterKey(kind, l, id)
				if k != filterKey(kind, l, id) {
					t.Fatal("key not deterministic")
				}
				if seen[k] || k.IsZero() || k == ProviderKey || k == SubLayerKey {
					t.Fatalf("key collision %s", k)
				}
				seen[k] = true
			}
		}
	}
	if ProviderKey.String() != "4699124e-3633-487f-90c5-77e86738322c" || SubLayerKey.String() != "58005a25-e04f-4367-9093-bbaeca5dd4f3" {
		t.Fatalf("fixed GUIDs changed: %s %s", ProviderKey, SubLayerKey)
	}
}

var _ Permit = (*sessionPermit)(nil)
