package wfp

import (
	"reflect"
	"testing"
)

func TestSnapshotPolicyInventory(t *testing.T) {
	b := newFake()
	fw := &Firewall{b: b}
	installed, paths, err := fw.Snapshot()
	if err != nil || installed || len(paths) != 0 {
		t.Fatalf("absent snapshot: %v %v %v", installed, paths, err)
	}
	if _, err := fw.Apply(nil, AddOnly); err != nil {
		t.Fatal(err)
	}
	installed, paths, err = fw.Snapshot()
	if err != nil || !installed || len(paths) != 0 {
		t.Fatalf("empty installed snapshot: %v %v %v", installed, paths, err)
	}
	want := []string{`C:\Apps\Discord.exe`, `C:\Apps\Update.exe`}
	if _, err := fw.Apply(want, Authoritative); err != nil {
		t.Fatal(err)
	}
	// Snapshot must use installed filters, even when discovery/resolution
	// would no longer be able to access the original executables.
	for _, p := range want {
		b.appIDErr[p] = true
	}
	installed, paths, err = fw.Snapshot()
	if err != nil || !installed || !reflect.DeepEqual(paths, want) {
		t.Fatalf("present snapshot: %v %v %v", installed, paths, err)
	}
	// Disabled filters do not protect an application; dynamic permits are
	// not persistent protection and must not contribute paths either.
	b.bfe.nextID++
	b.bfe.filters[b.bfe.nextID] = fakeFilter{f: Filter{Path: `C:\Apps\Other.exe`, Action: ActionPermit}}
	for id, rec := range b.bfe.filters {
		if rec.f.Path == want[1] {
			rec.disabled = true
			b.bfe.filters[id] = rec
		}
	}
	installed, paths, err = fw.Snapshot()
	if err != nil || !installed || !reflect.DeepEqual(paths, want[:1]) {
		t.Fatalf("disabled snapshot: %v %v %v", installed, paths, err)
	}
	for id, rec := range b.bfe.filters {
		if rec.f.Persistent && !rec.disabled {
			rec.f.Path = ""
			b.bfe.filters[id] = rec
		}
	}
	if _, _, err := fw.Snapshot(); err == nil {
		t.Fatal("accepted unknown block path")
	}
}
