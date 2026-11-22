//go:build windows && (amd64 || arm64)

package wfp

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// These tests exercise the structure builders and the enumeration parser
// without calling any WFP function.

func TestBuildFilterMarshalling(t *testing.T) {
	var pin runtime.Pinner
	defer pin.Unpin()
	appID := []byte(`\device\harddiskvolume3\users\x\appdata\local\discord\update.exe`)
	f := &Filter{
		Key: filterKey("block", LayerConnectV6, appID), Name: "n", Layer: LayerConnectV6,
		Action: ActionPermit, Weight: WeightTunnelPermit, Persistent: true,
		AppID: appID, Path: `C:\Users\x\AppData\Local\Discord\Update.exe`,
		Loopback: true, LocalInterface: 0x1122334455667788,
	}
	flt, err := buildFilter(&pin, f)
	if err != nil {
		t.Fatal(err)
	}
	// The source slice may change after building: the native copy must not.
	appID[0] = 'X'
	if flt.filterKey != windows.GUID(f.Key) || flt.layerKey != guidLayerALEAuthConnectV6 || flt.subLayerKey != subLayerKeyWin {
		t.Fatal("keys")
	}
	if flt.providerKey == nil || *flt.providerKey != providerKeyWin {
		t.Fatal("provider key")
	}
	if flt.flags != fwpmFilterFlagPersistent || flt.action.typ != fwpActionPermit {
		t.Fatalf("flags %#x action %#x", flt.flags, flt.action.typ)
	}
	if flt.weight.typ != fwpUint8 || flt.weight.value != uintptr(WeightTunnelPermit) {
		t.Fatalf("weight %+v", flt.weight)
	}
	if flt.numFilterConditions != 3 {
		t.Fatalf("conditions %d", flt.numFilterConditions)
	}
	conds := unsafe.Slice(flt.filterCondition, flt.numFilterConditions)
	if conds[0].fieldKey != guidConditionALEAppID || conds[0].matchType != fwpMatchEqual || conds[0].conditionValue.typ != fwpByteBlobType {
		t.Fatalf("app ID condition %+v", conds[0])
	}
	blob := (*fwpByteBlob)(unionPtr(&conds[0].conditionValue))
	if got := string(unsafe.Slice(blob.data, blob.size)); got[0] != '\\' || len(got) != len(appID) {
		t.Fatalf("app ID blob %q", got)
	}
	if conds[1].fieldKey != guidConditionFlags || conds[1].matchType != fwpMatchFlagsAllSet ||
		conds[1].conditionValue.typ != fwpUint32 || conds[1].conditionValue.value != fwpConditionFlagIsLoopback {
		t.Fatalf("loopback condition %+v", conds[1])
	}
	if conds[2].fieldKey != guidConditionIPLocalInterface || conds[2].conditionValue.typ != fwpUint64 ||
		*(*uint64)(unionPtr(&conds[2].conditionValue)) != 0x1122334455667788 {
		t.Fatalf("interface condition %+v", conds[2])
	}
	if windows.UTF16PtrToString(flt.displayData.name) != "n" {
		t.Fatal("display name")
	}
	// Enumeration reads the recorded path back.
	rec, ok := parseFilter(flt, LayerConnectV4)
	if !ok || rec.Path != f.Path || rec.Layer != LayerConnectV6 || rec.Action != ActionPermit || !rec.Persistent || rec.Key != f.Key {
		t.Fatalf("parsed %+v", rec)
	}
	runtime.GC() // pinned objects must survive a collection
	if *(*uint64)(unionPtr(&conds[2].conditionValue)) != 0x1122334455667788 {
		t.Fatal("pinned value changed")
	}
}

// unionPtr reads the FWP_VALUE0 union as the pointer it holds.
func unionPtr(v *fwpValue0) unsafe.Pointer { return *(*unsafe.Pointer)(unsafe.Pointer(&v.value)) }

func TestBuildFilterBlockMinimal(t *testing.T) {
	var pin runtime.Pinner
	defer pin.Unpin()
	flt, err := buildFilter(&pin, &Filter{Layer: LayerRecvAcceptV4, Action: ActionBlock, Weight: WeightBlock, AppID: []byte("a")})
	if err != nil {
		t.Fatal(err)
	}
	if flt.numFilterConditions != 1 || flt.flags != 0 || flt.action.typ != fwpActionBlock || flt.providerData.size != 0 {
		t.Fatalf("filter %+v", flt)
	}
	if _, err := buildFilter(&pin, &Filter{Layer: Layer(9), Action: ActionBlock, AppID: []byte("a")}); err == nil {
		t.Fatal("unknown layer accepted")
	}
	if _, err := buildFilter(&pin, &Filter{Layer: LayerConnectV4, Action: ActionBlock}); err == nil {
		t.Fatal("filter without app ID accepted")
	}
	if _, err := buildFilter(&pin, &Filter{Layer: LayerConnectV4, Action: 0, AppID: []byte("a")}); err == nil {
		t.Fatal("unknown action accepted")
	}
}

func TestParseFilterForeignProvider(t *testing.T) {
	other := windows.GUID{Data1: 1}
	if _, ok := parseFilter(&fwpmFilter0{providerKey: &other}, LayerConnectV4); ok {
		t.Fatal("foreign filter accepted")
	}
	if _, ok := parseFilter(&fwpmFilter0{}, LayerConnectV4); ok {
		t.Fatal("filter without provider accepted")
	}
	if _, ok := parseFilter(nil, LayerConnectV4); ok {
		t.Fatal("nil accepted")
	}
}

// The disabled flag survives parsing; persistent and disabled are
// independent bits.
func TestParseFilterDisabledFlag(t *testing.T) {
	pk := providerKeyWin
	for _, tc := range []struct {
		flags                uint32
		persistent, disabled bool
	}{
		{0, false, false},
		{fwpmFilterFlagPersistent, true, false},
		{fwpmFilterFlagDisabled, false, true},
		{fwpmFilterFlagPersistent | fwpmFilterFlagDisabled, true, true},
	} {
		rec, ok := parseFilter(&fwpmFilter0{providerKey: &pk, flags: tc.flags}, LayerConnectV4)
		if !ok || rec.Persistent != tc.persistent || rec.Disabled != tc.disabled {
			t.Fatalf("flags %#x: %+v", tc.flags, rec)
		}
	}
}

func TestBuildOtherStructures(t *testing.T) {
	var pin runtime.Pinner
	defer pin.Unpin()
	tpl := buildEnumTemplate(&pin, guidLayerALEAuthConnectV4, true)
	if tpl.flags != fwpFilterEnumFlagIncludeDisabled || tpl.providerKey == nil || *tpl.providerKey != providerKeyWin ||
		tpl.enumType != fwpFilterEnumOverlapping || tpl.actionMask != 0xFFFFFFFF {
		t.Fatalf("template %+v", tpl)
	}
	if buildEnumTemplate(&pin, guidLayerALEAuthConnectV4, false).flags != 0 {
		t.Fatal("fallback template has flags")
	}
	s := buildSession(&pin, true)
	if s.flags != fwpmSessionFlagDynamic || s.txnWaitTimeoutInMSec != fwpmTxnWaitMS || windows.UTF16PtrToString(s.displayData.name) != ProviderName {
		t.Fatalf("session %+v", s)
	}
	if buildSession(&pin, false).flags != 0 {
		t.Fatal("persistent session flagged dynamic")
	}
	p := buildProvider(&pin)
	if p.providerKey != providerKeyWin || p.flags != fwpmProviderFlagPersistent || p.serviceName != nil {
		t.Fatalf("provider %+v", p)
	}
	sl := buildSubLayer(&pin)
	if sl.subLayerKey != subLayerKeyWin || sl.weight != SubLayerWeight || sl.providerKey == nil || *sl.providerKey != providerKeyWin || sl.flags != fwpmSublayerFlagPersistent {
		t.Fatalf("sublayer %+v", sl)
	}
}

// The real change notification fires for a new app-* directory and a new
// executable (temporary directory, no privileges needed).
func TestPlatformWatchSeesNewVersion(t *testing.T) {
	t0 := t
	dir := t.TempDir()
	events := make(chan struct{}, 64)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- platformWatch(ctx, []WatchTarget{{Path: dir, Subtree: true}}, func() {
			select {
			case events <- struct{}{}:
			default:
			}
		}, func(t WatchTarget, err error) { t0.Errorf("watch %s failed: %v", t.Path, err) })
	}()
	time.Sleep(100 * time.Millisecond) // let the watch arm
	if err := os.MkdirAll(filepath.Join(dir, "app-1.0.9999"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app-1.0.9999", "Discord.exe"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	select {
	case <-events:
	case <-time.After(time.Second):
		t.Fatal("no change notification within 1s")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watch did not stop")
	}
}

// A target that cannot be opened is reported at once through fail, while
// the other target is still watched.
func TestPlatformWatchReportsOpenFailure(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "does-not-exist")
	failed := make(chan WatchTarget, 4)
	events := make(chan struct{}, 64)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- platformWatch(ctx, []WatchTarget{{Path: missing}, {Path: dir}}, func() {
			select {
			case events <- struct{}{}:
			default:
			}
		}, func(t WatchTarget, err error) { failed <- t })
	}()
	select {
	case ft := <-failed:
		if ft.Path != missing {
			t.Fatalf("failed target %q", ft.Path)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("open failure not reported promptly")
	}
	time.Sleep(100 * time.Millisecond)
	if err := os.WriteFile(filepath.Join(dir, "x"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	select {
	case <-events:
	case <-time.After(time.Second):
		t.Fatal("remaining target not watched")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watch did not stop")
	}
}
