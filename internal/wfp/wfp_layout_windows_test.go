//go:build windows && (amd64 || arm64)

package wfp

import (
	"testing"
	"unsafe"
)

// Sizes and offsets of the WFP structures on 64-bit Windows, as laid out
// by the C headers (fwptypes.h, fwpmtypes.h). A mismatch would make BFE
// read garbage, so these are checked without calling any WFP function.
func TestStructLayout64(t *testing.T) {
	check := func(name string, got, want uintptr) {
		t.Helper()
		if got != want {
			t.Errorf("%s = %d, want %d", name, got, want)
		}
	}
	var f fwpmFilter0
	check("sizeof FWPM_FILTER0", unsafe.Sizeof(f), 200)
	check("FWPM_FILTER0.displayData", unsafe.Offsetof(f.displayData), 16)
	check("FWPM_FILTER0.flags", unsafe.Offsetof(f.flags), 32)
	check("FWPM_FILTER0.providerKey", unsafe.Offsetof(f.providerKey), 40)
	check("FWPM_FILTER0.providerData", unsafe.Offsetof(f.providerData), 48)
	check("FWPM_FILTER0.layerKey", unsafe.Offsetof(f.layerKey), 64)
	check("FWPM_FILTER0.subLayerKey", unsafe.Offsetof(f.subLayerKey), 80)
	check("FWPM_FILTER0.weight", unsafe.Offsetof(f.weight), 96)
	check("FWPM_FILTER0.numFilterConditions", unsafe.Offsetof(f.numFilterConditions), 112)
	check("FWPM_FILTER0.filterCondition", unsafe.Offsetof(f.filterCondition), 120)
	check("FWPM_FILTER0.action", unsafe.Offsetof(f.action), 128)
	check("FWPM_FILTER0.providerContextKey", unsafe.Offsetof(f.providerContextKey), 152)
	check("FWPM_FILTER0.reserved", unsafe.Offsetof(f.reserved), 168)
	check("FWPM_FILTER0.filterID", unsafe.Offsetof(f.filterID), 176)
	check("FWPM_FILTER0.effectiveWeight", unsafe.Offsetof(f.effectiveWeight), 184)

	var c fwpmFilterCondition0
	check("sizeof FWPM_FILTER_CONDITION0", unsafe.Sizeof(c), 40)
	check("FWPM_FILTER_CONDITION0.matchType", unsafe.Offsetof(c.matchType), 16)
	check("FWPM_FILTER_CONDITION0.conditionValue", unsafe.Offsetof(c.conditionValue), 24)

	var v fwpValue0
	check("sizeof FWP_VALUE0", unsafe.Sizeof(v), 16)
	check("FWP_VALUE0.value", unsafe.Offsetof(v.value), 8)

	var bl fwpByteBlob
	check("sizeof FWP_BYTE_BLOB", unsafe.Sizeof(bl), 16)
	check("FWP_BYTE_BLOB.data", unsafe.Offsetof(bl.data), 8)

	var a fwpmAction0
	check("sizeof FWPM_ACTION0", unsafe.Sizeof(a), 20)

	var d fwpmDisplayData0
	check("sizeof FWPM_DISPLAY_DATA0", unsafe.Sizeof(d), 16)

	var s fwpmSession0
	check("sizeof FWPM_SESSION0", unsafe.Sizeof(s), 72)
	check("FWPM_SESSION0.flags", unsafe.Offsetof(s.flags), 32)
	check("FWPM_SESSION0.txnWaitTimeoutInMSec", unsafe.Offsetof(s.txnWaitTimeoutInMSec), 36)
	check("FWPM_SESSION0.processId", unsafe.Offsetof(s.processID), 40)
	check("FWPM_SESSION0.sid", unsafe.Offsetof(s.sid), 48)
	check("FWPM_SESSION0.username", unsafe.Offsetof(s.username), 56)
	check("FWPM_SESSION0.kernelMode", unsafe.Offsetof(s.kernelMode), 64)

	var sl fwpmSublayer0
	check("sizeof FWPM_SUBLAYER0", unsafe.Sizeof(sl), 72)
	check("FWPM_SUBLAYER0.flags", unsafe.Offsetof(sl.flags), 32)
	check("FWPM_SUBLAYER0.providerKey", unsafe.Offsetof(sl.providerKey), 40)
	check("FWPM_SUBLAYER0.providerData", unsafe.Offsetof(sl.providerData), 48)
	check("FWPM_SUBLAYER0.weight", unsafe.Offsetof(sl.weight), 64)

	var p fwpmProvider0
	check("sizeof FWPM_PROVIDER0", unsafe.Sizeof(p), 64)
	check("FWPM_PROVIDER0.flags", unsafe.Offsetof(p.flags), 32)
	check("FWPM_PROVIDER0.providerData", unsafe.Offsetof(p.providerData), 40)
	check("FWPM_PROVIDER0.serviceName", unsafe.Offsetof(p.serviceName), 56)

	var e fwpmFilterEnumTemplate0
	check("sizeof FWPM_FILTER_ENUM_TEMPLATE0", unsafe.Sizeof(e), 72)
	check("FWPM_FILTER_ENUM_TEMPLATE0.layerKey", unsafe.Offsetof(e.layerKey), 8)
	check("FWPM_FILTER_ENUM_TEMPLATE0.enumType", unsafe.Offsetof(e.enumType), 24)
	check("FWPM_FILTER_ENUM_TEMPLATE0.flags", unsafe.Offsetof(e.flags), 28)
	check("FWPM_FILTER_ENUM_TEMPLATE0.providerContextTemplate", unsafe.Offsetof(e.providerContextTemplate), 32)
	check("FWPM_FILTER_ENUM_TEMPLATE0.numFilterConditions", unsafe.Offsetof(e.numFilterConditions), 40)
	check("FWPM_FILTER_ENUM_TEMPLATE0.filterCondition", unsafe.Offsetof(e.filterCondition), 48)
	check("FWPM_FILTER_ENUM_TEMPLATE0.actionMask", unsafe.Offsetof(e.actionMask), 56)
	check("FWPM_FILTER_ENUM_TEMPLATE0.calloutKey", unsafe.Offsetof(e.calloutKey), 64)

	if unsafe.Sizeof(Key{}) != 16 {
		t.Error("Key must be 16 bytes")
	}
}

func TestLayerGUIDRoundTrip(t *testing.T) {
	for _, l := range Layers {
		g, ok := layerGUID(l)
		if !ok {
			t.Fatalf("no GUID for %s", l)
		}
		if back, ok := layerFromGUID(g); !ok || back != l {
			t.Fatalf("round trip %s -> %v", l, back)
		}
	}
	if _, ok := layerGUID(Layer(99)); ok {
		t.Fatal("unknown layer mapped")
	}
}
