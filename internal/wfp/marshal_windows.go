//go:build windows && (amd64 || arm64)

package wfp

import (
	"errors"
	"fmt"
	"runtime"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The builders in this file turn backend-neutral descriptions into the
// native WFP structures. Every Go object that BFE reads through a pointer
// (including pointers stored as uintptr in FWP_VALUE0 unions) is pinned
// with pin, so it can neither move nor be collected until the caller's
// pin.Unpin() after the call. They make no system call and are unit
// tested (marshal_windows_test.go).

// pinUTF16 converts s and pins the result; "" or a string with a NUL
// yields nil.
func pinUTF16(pin *runtime.Pinner, s string) *uint16 {
	if s == "" {
		return nil
	}
	p, err := windows.UTF16PtrFromString(s)
	if err != nil {
		return nil
	}
	pin.Pin(p)
	return p
}

// pinGUID returns a pinned heap copy of g.
func pinGUID(pin *runtime.Pinner, g windows.GUID) *windows.GUID {
	p := new(windows.GUID)
	*p = g
	pin.Pin(p)
	return p
}

// pinBlob returns a pinned FWP_BYTE_BLOB holding a pinned copy of data.
func pinBlob(pin *runtime.Pinner, data []byte) *fwpByteBlob {
	b := new(fwpByteBlob)
	if len(data) > 0 {
		cp := make([]byte, len(data))
		copy(cp, data)
		pin.Pin(&cp[0])
		b.size, b.data = uint32(len(cp)), &cp[0]
	}
	pin.Pin(b)
	return b
}

func buildSession(pin *runtime.Pinner, dynamic bool) *fwpmSession0 {
	s := &fwpmSession0{txnWaitTimeoutInMSec: fwpmTxnWaitMS}
	s.displayData.name = pinUTF16(pin, ProviderName)
	if dynamic {
		s.flags = fwpmSessionFlagDynamic
	}
	pin.Pin(s)
	return s
}

func buildProvider(pin *runtime.Pinner) *fwpmProvider0 {
	p := &fwpmProvider0{providerKey: providerKeyWin, flags: fwpmProviderFlagPersistent}
	p.displayData.name = pinUTF16(pin, ProviderName)
	p.displayData.description = pinUTF16(pin, "Keeps Discord fail-closed outside the AURA Split TR tunnel")
	// serviceName stays nil on purpose (see the package comment).
	pin.Pin(p)
	return p
}

func buildSubLayer(pin *runtime.Pinner) *fwpmSublayer0 {
	sl := &fwpmSublayer0{
		subLayerKey: subLayerKeyWin,
		flags:       fwpmSublayerFlagPersistent,
		providerKey: pinGUID(pin, providerKeyWin),
		weight:      SubLayerWeight,
	}
	sl.displayData.name = pinUTF16(pin, SubLayerName)
	pin.Pin(sl)
	return sl
}

// buildEnumTemplate selects every filter of our provider on layer lg.
func buildEnumTemplate(pin *runtime.Pinner, lg windows.GUID, includeDisabled bool) *fwpmFilterEnumTemplate0 {
	t := &fwpmFilterEnumTemplate0{
		providerKey: pinGUID(pin, providerKeyWin),
		layerKey:    lg,
		enumType:    fwpFilterEnumOverlapping,
		actionMask:  0xFFFFFFFF,
	}
	if includeDisabled {
		t.flags = fwpFilterEnumFlagIncludeDisabled
	}
	pin.Pin(t)
	return t
}

// buildFilter returns the native FWPM_FILTER0 for f.
func buildFilter(pin *runtime.Pinner, f *Filter) (*fwpmFilter0, error) {
	lg, ok := layerGUID(f.Layer)
	if !ok {
		return nil, fmt.Errorf("unknown layer %d", f.Layer)
	}
	if len(f.AppID) == 0 {
		return nil, errors.New("filter without app ID")
	}
	if len(f.Path) > maxProviderData {
		return nil, errors.New("executable path too long")
	}
	conds := make([]fwpmFilterCondition0, 0, 3)
	appBlob := pinBlob(pin, f.AppID)
	conds = append(conds, fwpmFilterCondition0{
		fieldKey: guidConditionALEAppID, matchType: fwpMatchEqual,
		conditionValue: fwpValue0{typ: fwpByteBlobType, value: uintptr(unsafe.Pointer(appBlob))},
	})
	if f.Loopback {
		conds = append(conds, fwpmFilterCondition0{
			fieldKey: guidConditionFlags, matchType: fwpMatchFlagsAllSet,
			conditionValue: fwpValue0{typ: fwpUint32, value: fwpConditionFlagIsLoopback},
		})
	}
	if f.LocalInterface != 0 {
		luid := new(uint64)
		*luid = f.LocalInterface
		pin.Pin(luid)
		conds = append(conds, fwpmFilterCondition0{
			fieldKey: guidConditionIPLocalInterface, matchType: fwpMatchEqual,
			conditionValue: fwpValue0{typ: fwpUint64, value: uintptr(unsafe.Pointer(luid))},
		})
	}
	pin.Pin(&conds[0])
	flt := &fwpmFilter0{
		filterKey:           windows.GUID(f.Key),
		providerKey:         pinGUID(pin, providerKeyWin),
		layerKey:            lg,
		subLayerKey:         subLayerKeyWin,
		weight:              fwpValue0{typ: fwpUint8, value: uintptr(f.Weight)},
		numFilterConditions: uint32(len(conds)),
		filterCondition:     &conds[0],
	}
	flt.displayData.name = pinUTF16(pin, f.Name)
	if f.Path != "" {
		// The executable path is kept with the filter, so a later process
		// can tell whether a block still protects an existing file.
		flt.providerData = *pinBlob(pin, []byte(f.Path))
	}
	if f.Persistent {
		flt.flags = fwpmFilterFlagPersistent
	}
	switch f.Action {
	case ActionBlock:
		flt.action.typ = fwpActionBlock
	case ActionPermit:
		flt.action.typ = fwpActionPermit
	default:
		return nil, fmt.Errorf("unknown action %d", f.Action)
	}
	pin.Pin(flt)
	return flt, nil
}

// parseFilter converts one enumerated native filter into a FilterRecord.
// ok is false for filters of another provider.
func parseFilter(f *fwpmFilter0, fallback Layer) (FilterRecord, bool) {
	if f == nil || f.providerKey == nil || *f.providerKey != providerKeyWin {
		return FilterRecord{}, false
	}
	rec := FilterRecord{
		ID: f.filterID, Key: Key(f.filterKey), Layer: fallback,
		Persistent: f.flags&fwpmFilterFlagPersistent != 0,
		Disabled:   f.flags&fwpmFilterFlagDisabled != 0,
	}
	if fl, ok := layerFromGUID(f.layerKey); ok {
		rec.Layer = fl
	}
	switch f.action.typ {
	case fwpActionBlock:
		rec.Action = ActionBlock
	case fwpActionPermit:
		rec.Action = ActionPermit
	}
	if n := f.providerData.size; n > 0 && n <= maxProviderData && f.providerData.data != nil {
		if b := unsafe.Slice(f.providerData.data, n); utf8.Valid(b) {
			rec.Path = string(b)
		}
	}
	return rec, true
}
