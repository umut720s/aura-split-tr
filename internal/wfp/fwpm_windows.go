//go:build windows && (amd64 || arm64)

/* Structure layouts and constants in this file are adapted from
 * wireguard-windows, tunnel/firewall (types_windows.go,
 * types_windows_64.go, syscall_windows.go):
 *
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 *
 * Changes: renamed, reduced to what this package uses, BOOL as int32,
 * FWP_VALUE0 type as uint32, added FWPM_FILTER_ENUM_TEMPLATE0, the
 * delete/enumerate/get bindings and lazy loading via x/sys/windows.
 */

package wfp

import (
	"errors"
	"fmt"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// fwptypes.h / fwpmtypes.h constants.
const (
	fwpActionFlagTerminating = 0x00001000
	fwpActionBlock           = 0x00000001 | fwpActionFlagTerminating
	fwpActionPermit          = 0x00000002 | fwpActionFlagTerminating

	fwpMatchEqual       = 0
	fwpMatchFlagsAllSet = 6

	fwpUint8        = 1
	fwpUint32       = 3
	fwpUint64       = 4
	fwpByteBlobType = 12

	fwpConditionFlagIsLoopback = 0x00000001

	fwpmFilterFlagPersistent = 0x00000001
	// FWPM_FILTER_FLAG_DISABLED (fwpmtypes.h, Windows 7+): BFE reports the
	// filter as disabled; it enforces nothing.
	fwpmFilterFlagDisabled     = 0x00000020
	fwpmSublayerFlagPersistent = 0x00000001
	fwpmProviderFlagPersistent = 0x00000001
	fwpmSessionFlagDynamic     = 0x00000001

	fwpFilterEnumOverlapping = 1
	// FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED (fwptypes.h, Windows 7+):
	// cleanup must see every filter of our provider, also disabled ones.
	fwpFilterEnumFlagIncludeDisabled = 0x00000010

	rpcCAuthnWinNT = 10

	// fwpmTxnWaitMS bounds how long a session waits for another
	// session's transaction.
	fwpmTxnWaitMS = 10000

	// Error codes (winerror.h, FWP_E_*).
	fwpEFilterNotFound   = 0x80320003
	fwpEProviderNotFound = 0x80320005
	fwpESublayerNotFound = 0x80320007
	fwpENotFound         = 0x80320008
	fwpEAlreadyExists    = 0x80320009
	fwpEInvalidFlags     = 0x8032001E
	fwpEInvalidParameter = 0x80320035

	// maxProviderData bounds the provider data (a UTF-8 path) we store with
	// and read back from a filter.
	maxProviderData = 64 << 10
)

// GUIDs from fwpmu.h.
var (
	guidConditionALEAppID         = windows.GUID{Data1: 0xd78e1e87, Data2: 0x8644, Data3: 0x4ea5, Data4: [8]byte{0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71}}
	guidConditionFlags            = windows.GUID{Data1: 0x632ce23b, Data2: 0x5167, Data3: 0x435c, Data4: [8]byte{0x86, 0xd7, 0xe9, 0x03, 0x68, 0x4a, 0xa8, 0x0c}}
	guidConditionIPLocalInterface = windows.GUID{Data1: 0x4cd62a49, Data2: 0x59c3, Data3: 0x4969, Data4: [8]byte{0xb7, 0xf3, 0xbd, 0xa5, 0xd3, 0x28, 0x90, 0xa4}}
	guidLayerALEAuthConnectV4     = windows.GUID{Data1: 0xc38d57d1, Data2: 0x05a7, Data3: 0x4c33, Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}}
	guidLayerALEAuthConnectV6     = windows.GUID{Data1: 0x4a72393b, Data2: 0x319f, Data3: 0x44bc, Data4: [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}}
	guidLayerALEAuthRecvAcceptV4  = windows.GUID{Data1: 0xe1cd9fe7, Data2: 0xf4b5, Data3: 0x4273, Data4: [8]byte{0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50}}
	guidLayerALEAuthRecvAcceptV6  = windows.GUID{Data1: 0xa3b42c97, Data2: 0x9f04, Data3: 0x4672, Data4: [8]byte{0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f}}
)

func layerGUID(l Layer) (windows.GUID, bool) {
	switch l {
	case LayerConnectV4:
		return guidLayerALEAuthConnectV4, true
	case LayerConnectV6:
		return guidLayerALEAuthConnectV6, true
	case LayerRecvAcceptV4:
		return guidLayerALEAuthRecvAcceptV4, true
	case LayerRecvAcceptV6:
		return guidLayerALEAuthRecvAcceptV6, true
	}
	return windows.GUID{}, false
}

func layerFromGUID(g windows.GUID) (Layer, bool) {
	for _, l := range Layers {
		if lg, _ := layerGUID(l); lg == g {
			return l, true
		}
	}
	return 0, false
}

// FWP_BYTE_BLOB (16 bytes on 64-bit).
type fwpByteBlob struct {
	size uint32
	data *uint8
}

// FWP_VALUE0 / FWP_CONDITION_VALUE0 (16 bytes). value is the union; for
// FWP_UINT8/FWP_UINT32 it holds the number, otherwise a pointer.
type fwpValue0 struct {
	typ   uint32
	value uintptr
}

// FWPM_DISPLAY_DATA0 (16 bytes).
type fwpmDisplayData0 struct {
	name        *uint16
	description *uint16
}

// FWPM_FILTER_CONDITION0 (40 bytes).
type fwpmFilterCondition0 struct {
	fieldKey       windows.GUID
	matchType      uint32
	conditionValue fwpValue0
}

// FWPM_ACTION0 (20 bytes).
type fwpmAction0 struct {
	typ        uint32
	filterType windows.GUID
}

// FWPM_FILTER0 (200 bytes).
type fwpmFilter0 struct {
	filterKey           windows.GUID
	displayData         fwpmDisplayData0
	flags               uint32
	providerKey         *windows.GUID
	providerData        fwpByteBlob
	layerKey            windows.GUID
	subLayerKey         windows.GUID
	weight              fwpValue0
	numFilterConditions uint32
	filterCondition     *fwpmFilterCondition0
	action              fwpmAction0
	_                   [4]byte      // union { UINT64 rawContext; GUID providerContextKey; } is 8-aligned
	providerContextKey  windows.GUID // union with rawContext
	reserved            *windows.GUID
	filterID            uint64
	effectiveWeight     fwpValue0
}

// FWPM_SESSION0 (72 bytes).
type fwpmSession0 struct {
	sessionKey           windows.GUID
	displayData          fwpmDisplayData0
	flags                uint32
	txnWaitTimeoutInMSec uint32
	processID            uint32
	sid                  *windows.SID
	username             *uint16
	kernelMode           int32 // BOOL
}

// FWPM_SUBLAYER0 (72 bytes).
type fwpmSublayer0 struct {
	subLayerKey  windows.GUID
	displayData  fwpmDisplayData0
	flags        uint32
	providerKey  *windows.GUID
	providerData fwpByteBlob
	weight       uint16
}

// FWPM_PROVIDER0 (64 bytes).
type fwpmProvider0 struct {
	providerKey  windows.GUID
	displayData  fwpmDisplayData0
	flags        uint32
	providerData fwpByteBlob
	serviceName  *uint16
}

// FWPM_FILTER_ENUM_TEMPLATE0 (72 bytes).
type fwpmFilterEnumTemplate0 struct {
	providerKey             *windows.GUID
	layerKey                windows.GUID
	enumType                uint32
	flags                   uint32
	providerContextTemplate uintptr
	numFilterConditions     uint32
	filterCondition         *fwpmFilterCondition0
	actionMask              uint32
	calloutKey              *windows.GUID
}

var (
	modfwpuclnt = windows.NewLazySystemDLL("fwpuclnt.dll")

	procFwpmEngineOpen0              = modfwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0             = modfwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmTransactionBegin0        = modfwpuclnt.NewProc("FwpmTransactionBegin0")
	procFwpmTransactionCommit0       = modfwpuclnt.NewProc("FwpmTransactionCommit0")
	procFwpmTransactionAbort0        = modfwpuclnt.NewProc("FwpmTransactionAbort0")
	procFwpmProviderAdd0             = modfwpuclnt.NewProc("FwpmProviderAdd0")
	procFwpmProviderDeleteByKey0     = modfwpuclnt.NewProc("FwpmProviderDeleteByKey0")
	procFwpmProviderGetByKey0        = modfwpuclnt.NewProc("FwpmProviderGetByKey0")
	procFwpmSubLayerAdd0             = modfwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFwpmSubLayerDeleteByKey0     = modfwpuclnt.NewProc("FwpmSubLayerDeleteByKey0")
	procFwpmSubLayerGetByKey0        = modfwpuclnt.NewProc("FwpmSubLayerGetByKey0")
	procFwpmFilterAdd0               = modfwpuclnt.NewProc("FwpmFilterAdd0")
	procFwpmFilterDeleteById0        = modfwpuclnt.NewProc("FwpmFilterDeleteById0")
	procFwpmFilterCreateEnumHandle0  = modfwpuclnt.NewProc("FwpmFilterCreateEnumHandle0")
	procFwpmFilterEnum0              = modfwpuclnt.NewProc("FwpmFilterEnum0")
	procFwpmFilterDestroyEnumHandle0 = modfwpuclnt.NewProc("FwpmFilterDestroyEnumHandle0")
	procFwpmGetAppIdFromFileName0    = modfwpuclnt.NewProc("FwpmGetAppIdFromFileName0")
	procFwpmFreeMemory0              = modfwpuclnt.NewProc("FwpmFreeMemory0")
)

var (
	procsOnce sync.Once
	procsErr  error
)

// loadProcs resolves every WFP entry point once. LazyProc.Call panics on
// a missing procedure; after loadProcs succeeded it never has to look one
// up again.
func loadProcs() error {
	procsOnce.Do(func() {
		for _, p := range []*windows.LazyProc{
			procFwpmEngineOpen0, procFwpmEngineClose0, procFwpmTransactionBegin0,
			procFwpmTransactionCommit0, procFwpmTransactionAbort0, procFwpmProviderAdd0,
			procFwpmProviderDeleteByKey0, procFwpmProviderGetByKey0, procFwpmSubLayerAdd0,
			procFwpmSubLayerDeleteByKey0, procFwpmSubLayerGetByKey0, procFwpmFilterAdd0,
			procFwpmFilterDeleteById0, procFwpmFilterCreateEnumHandle0, procFwpmFilterEnum0,
			procFwpmFilterDestroyEnumHandle0, procFwpmGetAppIdFromFileName0, procFwpmFreeMemory0,
		} {
			if err := p.Find(); err != nil {
				procsErr = fmt.Errorf("wfp: %w", err)
				return
			}
		}
	})
	return procsErr
}

func errnoResult(r uintptr) error {
	if r != 0 {
		return syscall.Errno(r)
	}
	return nil
}

// Typed bindings. Every pointer stays typed until it is converted to
// uintptr directly inside the LazyProc.Call expression: Call carries
// //go:uintptrescapes, so the compiler keeps each referenced object alive
// and on the heap (never on a movable stack) for the duration of the call.
// Do not move these conversions into a helper that takes uintptr
// arguments; that loses the guarantee.
//
// Go memory reached only through structure fields (FWP_VALUE0 unions,
// blobs, condition arrays, display strings) is additionally pinned with a
// runtime.Pinner by the callers (see marshal_windows.go).

func fwpmEngineOpen0(authnService uint32, session *fwpmSession0, engine *uintptr) error {
	if err := loadProcs(); err != nil {
		return err
	}
	r, _, _ := procFwpmEngineOpen0.Call(0, uintptr(authnService), 0, uintptr(unsafe.Pointer(session)), uintptr(unsafe.Pointer(engine)))
	return errnoResult(r)
}

func fwpmEngineClose0(engine uintptr) error {
	if err := loadProcs(); err != nil {
		return err
	}
	r, _, _ := procFwpmEngineClose0.Call(engine)
	return errnoResult(r)
}

func fwpmTransactionBegin0(engine uintptr, flags uint32) error {
	if err := loadProcs(); err != nil {
		return err
	}
	r, _, _ := procFwpmTransactionBegin0.Call(engine, uintptr(flags))
	return errnoResult(r)
}

func fwpmTransactionCommit0(engine uintptr) error {
	if err := loadProcs(); err != nil {
		return err
	}
	r, _, _ := procFwpmTransactionCommit0.Call(engine)
	return errnoResult(r)
}

func fwpmTransactionAbort0(engine uintptr) error {
	if err := loadProcs(); err != nil {
		return err
	}
	r, _, _ := procFwpmTransactionAbort0.Call(engine)
	return errnoResult(r)
}

func fwpmProviderAdd0(engine uintptr, provider *fwpmProvider0) error {
	if err := loadProcs(); err != nil {
		return err
	}
	r, _, _ := procFwpmProviderAdd0.Call(engine, uintptr(unsafe.Pointer(provider)), 0)
	return errnoResult(r)
}

func fwpmProviderDeleteByKey0(engine uintptr, key *windows.GUID) error {
	if err := loadProcs(); err != nil {
		return err
	}
	r, _, _ := procFwpmProviderDeleteByKey0.Call(engine, uintptr(unsafe.Pointer(key)))
	return errnoResult(r)
}

func fwpmProviderGetByKey0(engine uintptr, key *windows.GUID, out **fwpmProvider0) error {
	if err := loadProcs(); err != nil {
		return err
	}
	r, _, _ := procFwpmProviderGetByKey0.Call(engine, uintptr(unsafe.Pointer(key)), uintptr(unsafe.Pointer(out)))
	return errnoResult(r)
}

func fwpmSubLayerAdd0(engine uintptr, sublayer *fwpmSublayer0) error {
	if err := loadProcs(); err != nil {
		return err
	}
	r, _, _ := procFwpmSubLayerAdd0.Call(engine, uintptr(unsafe.Pointer(sublayer)), 0)
	return errnoResult(r)
}

func fwpmSubLayerDeleteByKey0(engine uintptr, key *windows.GUID) error {
	if err := loadProcs(); err != nil {
		return err
	}
	r, _, _ := procFwpmSubLayerDeleteByKey0.Call(engine, uintptr(unsafe.Pointer(key)))
	return errnoResult(r)
}

func fwpmSubLayerGetByKey0(engine uintptr, key *windows.GUID, out **fwpmSublayer0) error {
	if err := loadProcs(); err != nil {
		return err
	}
	r, _, _ := procFwpmSubLayerGetByKey0.Call(engine, uintptr(unsafe.Pointer(key)), uintptr(unsafe.Pointer(out)))
	return errnoResult(r)
}

func fwpmFilterAdd0(engine uintptr, filter *fwpmFilter0, id *uint64) error {
	if err := loadProcs(); err != nil {
		return err
	}
	r, _, _ := procFwpmFilterAdd0.Call(engine, uintptr(unsafe.Pointer(filter)), 0, uintptr(unsafe.Pointer(id)))
	return errnoResult(r)
}

func fwpmFilterDeleteByID0(engine uintptr, id uint64) error {
	if err := loadProcs(); err != nil {
		return err
	}
	r, _, _ := procFwpmFilterDeleteById0.Call(engine, uintptr(id))
	return errnoResult(r)
}

func fwpmFilterCreateEnumHandle0(engine uintptr, template *fwpmFilterEnumTemplate0, enumHandle *uintptr) error {
	if err := loadProcs(); err != nil {
		return err
	}
	r, _, _ := procFwpmFilterCreateEnumHandle0.Call(engine, uintptr(unsafe.Pointer(template)), uintptr(unsafe.Pointer(enumHandle)))
	return errnoResult(r)
}

func fwpmFilterEnum0(engine, enumHandle uintptr, requested uint32, entries ***fwpmFilter0, returned *uint32) error {
	if err := loadProcs(); err != nil {
		return err
	}
	r, _, _ := procFwpmFilterEnum0.Call(engine, enumHandle, uintptr(requested), uintptr(unsafe.Pointer(entries)), uintptr(unsafe.Pointer(returned)))
	return errnoResult(r)
}

func fwpmFilterDestroyEnumHandle0(engine, enumHandle uintptr) error {
	if err := loadProcs(); err != nil {
		return err
	}
	r, _, _ := procFwpmFilterDestroyEnumHandle0.Call(engine, enumHandle)
	return errnoResult(r)
}

func fwpmGetAppIDFromFileName0(fileName *uint16, appID **fwpByteBlob) error {
	if err := loadProcs(); err != nil {
		return err
	}
	r, _, _ := procFwpmGetAppIdFromFileName0.Call(uintptr(unsafe.Pointer(fileName)), uintptr(unsafe.Pointer(appID)))
	return errnoResult(r)
}

// fwpmFreeMemory0 releases memory returned by WFP and sets *p to nil. p
// is the address of the pointer variable (void **).
func fwpmFreeMemory0(p *unsafe.Pointer) {
	if loadProcs() != nil || *p == nil {
		return
	}
	procFwpmFreeMemory0.Call(uintptr(unsafe.Pointer(p)))
}

func isErrno(err error, codes ...uintptr) bool {
	var e syscall.Errno
	if !errors.As(err, &e) {
		return false
	}
	for _, c := range codes {
		if uintptr(e) == c {
			return true
		}
	}
	return false
}
