//go:build windows && (amd64 || arm64)

package wfp

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Every call in this file talks to the Base Filtering Engine. None of it
// is exercised by unit tests (they use a fake backend; the structure
// builders are tested separately); it is NOT TESTED until an authorised
// administrator test on a real machine.
//
// Pointer rules: output cells (&h, &blob, &entries, &n, &id) are passed to
// typed bindings that convert them inside the LazyProc.Call expression
// (fwpm_windows.go). Structures handed to BFE are built by the
// marshal_windows.go builders, which pin everything reachable from them;
// each method unpins after the call returned.

func platformBackend() backend { return winBackend{} }

type winBackend struct{}

var (
	providerKeyWin = windows.GUID(ProviderKey)
	subLayerKeyWin = windows.GUID(SubLayerKey)
)

func (winBackend) Open(dynamic bool) (session, error) {
	var pin runtime.Pinner
	defer pin.Unpin()
	s := buildSession(&pin, dynamic)
	var h uintptr
	if err := fwpmEngineOpen0(rpcCAuthnWinNT, s, &h); err != nil {
		return nil, err
	}
	return &winSession{h: h}, nil
}

// AppID returns the ALE application ID (NT device path) of path. The file
// must exist.
func (winBackend) AppID(path string) ([]byte, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var blob *fwpByteBlob
	if err := fwpmGetAppIDFromFileName0(p, &blob); err != nil {
		return nil, err
	}
	runtime.KeepAlive(p)
	defer fwpmFreeMemory0((*unsafe.Pointer)(unsafe.Pointer(&blob)))
	if blob == nil || blob.size == 0 || blob.data == nil {
		return nil, errors.New("empty app ID")
	}
	return append([]byte(nil), unsafe.Slice(blob.data, blob.size)...), nil
}

type winSession struct{ h uintptr }

func (s *winSession) Close() error {
	if s.h == 0 {
		return nil
	}
	err := fwpmEngineClose0(s.h)
	s.h = 0
	return err
}

// Begin opens a read-write transaction (flags 0). BFE serialises
// read-write transactions across all sessions and processes; another
// session waits up to fwpmTxnWaitMS.
func (s *winSession) Begin() error  { return fwpmTransactionBegin0(s.h, 0) }
func (s *winSession) Commit() error { return fwpmTransactionCommit0(s.h) }
func (s *winSession) Abort() error  { return fwpmTransactionAbort0(s.h) }

func (s *winSession) AddProvider() error {
	var pin runtime.Pinner
	defer pin.Unpin()
	err := fwpmProviderAdd0(s.h, buildProvider(&pin))
	if isErrno(err, fwpEAlreadyExists) {
		return nil
	}
	return err
}

func (s *winSession) AddSubLayer() error {
	var pin runtime.Pinner
	defer pin.Unpin()
	err := fwpmSubLayerAdd0(s.h, buildSubLayer(&pin))
	if isErrno(err, fwpEAlreadyExists) {
		return nil
	}
	return err
}

func (s *winSession) HasProvider() (bool, error) {
	key := providerKeyWin
	var out *fwpmProvider0
	err := fwpmProviderGetByKey0(s.h, &key, &out)
	if isErrno(err, fwpEProviderNotFound, fwpENotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("wfp: get provider: %w", err)
	}
	fwpmFreeMemory0((*unsafe.Pointer)(unsafe.Pointer(&out)))
	return true, nil
}

func (s *winSession) HasSubLayer() (bool, error) {
	key := subLayerKeyWin
	var out *fwpmSublayer0
	err := fwpmSubLayerGetByKey0(s.h, &key, &out)
	if isErrno(err, fwpESublayerNotFound, fwpENotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("wfp: get sublayer: %w", err)
	}
	if out == nil {
		return true, nil
	}
	w := out.weight
	fwpmFreeMemory0((*unsafe.Pointer)(unsafe.Pointer(&out)))
	if w != SubLayerWeight {
		return true, fmt.Errorf("wfp: sublayer exists with weight %#x, expected %#x (run `aurasplit recover`)", w, SubLayerWeight)
	}
	return true, nil
}

const enumBatch = 128

// Filters lists every filter of our provider on every layer, including
// disabled filters. If BFE rejects the include-disabled flag (not expected
// on Windows 7 and later) the enumeration is repeated without it.
func (s *winSession) Filters() ([]FilterRecord, error) {
	var out []FilterRecord
	for _, l := range Layers {
		recs, err := s.filtersOn(l, true)
		if isErrno(err, fwpEInvalidFlags, fwpEInvalidParameter) {
			recs, err = s.filtersOn(l, false)
		}
		if err != nil {
			return nil, err
		}
		out = append(out, recs...)
	}
	return out, nil
}

func (s *winSession) filtersOn(l Layer, includeDisabled bool) ([]FilterRecord, error) {
	lg, _ := layerGUID(l)
	var eh uintptr
	err := func() error {
		var pin runtime.Pinner
		defer pin.Unpin()
		return fwpmFilterCreateEnumHandle0(s.h, buildEnumTemplate(&pin, lg, includeDisabled), &eh)
	}()
	if err != nil {
		return nil, fmt.Errorf("create enum handle (%s): %w", l, err)
	}
	defer fwpmFilterDestroyEnumHandle0(s.h, eh)
	var out []FilterRecord
	for {
		var entries **fwpmFilter0
		var n uint32
		if err := fwpmFilterEnum0(s.h, eh, enumBatch, &entries, &n); err != nil {
			return nil, fmt.Errorf("enumerate filters (%s): %w", l, err)
		}
		if n > 0 && entries != nil {
			for _, f := range unsafe.Slice(entries, n) {
				if rec, ok := parseFilter(f, l); ok {
					out = append(out, rec)
				}
			}
		}
		fwpmFreeMemory0((*unsafe.Pointer)(unsafe.Pointer(&entries)))
		if n < enumBatch {
			return out, nil
		}
	}
}

func (s *winSession) AddFilter(f *Filter) error {
	var pin runtime.Pinner
	defer pin.Unpin()
	flt, err := buildFilter(&pin, f)
	if err != nil {
		return err
	}
	var id uint64
	err = fwpmFilterAdd0(s.h, flt, &id)
	if !f.Key.IsZero() && isErrno(err, fwpEAlreadyExists) {
		return nil
	}
	return err
}

func (s *winSession) DeleteFilter(id uint64) error {
	err := fwpmFilterDeleteByID0(s.h, id)
	if isErrno(err, fwpEFilterNotFound, fwpENotFound) {
		return nil
	}
	return err
}

func (s *winSession) DeleteSubLayer() error {
	key := subLayerKeyWin
	err := fwpmSubLayerDeleteByKey0(s.h, &key)
	if isErrno(err, fwpESublayerNotFound, fwpENotFound) {
		return nil
	}
	return err
}

func (s *winSession) DeleteProvider() error {
	key := providerKeyWin
	err := fwpmProviderDeleteByKey0(s.h, &key)
	if isErrno(err, fwpEProviderNotFound, fwpENotFound) {
		return nil
	}
	return err
}
