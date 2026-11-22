//go:build windows

package wfp

import (
	"errors"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modIphlp        = windows.NewLazySystemDLL("iphlpapi.dll")
	procAliasToLuid = modIphlp.NewProc("ConvertInterfaceAliasToLuid")
)

// TunnelLUID returns the NET_LUID of the network interface named alias
// (the TUN adapter "AuraSplitTR"). NOT TESTED without a real adapter.
func TunnelLUID(alias string) (uint64, error) {
	p, err := windows.UTF16PtrFromString(alias)
	if err != nil {
		return 0, err
	}
	if err := procAliasToLuid.Find(); err != nil {
		return 0, err
	}
	var luid uint64
	r, _, _ := procAliasToLuid.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&luid)))
	if r != 0 {
		return 0, syscall.Errno(r)
	}
	if luid == 0 {
		return 0, errors.New("interface LUID is zero")
	}
	return luid, nil
}
