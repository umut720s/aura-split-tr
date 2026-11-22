package main

import (
	"runtime"
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// openFileName matches OPENFILENAMEW, including its pointer-sized fields.
type openFileName struct {
	Size                         uint32
	Owner, Instance              windows.Handle
	Filter, CustomFilter         *uint16
	MaxCustomFilter, FilterIndex uint32
	File                         *uint16
	MaxFile                      uint32
	FileTitle                    *uint16
	MaxFileTitle                 uint32
	InitialDir, Title            *uint16
	Flags                        uint32
	FileOffset, FileExtension    uint16
	DefaultExtension             *uint16
	CustomData                   uintptr
	Hook, Template, Reserved     uintptr
	ReservedSize, FlagsEx        uint32
}

func confFilter() []uint16 {
	// The common dialog requires NUL-separated pairs and a double terminator.
	return utf16.Encode([]rune(strings.ReplaceAll("WireGuard yapılandırması (*.conf)|*.conf|Tüm dosyalar (*.*)|*.*", "|", "\x00") + "\x00\x00"))
}

func pickConfFile() (string, error) {
	filter := confFilter()
	title, _ := windows.UTF16FromString("WireGuard .conf dosyasını seçin")
	file := make([]uint16, 32768)
	owner, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleWindow").Call()
	of := openFileName{Owner: windows.Handle(owner), Filter: &filter[0], FilterIndex: 1,
		File: &file[0], MaxFile: uint32(len(file)), Title: &title[0],
		Flags: 0x00080000 | 0x00001000 | 0x00000800 | 0x00000008} // Explorer, file/path must exist, no directory change.
	of.Size = uint32(unsafe.Sizeof(of))
	// Pin all memory reachable through the native structure until the call returns.
	var pin runtime.Pinner
	pin.Pin(&of)
	pin.Pin(&filter[0])
	pin.Pin(&title[0])
	pin.Pin(&file[0])
	defer pin.Unpin()
	ok, _, _ := windows.NewLazySystemDLL("comdlg32.dll").NewProc("GetOpenFileNameW").Call(uintptr(unsafe.Pointer(&of)))
	runtime.KeepAlive(of)
	if ok == 0 {
		return "", nil // Cancellation and dialog failures both use the console fallback.
	}
	return windows.UTF16ToString(file), nil
}

func chooseConfPath(picker func() (string, error), prompt func(string) string) string {
	if path, err := picker(); err == nil && path != "" {
		return path
	}
	return cleanPath(prompt(".conf dosyasının yolu (Yol olarak kopyala; boş bırakırsanız menüye döner): "))
}
