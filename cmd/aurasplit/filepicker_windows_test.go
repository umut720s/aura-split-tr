package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
	"unsafe"

	"aurasplit/internal/engine"
)

func TestOpenFileNameAMD64Layout(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("Windows 64-bit ABI")
	}
	var of openFileName
	if unsafe.Sizeof(of) != 152 {
		t.Fatalf("OPENFILENAMEW size = %d, want 152", unsafe.Sizeof(of))
	}
	for _, field := range []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"Owner", unsafe.Offsetof(of.Owner), 8},
		{"Instance", unsafe.Offsetof(of.Instance), 16},
		{"Filter", unsafe.Offsetof(of.Filter), 24},
		{"CustomFilter", unsafe.Offsetof(of.CustomFilter), 32},
		{"MaxCustomFilter", unsafe.Offsetof(of.MaxCustomFilter), 40},
		{"FilterIndex", unsafe.Offsetof(of.FilterIndex), 44},
		{"File", unsafe.Offsetof(of.File), 48},
		{"MaxFile", unsafe.Offsetof(of.MaxFile), 56},
		{"FileTitle", unsafe.Offsetof(of.FileTitle), 64},
		{"MaxFileTitle", unsafe.Offsetof(of.MaxFileTitle), 72},
		{"InitialDir", unsafe.Offsetof(of.InitialDir), 80},
		{"Title", unsafe.Offsetof(of.Title), 88},
		{"Flags", unsafe.Offsetof(of.Flags), 96},
		{"FileOffset", unsafe.Offsetof(of.FileOffset), 100},
		{"FileExtension", unsafe.Offsetof(of.FileExtension), 102},
		{"DefaultExtension", unsafe.Offsetof(of.DefaultExtension), 104},
		{"CustomData", unsafe.Offsetof(of.CustomData), 112},
		{"Hook", unsafe.Offsetof(of.Hook), 120},
		{"Template", unsafe.Offsetof(of.Template), 128},
		{"Reserved", unsafe.Offsetof(of.Reserved), 136},
		{"ReservedSize", unsafe.Offsetof(of.ReservedSize), 144},
		{"FlagsEx", unsafe.Offsetof(of.FlagsEx), 148},
	} {
		if field.got != field.want {
			t.Errorf("%s offset = %d, want %d", field.name, field.got, field.want)
		}
	}
}

func TestConfFilter(t *testing.T) {
	got := string(utf16.Decode(confFilter()))
	want := "WireGuard yapılandırması (*.conf)\x00*.conf\x00Tüm dosyalar (*.*)\x00*.*\x00\x00"
	if got != want {
		t.Fatalf("filter %q, want %q", got, want)
	}
}

func TestChooseConfPath(t *testing.T) {
	for _, tc := range []struct {
		picked, typed, want string
		err                 error
	}{
		{picked: `C:\config.conf`, want: `C:\config.conf`},
		{typed: ` "C:\my config.conf" `, want: `C:\my config.conf`},
		{typed: `& 'C:\my config.conf'`, want: `C:\my config.conf`, err: errors.New("dialog failed")},
		{typed: ""},
	} {
		prompted := false
		got := chooseConfPath(func() (string, error) { return tc.picked, tc.err }, func(string) string { prompted = true; return tc.typed })
		if got != tc.want || prompted != (tc.picked == "" || tc.err != nil) {
			t.Fatalf("%+v: got %q, prompted %v", tc, got, prompted)
		}
	}
}

func TestConnectingStatus(t *testing.T) {
	out := strings.Join(describeStatus(statusInput{scmRunning: true, state: &tunnelState{
		State: string(engine.StateTunnelStarted), Connectivity: string(engine.ConnConnecting),
	}}, time.UTC), "\n")
	if !strings.Contains(out, "VPN_CONNECTING — bağlanıyor") {
		t.Fatal(out)
	}
}

func TestConfSizeLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.conf")
	for _, size := range []int{maxConfSize, maxConfSize + 1} {
		if err := os.WriteFile(path, make([]byte, size), 0600); err != nil {
			t.Fatal(err)
		}
		data, err := readSmallFile(path, maxConfSize)
		if size == maxConfSize && (err != nil || len(data) != size) {
			t.Fatalf("limit: len=%d err=%v", len(data), err)
		}
		if size > maxConfSize && err == nil {
			t.Fatal("oversized file accepted")
		}
	}
}
