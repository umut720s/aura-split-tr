package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"aurasplit/internal/engine"
)

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
