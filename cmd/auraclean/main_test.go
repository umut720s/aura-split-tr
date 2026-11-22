//go:build windows

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	for _, tt := range []struct {
		name              string
		args              []string
		admin             bool
		cleanupCode, want int
		wantMessage       string
	}{
		{name: "missing", want: 2, wantMessage: "Kullanım:"},
		{name: "no MSI flag", args: []string{"uninstall"}, want: 2, wantMessage: "Kullanım:"},
		{name: "wrong command", args: []string{"recover", "--msi"}, want: 2, wantMessage: "Kullanım:"},
		{name: "extra argument", args: []string{"uninstall", "--msi", "C:\\"}, want: 2, wantMessage: "Kullanım:"},
		{name: "unelevated", args: []string{"uninstall", "--msi"}, want: 1, wantMessage: "hiçbir şey yapılmadı"},
		{name: "success", args: []string{"uninstall", "--msi"}, admin: true},
		{name: "recovery failure", args: []string{"uninstall", "--msi"}, admin: true, cleanupCode: 1, want: 1},
		{name: "alias and flag order", args: []string{"--MSI", "KALDIR", "--msi"}, admin: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var stderr bytes.Buffer
			adminCalls, cleanupCalls := 0, 0
			code := run(tt.args, &stderr, func() bool { adminCalls++; return tt.admin }, func() int { cleanupCalls++; return tt.cleanupCode })
			if code != tt.want || !strings.Contains(stderr.String(), tt.wantMessage) {
				t.Fatalf("code=%d stderr=%q; want %d containing %q", code, stderr.String(), tt.want, tt.wantMessage)
			}
			if tt.want == 2 && adminCalls != 0 {
				t.Fatal("invalid arguments reached token check")
			}
			wantCleanup := 0
			if tt.admin && tt.want != 2 {
				wantCleanup = 1
			}
			if cleanupCalls != wantCleanup {
				t.Fatalf("cleanup calls=%d, want %d", cleanupCalls, wantCleanup)
			}
		})
	}
}
