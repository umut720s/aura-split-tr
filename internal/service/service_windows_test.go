//go:build windows

package service

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

func TestQuotedCommandLine(t *testing.T) {
	for in, want := range map[string]string{
		`C:\Program Files\AuraSplitTR\aurasplit.exe`:   `"C:\Program Files\AuraSplitTR\aurasplit.exe" service`,
		`"C:\Program Files\AuraSplitTR\aurasplit.exe"`: `"C:\Program Files\AuraSplitTR\aurasplit.exe" service`,
		`D:\Apps\AuraSplitTR\aurasplit.exe`:            `"D:\Apps\AuraSplitTR\aurasplit.exe" service`,
	} {
		if got := quotedCommandLine(in); got != want {
			t.Errorf("quotedCommandLine(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSplitQuotedCommandLine(t *testing.T) {
	for _, c := range []struct {
		in        string
		exe, args string
		ok        bool
	}{
		{`"C:\Program Files\AuraSplitTR\aurasplit.exe" service`, `C:\Program Files\AuraSplitTR\aurasplit.exe`, "service", true},
		{`  "C:\A B\aurasplit.exe"   service  `, `C:\A B\aurasplit.exe`, "service", true},
		{`"C:\A\aurasplit.exe"`, `C:\A\aurasplit.exe`, "", true},
		{`C:\Program Files\AuraSplitTR\aurasplit.exe service`, "", "", false}, // unquoted
		{`"C:\A\aurasplit.exe"service`, "", "", false},
		{`"unterminated service`, "", "", false},
		{`"" service`, "", "", false},
	} {
		exe, args, ok := splitQuotedCommandLine(c.in)
		if exe != c.exe || args != c.args || ok != c.ok {
			t.Errorf("splitQuotedCommandLine(%q) = %q, %q, %v", c.in, exe, args, ok)
		}
	}
}

// checkConfig accepts what the MSI registers and rejects anything that
// would run a different binary, account or without the BFE dependency.
func TestCheckConfig(t *testing.T) {
	const exe = `C:\Program Files\AuraSplitTR\aurasplit.exe`
	good := mgr.Config{
		BinaryPathName:   `"C:\Program Files\AuraSplitTR\aurasplit.exe" service`,
		ServiceType:      windows.SERVICE_WIN32_OWN_PROCESS,
		ServiceStartName: "LocalSystem",
		Dependencies:     []string{"BFE"},
	}
	if err := checkConfig(good, exe); err != nil {
		t.Fatalf("MSI configuration rejected: %v", err)
	}
	lower := good
	lower.BinaryPathName = strings.ToLower(good.BinaryPathName)
	if err := checkConfig(lower, exe); err != nil {
		t.Fatalf("case difference rejected: %v", err)
	}
	for name, mut := range map[string]func(*mgr.Config){
		"other binary":   func(c *mgr.Config) { c.BinaryPathName = `"C:\Other\aurasplit.exe" service` },
		"unquoted":       func(c *mgr.Config) { c.BinaryPathName = exe + " service" },
		"extra args":     func(c *mgr.Config) { c.BinaryPathName = `"` + exe + `" service --debug` },
		"no args":        func(c *mgr.Config) { c.BinaryPathName = `"` + exe + `"` },
		"user account":   func(c *mgr.Config) { c.ServiceStartName = `.\someone` },
		"no BFE":         func(c *mgr.Config) { c.Dependencies = nil },
		"shared process": func(c *mgr.Config) { c.ServiceType = windows.SERVICE_WIN32_SHARE_PROCESS },
	} {
		c := good
		mut(&c)
		if err := checkConfig(c, exe); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
