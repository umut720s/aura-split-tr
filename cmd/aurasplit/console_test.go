//go:build windows

package main

import (
	"bufio"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"aurasplit/internal/oldflow"
)

type forbiddenInput struct{}

func (forbiddenInput) Read([]byte) (int, error) { panic("non-interactive console read") }

func TestNonInteractiveNeverReadsOrConsents(t *testing.T) {
	oldConsole, oldSuppress, oldStdin := interactiveConsole, suppressInput, stdin
	t.Cleanup(func() { interactiveConsole, suppressInput, stdin = oldConsole, oldSuppress, oldStdin })
	stdin = bufio.NewReader(forbiddenInput{})
	for _, tc := range []struct{ visible, suppressed bool }{{false, false}, {true, true}, {false, true}} {
		interactiveConsole = func() bool { return tc.visible }
		suppressInput = tc.suppressed
		if readLine("forbidden") != "" || askYesNo("forbidden", true) {
			t.Fatal("input/consent granted")
		}
		waitEnter()
		if got := cmdSetup(true); got != exitNeedsInput {
			t.Fatal(got)
		}
		if got := cmdDisable(); got != exitNeedsInput {
			t.Fatal(got)
		}
	}
}

func TestNonInteractivePendingStartReturnsGuidanceCode(t *testing.T) {
	oldConsole, oldDiscover, oldProcesses := interactiveConsole, discoverDiscord, startupProcesses
	oldSuppress := suppressInput
	t.Cleanup(func() {
		interactiveConsole, discoverDiscord, startupProcesses, suppressInput = oldConsole, oldDiscover, oldProcesses, oldSuppress
	})
	interactiveConsole = func() bool { return false }
	suppressInput = false
	exe := `C:\Users\fixture\AppData\Local\Discord\app-1\Discord.exe`
	discoverDiscord = func() ([]string, error) { return []string{exe}, nil }
	startupProcesses = func([]string) ([]oldflow.Process, error) { return []oldflow.Process{{PID: 42, Image: exe}}, nil }
	if got := finishProtectionStart(time.Hour); got != exitNeedsInput {
		t.Fatal(got)
	}
}

func TestSetupConsoleHeldOnEveryResult(t *testing.T) {
	// The common deferred exit decision is independent of the command result.
	for _, result := range []int{0, 1, 2, exitNeedsInput} {
		if !holdConsole(true, false, false, false, false) || !holdConsole(true, true, false, false, false) {
			t.Fatal(result)
		}
	}
	for _, tc := range []struct{ setup, elevated, msi, relaunched, service bool }{{true, true, true, false, false}, {true, false, false, true, false}, {false, true, false, false, true}, {false, false, false, false, false}} {
		if holdConsole(tc.setup, tc.elevated, tc.msi, tc.relaunched, tc.service) {
			t.Fatal(tc)
		}
	}
}

type countingInput struct{ reads int }

func (r *countingInput) Read(p []byte) (int, error) { r.reads++; p[0] = '\n'; return 1, nil }

func TestMainWaitsBeforeReturningSetupArgumentError(t *testing.T) {
	oldArgs, oldConsole, oldStdin, oldSuppress, oldRelaunch := os.Args, interactiveConsole, stdin, suppressInput, setupRelaunched
	t.Cleanup(func() {
		os.Args, interactiveConsole, stdin, suppressInput, setupRelaunched = oldArgs, oldConsole, oldStdin, oldSuppress, oldRelaunch
	})
	os.Args = []string{"fixture", "setup", "--save-state"}
	interactiveConsole = func() bool { return true }
	suppressInput, setupRelaunched = false, false
	r := &countingInput{}
	stdin = bufio.NewReader(r)
	if code := runMain(); code != 2 || r.reads != 1 {
		t.Fatal(code, r.reads)
	}
}

func TestEOFNeverAcceptsDefaultYes(t *testing.T) {
	oldConsole, oldStdin, oldSuppress := interactiveConsole, stdin, suppressInput
	t.Cleanup(func() { interactiveConsole, stdin, suppressInput = oldConsole, oldStdin, oldSuppress })
	interactiveConsole = func() bool { return true }
	suppressInput = false
	stdin = bufio.NewReader(io.LimitReader(strings.NewReader(""), 0))
	if askYesNo("fixture", true) {
		t.Fatal("EOF accepted consent")
	}
}
