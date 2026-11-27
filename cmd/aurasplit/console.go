//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

var stdin = bufio.NewReader(os.Stdin)

const exitNeedsInput = 3

var suppressInput bool
var interactiveConsole = detectInteractiveConsole

func inputAllowed() bool { return !suppressInput && interactiveConsole() }

var consoleWindow = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleWindow")
var windowVisible = windows.NewLazySystemDLL("user32.dll").NewProc("IsWindowVisible")

func detectInteractiveConsole() bool {
	var mode, session uint32
	if windows.GetConsoleMode(windows.Handle(os.Stdin.Fd()), &mode) != nil || windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session) != nil || session == 0 {
		return false
	}
	var startup windows.StartupInfo
	if windows.GetStartupInfo(&startup) != nil || startup.Flags&windows.STARTF_USESHOWWINDOW != 0 && startup.ShowWindow == windows.SW_HIDE {
		return false
	}
	hwnd, _, _ := consoleWindow.Call()
	visible, _, _ := windowVisible.Call(hwnd)
	// ConPTY hosts use an invisible console HWND; their terminal owns the UI.
	terminal := os.Getenv("WT_SESSION") != "" || os.Getenv("TERM_PROGRAM") == "vscode"
	return hwnd != 0 && (visible != 0 || terminal)
}

func inputGuidance() {
	fmt.Fprintln(os.Stderr, "Etkileşimli, görünür bir konsol gerekiyor. Başlat menüsünden AURA Split TR - Yapılandır'ı veya görünür bir yönetici terminalini açın. Discord'u tamamen kapatıp yeniden açın; durumu aurasplit.exe status ile denetleyin. (Çıkış kodu: 3)")
}

// readLine prints prompt and returns the trimmed line the user typed.
func readLine(prompt string) string {
	if !inputAllowed() {
		inputGuidance()
		return ""
	}
	fmt.Print(prompt)
	s, err := stdin.ReadString('\n')
	if err != nil {
		suppressInput = true
	}
	return strings.TrimSpace(s)
}

// askYesNo asks a yes/no question in Turkish. Empty input returns def.
func askYesNo(prompt string, def bool) bool {
	if !inputAllowed() {
		inputGuidance()
		return false
	}
	hint := "(e/H)"
	if def {
		hint = "(E/h)"
	}
	for {
		s := strings.ToLower(readLine(fmt.Sprintf("%s %s: ", prompt, hint)))
		if !inputAllowed() {
			return false
		}
		switch s {
		case "":
			return def
		case "e", "evet", "y", "yes":
			return true
		case "h", "hayır", "hayir", "n", "no":
			return false
		}
		fmt.Println("Lütfen 'e' (evet) ya da 'h' (hayır) yazın.")
		if !inputAllowed() {
			return false
		}
	}
}

// waitEnter keeps the console window open until the user presses Enter.
func waitEnter() {
	if !inputAllowed() {
		return
	}
	fmt.Println()
	readLine("Kapatmak için Enter'a basın...")
}

// fail prints a Turkish user message plus the technical detail. Callers
// must make sure err never contains secret material (the internal
// packages guarantee they never put keys into errors).
func fail(msg string, err error) {
	fmt.Fprintf(os.Stderr, "\nHATA: %s\n", msg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ayrıntı: %v\n", err)
	}
}

func failMsg(msg string) { fail(msg, nil) }

// cleanPath normalises a path typed or drag-and-dropped into the console:
// surrounding whitespace and quotes are removed, as is the "& '...'"
// wrapper PowerShell adds when a file is dropped.
func cleanPath(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "& ") {
		s = strings.TrimSpace(s[2:])
	}
	for len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'')) {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	return s
}
