//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

var stdin = bufio.NewReader(os.Stdin)

// readLine prints prompt and returns the trimmed line the user typed.
func readLine(prompt string) string {
	fmt.Print(prompt)
	s, _ := stdin.ReadString('\n')
	return strings.TrimSpace(s)
}

// askYesNo asks a yes/no question in Turkish. Empty input returns def.
func askYesNo(prompt string, def bool) bool {
	hint := "(e/H)"
	if def {
		hint = "(E/h)"
	}
	for {
		s := strings.ToLower(readLine(fmt.Sprintf("%s %s: ", prompt, hint)))
		switch s {
		case "":
			return def
		case "e", "evet", "y", "yes":
			return true
		case "h", "hayır", "hayir", "n", "no":
			return false
		}
		fmt.Println("Lütfen 'e' (evet) ya da 'h' (hayır) yazın.")
	}
}

// waitEnter keeps the console window open until the user presses Enter.
func waitEnter() {
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
