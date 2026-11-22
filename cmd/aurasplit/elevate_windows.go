//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

// relaunchElevated starts this executable again through the UAC prompt
// ("runas") with the given arguments plus the internal elevated flag.
//
// Self-elevation is kept only for interactive commands a user starts
// (setup from the Start Menu shortcut, or start/stop/... typed in a normal
// console), so a visible UAC prompt always follows a user action. It never
// installs anything: the program file and the service belong to the MSI
// package. Commands run by Windows Installer (--msi) are already elevated
// (deferred, not impersonated) and never relaunch or prompt.
func relaunchElevated(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	all := append(append([]string{}, args...), elevatedFlag)
	quoted := make([]string, len(all))
	for i, a := range all {
		quoted[i] = syscall.EscapeArg(a)
	}

	verb, _ := windows.UTF16PtrFromString("runas")
	file, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	params, err := windows.UTF16PtrFromString(strings.Join(quoted, " "))
	if err != nil {
		return err
	}
	cwd, _ := windows.UTF16PtrFromString(filepath.Dir(exe))

	err = windows.ShellExecute(0, verb, file, params, cwd, windows.SW_NORMAL)
	if errors.Is(err, windows.ERROR_CANCELLED) {
		return errors.New("kullanıcı yönetici iznini reddetti")
	}
	return err
}
