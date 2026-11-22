//go:build windows

// Command auraclean is the MSI's embedded commit-time cleanup helper.
// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"aurasplit/internal/msiclean"
	"aurasplit/internal/service"
	"aurasplit/internal/wfp"
)

// version is set with the same linker flags as aurasplit.
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stderr, service.IsAdmin, uninstall))
}

// run validates the private MSI entry point before calling any system operation.
func run(args []string, stderr io.Writer, isAdmin func() bool, cleanup func() int) int {
	var positional []string
	msi := false
	for _, arg := range args {
		if strings.EqualFold(arg, "--msi") {
			msi = true
		} else {
			positional = append(positional, strings.ToLower(arg))
		}
	}
	if !msi || len(positional) != 1 || (positional[0] != "uninstall" && positional[0] != "kaldir") {
		fmt.Fprintln(stderr, "Kullanım: auraclean.exe uninstall --msi")
		return 2
	}
	if !isAdmin() {
		fmt.Fprintln(stderr, "--msi yönetici (veya SYSTEM) olarak çalıştırılmalıdır; hiçbir şey yapılmadı.")
		return 1
	}
	return cleanup()
}

func uninstall() int {
	return msiclean.Uninstall(func() int {
		return msiclean.Recover(true, msiclean.RecoverOps{
			Disable: service.Disable,
			Stop:    service.Stop,
			Remove: func() error {
				return wfp.New().RemoveAll()
			},
			Installed: func() (bool, int, error) {
				return wfp.New().Installed()
			},
		})
	})
}
