//go:build !windows

package engine

import "errors"

func readDiagnosticNICs() ([]diagnosticNIC, error) {
	return nil, errors.New("Windows adapter tables unavailable")
}
