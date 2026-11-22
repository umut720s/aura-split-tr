//go:build !(windows && (amd64 || arm64))

package wfp

// The WFP structure layouts in fwpm_windows.go are written for 64-bit
// Windows; every other platform gets a backend that always fails.
func platformBackend() backend { return unsupportedBackend{} }

type unsupportedBackend struct{}

func (unsupportedBackend) Open(bool) (session, error)   { return nil, ErrUnsupported }
func (unsupportedBackend) AppID(string) ([]byte, error) { return nil, ErrUnsupported }
