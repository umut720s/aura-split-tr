//go:build !windows

package engine

// detectHostIPv6 is a stub outside Windows (the engine only runs there; the
// package builds elsewhere for tests and vet).
func detectHostIPv6() (bool, error) { return false, nil }

func detectHostIPv6On(_ int) (bool, error) { return false, nil }
