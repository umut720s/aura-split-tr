//go:build !windows

package engine

func detectPhysicalNetwork() (physicalLink, error) { return physicalLink{up: true}, nil }
