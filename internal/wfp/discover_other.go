//go:build !windows

package wfp

import "io/fs"

func isLinkLike(fi fs.FileInfo) bool { return fi.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0 }

// ProfileDirs is only implemented on Windows.
func ProfileDirs() ([]string, error) { return nil, ErrUnsupported }

// Discover is only implemented on Windows.
func Discover() ([]string, error) { return nil, ErrUnsupported }

// WatchTargets is only implemented on Windows.
func WatchTargets() ([]WatchTarget, error) { return nil, ErrUnsupported }

// TunnelLUID is only implemented on Windows.
func TunnelLUID(string) (uint64, error) { return 0, ErrUnsupported }
