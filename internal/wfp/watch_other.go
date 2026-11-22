//go:build !windows

package wfp

import "context"

// platformWatch is only implemented on Windows.
func platformWatch(context.Context, []WatchTarget, func(), func(WatchTarget, error)) error {
	return ErrUnsupported
}
