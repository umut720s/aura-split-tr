//go:build !windows

package testutil

import "testing"

// AssertNoOpenHandles is a no-op outside Windows: POSIX lets open files be
// removed, so a leaked handle never blocks the cleanup there.
func AssertNoOpenHandles(t testing.TB, dir string) { t.Helper() }
