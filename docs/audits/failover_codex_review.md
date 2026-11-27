# Multi-NIC failover — independent Codex (gpt-6.1-sol) review

Run: 2026-11-27, read-only. Verbatim final output (local paths redacted).

- **Medium — [egress.go:199](internal/engine/egress.go:199), [egress.go:154](internal/engine/egress.go:154): DNS-only success can restore an unusable primary NIC.** After successful failover, the primary router can resume answering cached `example.com` queries while its Internet uplink remains dead. These responses count toward recovery despite both TCP probes failing. After three samples, AURA abandons the working backup and routes non-Discord traffic through the dead primary; continued DNS responses prevent further failover indefinitely. Require Internet reachability before restoring/selecting an egress, and track DNS health separately.

Blocking defects in this change: YES

## Targeted re-check after fix (2026-11-27)

FIXED — `internal/engine/egress.go:151`: health depends exclusively on `sample.TCP`; DNS-only success resets recovery progress (`:157`) and cannot select a backup (`:177`).
Recovery requires three consecutive TCP-successful samples (`internal/engine/egress.go:166`).
Regression coverage: `internal/engine/egress_test.go:222`, `:263`, `:290` covers probe aggregation, DNS-only backup rejection, and interrupted TCP recovery.
Focused engine tests could not run: sandbox denied Go’s temporary build directory. No elevation or prohibited test binaries used; no files modified.
No new blocking defect identified in this targeted inspection.
Blocking defects in this change: NO
