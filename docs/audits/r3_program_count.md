# R3 enrolled-program count

The exact 9-to-6 transition cannot be reconstructed from counts alone. R3 did
not retain two path/class inventories. There is no setup-only discovery mode:
`cmd/aurasplit/protect_windows.go:21,128` and `internal/wfp/discover_windows.go:105`
use the same ProfileList + DiscoverIn path in setup and the service. Both run
elevated; the service enumerates every real user profile, not its own AppData.

`internal/wfp/discover.go:110-161` includes Update.exe, transient installers in
SquirrelTemp and installation roots, every app-* version, direct EXEs and
bounded module helpers. Temporary installers or obsolete app-* directories can
disappear after an updater finishes. Each existing version is included, newest
first (`:174-198`), not only the current version. Helper traversal is exactly
modules/*/*/*.exe (`:203-225`). Direct EXEs include routing fallbacks outside the
narrow manifest; the block count is not the number of manifest process names
or of running processes. Dynamic tunnel permits use canonical manifest paths.

Bounds (64 profiles, 16 EXEs/directory, 64 directory entries, global/per-profile
policy budgets) report incomplete inventory and make reconciliation add-only;
they do not silently select six programs. Read/enrollment errors must be checked
alongside counts. A separate bug was found: ProfileDirs skipped invalid or
unreadable ProfileImagePath values without marking that profile incomplete.
This is fixed: read/expansion/absolute-path validation failures now propagate an
incomplete inventory, preserving existing blocks. No evidence links that registry
condition to R3's seven-minute transition; do not label it the proven cause.

`internal/wfp/policy.go:569-581` only prunes stale blocks on authoritative
discovery when the old executable no longer exists. Therefore a count decrease
following actual file cleanup is expected. Keeping a fixed historical count
would misrepresent enrollment and unnecessarily retain obsolete policy.

No version/helper selection change is justified by R3 alone. A compile-only regression
test covers unchanged repeated inventories and three transient installer removals
producing 9 then 6. It is intentionally not executed under the maintainer's
restriction on internal/wfp test binaries. To establish the actual R3 cause,
compare private per-class inventories, updater file events, and discovery errors
at setup/start; do not publish user paths. No live filesystem inventory was read
during this investigation.
