# P0 wave 1 — independent Codex (gpt-6.1-sol) targeted check 4

Run: 2026-11-27, read-only. Verbatim final output (local paths redacted).

Read-only static check; no files modified, elevation, or test binaries executed.

1. **FIXED — failed permit closure forgotten:** `internal/wfp/backend_windows.go:70–73` and `internal/wfp/policy.go:692–695` preserve ownership on failure. `internal/wfp/guard.go:172–182,288–293,338–361` retains failed closures and retries; `:149,203` prevents readiness while closure remains pending.
2. **FIXED — block-mode coverage regression:** `internal/engine/config.go:367,372–374,391` restores whole-install-directory routing/rejection. `internal/wfp/discover.go:189–215,250–266` discovers arbitrary EXEs within bounded app/module locations and reports caps. Destructive actions remain exact-manifest-only through `internal/oldflow/gate.go:22`, `internal/manifest/manifest.go:49–58`, and same-handle validation at `internal/oldflow/source_windows.go:69–79`.

No new qualifying defect found in the targeted scope.

Blocking defects in this change: NO