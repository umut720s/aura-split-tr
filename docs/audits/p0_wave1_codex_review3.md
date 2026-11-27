# P0 wave 1 — independent Codex (gpt-6.1-sol) re-review 3

Run: 2026-11-27, read-only. Verbatim final output (local paths redacted).

Read-only static review; no files modified, elevation, or test binaries executed.

1. **PARTIAL — retained noncanonical permits:** Canonical filtering is implemented at `internal/wfp/guard.go:279,452`, but failed closure is unsafe: `internal/wfp/backend_windows.go:70–71` discards the native handle even on error, and `internal/wfp/policy.go:692–693` discards the session. The next retry returns success without closing it, allowing readiness despite a potentially surviving legacy permit. Preserve handles/session references until closure succeeds.
2. **FIXED — unresolved orphan omission:** `internal/oldflow/gate.go:95–117` keeps unreadable pre-enrollment processes with unknown ancestry pending, including unfamiliar children whose parent disappeared.
3. **FIXED — stale enrollment cutoff:** `internal/oldflow/gate.go:47–60` retires absent generations; `internal/wfp/guard.go:344–347,398–399` invalidates cutoffs on observed coverage loss before repair.
4. **FIXED — basename/installer block-mode regression:** `internal/engine/config.go:364–372,389–394` restores both fallbacks with `wg`/`reject`; `internal/wfp/readiness.go:34` distinguishes them from verified coverage.
5. **FIXED — L1 baseline counted as leakage:** `tools/leaktest/capture.ps1:146` records activation; `tools/leaktest/analyze.py:650–651` excludes baseline from leak evaluation. This relies on operator confirmation.
6. **FIXED — PID-only relevance inheritance:** `internal/oldflow/gate.go:32–37,76,86` uses PID plus creation time; `internal/oldflow/source_windows.go:41–43` queries creation time independently of image-query success.

**NEW qualifying defect:**

- **Medium — remaining block-mode coverage regression:** `internal/engine/config.go:365` replaces the previous whole-install-directory routing regex with the narrow manifest. For example, `...\AppData\Local\Discord\app-1\DiscordOther.exe` previously received persistent enrollment and block-mode rejection; discovery now excludes it (`internal/wfp/discover.go:259`), and public IP-only traffic falls through to `direct` (`internal/engine/config.go:495`) on a fresh installation. Restore the broader routing/rejection fallback separately from destructive-action eligibility.

Blocking justification: failed permit closure can be forgotten, and previously rejected executable traffic can now route directly.
Blocking defects in this change: YES