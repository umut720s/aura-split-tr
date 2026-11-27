# P0 wave 1 — independent Codex (gpt-6.1-sol) re-review

Sonraki kod düzeltmeleri ve sınırlı doğrulama: [ikinci inceleme düzeltme kaydı](p0_wave1_review2_fixes.md). Aşağıdaki inceleme tarihsel kayıt olarak korunmuştur; canlı ağ kabulü değildir.

Run: 2026-11-27, read-only, after the fix pass. Verbatim final output (local paths redacted).

Read-only review of the diff and untracked files. No elevation, file changes, or test binaries executed; conclusions are static.

Previous six findings:

1. **PARTIAL — discovery/classification mismatch:** New discovery uses canonical manifest roots (`internal/wfp/discover.go:246`), but retained, previously enrolled noncanonical paths still receive tunnel permits (`internal/wfp/guard.go:363`) while classification excludes them (`internal/engine/config.go:360`). Their IP-only flows can still reach `direct`.
2. **FIXED — TCP tuple ownership race:** `SetTcpEntry` is absent; termination uses the handle whose image was verified (`internal/oldflow/source_windows.go:71–83`).
3. **FIXED — unrelated executable termination:** Destructive matching requires supported executable identity plus exact enrolled-path membership (`internal/manifest/manifest.go:49–56`); consent defaults to No (`cmd/aurasplit/readiness_windows.go:31`).
4. **PARTIAL — unresolved process omission:** Failures are preserved (`internal/oldflow/source_windows.go:48–50`), and known descendants remain pending. However, an inaccessible, unfamiliar child whose parent exited before the first snapshot has neither a heuristic match nor remembered ancestry and is ignored (`internal/oldflow/gate.go:52–68`).
5. **FIXED — analyzer protection heuristic:** Analysis consumes the exported regex, checks the embedded contract for equality, and prevents PASS on mismatch (`tools/leaktest/analyze.py:476–504`); export parity is asserted (`internal/manifest/manifest_test.go:9–14`).
6. **FIXED — capture requires existing TUN:** Physical recording starts before the activation instruction (`tools/leaktest/capture.ps1:128–135`); missing TUN evidence remains inconclusive (`tools/leaktest/analyze.py:536–537`).

New Critical/High/Medium defects:

- **High — stale enrollment cutoff:** `internal/oldflow/gate.go:44–47` retains each path’s first cutoff forever. Uninstall/prune, then reinstall the same path: a process started before renewed enrollment passes because it started after the original cutoff, despite possible surviving direct flows. **Fix:** associate cutoffs with verified enrollment generations and invalidate them when coverage is retired or lost.
- **High — block-mode coverage regression:** `internal/engine/config.go:358–360` removes default Discord basenames and the Downloads installer regex. Portable/per-machine Discord and `Downloads\DiscordSetup.exe` now fall through to `direct`, including in `ModeBlock`, for IP-only traffic previously rejected. **Fix:** retain those fallback routing/rejection rules separately from verified manifest coverage.
- **Medium — L1 baseline falsely counted as leakage:** `tools/leaktest/analyze.py:634–638` marks every protected physical packet throughout recording as a leak. The prescribed preactivation traffic therefore makes a correctly functioning L1 run FAIL. **Fix:** record a verified activation boundary; retain baseline evidence while evaluating leakage from that boundary.
- **Medium — PID reuse can indefinitely block readiness:** `internal/oldflow/gate.go:29,52–68` remembers relevance by PID alone. If a relevant process exits and its PID is reused between polls by an inaccessible unrelated process, readiness remains pending for that replacement’s lifetime. **Fix:** track creation-time identity and distinguish confirmed replacement from unresolved original identity.

Profile discovery uses HKLM ProfileList across users, rather than SYSTEM’s current-user directory (`internal/wfp/discover_windows.go:41–91`). Regex escaping and case-insensitive matching appear correct; consented termination does not reopen the process after handle verification.

Blocking defects in this change: YES — false readiness, residual classification gaps, and regressed block-mode coverage remain.
