# Phase 3 independent review — Codex (gpt-6.1-sol), round 3

Run: 2026-11-22, read-only, after the round-2 fix pass. Verbatim final output (local paths redacted).

Read-only source review completed. No files changed, tests executed, elevated commands, or live WFP operations. **FIXED means source-level correction, pending live validation.**

| Round-2 item | Status | Evidence |
|---|---|---|
| 1. High — disabled filters counted as active | **FIXED** | Disabled state preserved in `internal/wfp/marshal_windows.go:176`; reconciliation recreates disabled matches in `policy.go:483` and `:651`; coverage/counts exclude them at `:635` and `:797`. |
| 2. Medium — partial permit replacement | **FIXED** | `internal/wfp/guard.go:242–265` retains old sessions until remaining sessions cover their still-relevant paths; excess replacement sessions are discarded while preserving existing coverage. |
| 3. Medium — watcher retry | **PARTIAL** | Prompt failure reporting and bounded retries exist in `internal/wfp/watch_windows.go:43–46`, `:113–127`, and `watch.go:151–174`, but the new failure queue can lose the retry signal; see below. |
| 4. Medium — policy growth budget | **FIXED** | `internal/wfp/policy.go:594–607` counts retained persistent blocks before admitting additions, enforcing global/per-profile limits. Excess paths produce incomplete status at `:675–676`; dynamic permits are bounded at `:709–717`. |
| 5. Low — probe DNS validation | **FIXED** | `internal/engine/probe.go:230–240` validates response/opcode and exactly one matching IN question; `:285–307` restricts addresses to matching IN records along a bounded CNAME chain. |
| README fail-closed promise | **FIXED** | `README.md:13–18`, `:156–175`, and `:259–277` explicitly qualify inventory coverage, update races, budget exclusions, browser/DNS limitations, and unverified live behavior. |

**New Medium defect — watcher restart can permanently lose failure reporting.** `internal/wfp/watch.go:82–87`, `:101–123`, `:151–159`, `:191–194`: the shared 64-entry failure queue drops reports when full, but queued reports can belong to an obsolete generation. If a target-list restart occurs before those failures are consumed, the new watcher can fail while the queue remains full, losing every current-generation failure—including its termination report. The loop subsequently discards the old-generation reports without scheduling a retry; unchanged targets then leave the watcher dead indefinitely. The periodic discovery scan remains. Make retry notification reliable per generation, or drain obsolete reports after joining the old watcher and before starting its replacement.

No additional Critical/High defects identified in the reviewed paths.

**Blocking defects for public BETA pending live tests: YES**

The watcher retry correction still has a source-level failure path that silently restores the round-2 loss of prompt update detection until targets change or the service restarts. Its existing tests cover individual failures and termination, but not queue saturation across generations. Correct that retry-signalling gap before treating live testing as the sole remaining release gate; actual WFP enforcement, boot/crash behavior, and tunnel integration remain unvalidated by this review.