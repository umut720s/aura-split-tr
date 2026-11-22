# Phase 3 independent review — Codex (gpt-6.1-sol), round 6

Run: 2026-11-22, read-only, after the round-5 fix pass. Verbatim final output (local paths redacted).

Read-only source review completed. No files modified, tests executed, elevation used, or installation performed.

| Requested item / open round-5 finding | Verdict and evidence |
|---|---|
| **1. `AURARECOVERED` escape hatch**; round-5 new #1 and outstanding WFP-cleanup bypass | **FIXED** — property and bypass removed. Missing EXE unconditionally refuses full uninstall: `installer/AuraSplitTR.wxs:323–324`; recovery remains checked: `:270`. |
| **2. AuraRecover rollback**; round-5 new #2 | **PARTIAL** — service state captured and restoration authored: `cmd/aurasplit/recover_state_windows.go:59`, `:113`; elevated hidden command: `cmd/aurasplit/main.go:147–158`. Previous WFP state is not captured; new defect below. |
| **3. RollbackDisabled upgrade/repair refusal**; round-5 new #3 | **FIXED** — guard precedes `InstallInitialize` and covers detected upgrades, `REINSTALL`, installed maintenance and full standalone uninstall: `installer/AuraSplitTR.wxs:321–322`. This follows [Microsoft’s RollbackDisabled guidance](https://learn.microsoft.com/en-us/windows/win32/msi/rollbackdisabled). |
| **4. Selected-egress IPv6 detection**; round-5 outstanding IPv6 finding | **FIXED** — `internal/engine/hostipv6.go:116–137` matches the pinned sing-tun monitor’s AF_INET filtering, metric sum and first-on-tie selection; `:151–172` requires IPv6 on that interface. Windows extraction: `hostipv6_windows.go:18`, `:50–54`. Compared directly against cached `sing-tun/monitor_windows.go:157–198` and `sing-box/route/network.go:351–363`. |
| **Upgrade rollback restoration**; round-5 outstanding item #3 | **PARTIAL** — transaction boundary remains corrected: `installer/AuraSplitTR.wxs:83`. New capture/rollback actions explicitly exclude `UPGRADINGPRODUCTCODE` and require full removal: `:325–328`; they do not establish restoration of the old service’s actual start/running state during failed upgrades. Live proof remains outstanding. |

Rollback-specific checks:

- **Trust/location:** `%ProgramData%\AuraSplitTR\recover-state.json`, resolved through Known Folder APIs (`internal/paths/base_windows.go:18–29`). Protected directory/file ACLs grant writes to SYSTEM/Administrators (`secure_windows.go:27–29`); untrusted records are quarantined (`:115`, `:154–157`). No standard-user record-forgery defect established.
- **Stale state:** save atomically replaces the fixed record before recovery (`recover_state_windows.go:79`; `secure_windows.go:831–840`). Records survive rollback without transaction identity or consumption, but the normal uninstall path requires another successful save before recovery; residual state alone does not demonstrate a Medium defect.
- **Ordering:** save → rollback marker → recover → `StopServices` → `RemoveFiles` (`AuraSplitTR.wxs:325–332`). Reverse execution places custom restoration after native service/file restoration. Data cleanup waits until commit (`:288–290`).

**New Medium defect — rollback enables protection that was previously disabled.**  
`cmd/aurasplit/recover_state_windows.go:16–20`, `:99–100`: the snapshot records no WFP state, and restoration reapplies policy whenever a valid profile exists. After `disable`/`recover`, the profile remains while the service is stopped/Disabled and policy absent. Cancel or fail a subsequent uninstall after recovery: rollback creates persistent blocks, then restores the stopped/Disabled service, leaving Discord blocked indefinitely. Conversely, previously present policy cannot be reconstructed through this path when the profile is missing. **Fix:** capture prior policy presence and the restoration data needed independently of profile availability; restore that captured state instead of inferring protection from profile existence.

Blocking defects for public BETA pending remaining live tests: YES

The new Medium rollback defect requires correction. Failed-upgrade service restoration remains unproven; MSI failure injection, partial-recovery rollback, rollback-disabled maintenance and network-transition tests remain release gates.