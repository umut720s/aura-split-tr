# Phase 3 independent review — Codex (gpt-6.1-sol), round 2

Run: 2026-11-22, read-only, after the round-1 fix pass. Verbatim final output (local paths redacted).

**Blocking defects remain: yes.** Most round-1 fixes are present, but disabled filters can now be counted as active protection, and the update coverage gap remains advertised too broadly.

I reviewed the current sources, round-1 report, relevant cached dependencies, Go runtime implementation, and Microsoft documentation. No files were modified, no elevated commands were run, and no tests or live WFP/service operations were performed. “FIXED” below means source-level correction, pending live validation.

**Round-1 findings**

| Finding | Status | Current evidence |
|---|---|---|
| **1. High — Go pointer transport through syscall wrapper** | **FIXED** | Typed bindings convert pointers directly inside `LazyProc.Call`: [fwpm_windows.go:272](internal/wfp/fwpm_windows.go:272), `:360`, `:384`. Union targets, blob backing storage and condition arrays are explicitly pinned: [marshal_windows.go:45](internal/wfp/marshal_windows.go:45), `:115`, `:127`. |
| **2. High — incomplete first discovery deletes persistent protection** | **FIXED** | Discovery errors select `AddOnly` in [guard.go:203](internal/wfp/guard.go:203) and [protect_windows.go:105](cmd/aurasplit/protect_windows.go:105). Deletion requires authoritative mode and no unresolved paths; existing recorded paths are retained: [policy.go:460](internal/wfp/policy.go:460), `:497`. |
| **3. High — App-ID failures remove protection and suppress retries** | **FIXED** | Resolution distinguishes missing from unresolved paths and returns `IncompleteError`: [policy.go:317](internal/wfp/policy.go:317), `:346`, `:533`. Incomplete guard passes bypass the unchanged-inventory shortcut: [guard.go:200](internal/wfp/guard.go:200), `:229`. |
| **4. High — future Discord versions lack exact-path protection** | **PARTIAL** | Watcher added; caps report incompleteness; all version directories are considered: [watch_windows.go:29](internal/wfp/watch_windows.go:29), [discover.go:62](internal/wfp/discover.go:62), `:125`, `:170`. Enforcement still requires reconciliation after creation. [ARCHITECTURE.md:106](ARCHITECTURE.md:106) acknowledges this, but [README.md:13](README.md:13) still promises unconditional fail-closed behavior. |
| **5. Medium — failed permit extension never retried** | **FIXED** | `permitDirty`, coverage comparison and shorter retries address the unchanged-inventory case: [guard.go:150](internal/wfp/guard.go:150), `:168`, `:200`, `:317`. A separate partial-replacement regression remains below. |
| **6. Medium — intentional stop timeout triggers SCM recovery** | **FIXED** | Disable precedes stop in [commands.go:287](cmd/aurasplit/commands.go:287), `:311`, `:339`. Requested stop timeout returns `(false, 0)`: [service_windows.go:433](internal/service/service_windows.go:433). Re-enable exists at [commands.go:223](cmd/aurasplit/commands.go:223). |
| **7. Medium — close timeout allows another TUN instance** | **FIXED** | Timeout is propagated from failed starts and prevents retry after fallback close: [engine.go:135](internal/engine/engine.go:135), `:401`, `:451`, `:463`. It becomes `service.ErrFatal`: [commands.go:572](cmd/aurasplit/commands.go:572); supervisor terminates at [service_windows.go:461](internal/service/service_windows.go:461). |
| **8. Medium — failed rollback deletes retained executable backup** | **FIXED** | Failed restoration sets `keepBackup`; cleanup preserves and reports the backup: [setup.go:157](cmd/aurasplit/setup.go:157), `:181`. |

The three additional round-1 issues:

| Issue | Status | Evidence |
|---|---|---|
| Disabled filters excluded from cleanup | **FIXED** | Include-disabled enumeration at [backend_windows.go:142](internal/wfp/backend_windows.go:142), [marshal_windows.go:89](internal/wfp/marshal_windows.go:89). Active-state handling has a new defect below. |
| Snapshot outside write transaction | **FIXED** | Enumeration and diff run inside `inTxn`: [policy.go:472](internal/wfp/policy.go:472), `:488`; removal likewise at `:594`. |
| Probe hostname resolved locally | **FIXED** | DNS server is an IP, queried through the WG dialer; HTTPS receives numeric destinations: [probe.go:123](internal/engine/probe.go:123), `:129`, `:182`; [engine.go:365](internal/engine/engine.go:365). WireGuard **endpoint** bootstrap resolution remains separate and local. |

**New defects in the fix paths**

1. **High — disabled filters satisfy reconciliation and protection status.**  
   **Location:** [marshal_windows.go:173](internal/wfp/marshal_windows.go:173), [policy.go:415](internal/wfp/policy.go:415), `:489`, `:642`.

   Enumeration now includes disabled filters, but `parseFilter` discards their disabled state. `diff` accepts a matching persistent key as present; `Apply` reports the requested path as covered, and `Installed` counts disabled blocks.

   **Scenario:** BFE returns a disabled persistent block. A restart/reconcile finds its deterministic key and leaves it untouched, then reports protection established although that block does not enforce anything.

   **Fix:** Preserve `Disabled` in `FilterRecord`; exclude disabled filters from active coverage/counts and transactionally recreate desired disabled filters. Never count key existence alone as active enforcement. Microsoft distinguishes disabled filters explicitly. Its conflicting service-name documentation still requires live verification; this finding does **not** assume that a nil service name necessarily disables these filters. [FWPM_FILTER0 documentation](https://learn.microsoft.com/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0).

2. **Medium — partial permit replacement removes previously working permits.**  
   **Location:** [guard.go:168](internal/wfp/guard.go:168), `:179–186`; [policy.go:582](internal/wfp/policy.go:582).

   **Scenario:** The old permit covers A. During extension for B, A’s App-ID resolution transiently fails. `PermitOnTunnel` returns a valid partial permit covering B plus `IncompleteError`. The guard installs it and closes the old session, so A loses its working permit and becomes blocked. Repeated failures prolong the outage.

   **Fix:** Retain old sessions until replacement coverage includes all previously permitted, still-relevant paths. Partial replacement may extend coverage without retiring the old coverage. The current retry test exercises a **nil** replacement, not this case.

3. **Medium — failed watches are never retried while target paths remain unchanged.**  
   **Location:** [watch.go:53](internal/wfp/watch.go:53), `:63`, `:97`; [watch_windows.go:32](internal/wfp/watch_windows.go:32), `:74`, `:82`.

   **Scenario:** Opening a watch fails transiently. `cur` still records that target, so refresh sees an unchanged target list and never retries. If only some opens fail, errors are returned only after cancellation and then suppressed by `wctx.Err() != nil`. A wait failure or dropped handle similarly leaves the outer watcher unaware.

   **Impact:** A directory silently loses prompt update detection until service restart or target-list change; the 60-second scan remains.

   **Fix:** Report per-target/group failures promptly, propagate watch termination, and retry failed or dropped targets with bounded backoff.

4. **Medium — discovery caps no longer bound persistent policy growth.**  
   **Location:** [discover.go:62](internal/wfp/discover.go:62), [policy.go:497](internal/wfp/policy.go:497), `:501`; [guard.go:211](internal/wfp/guard.go:211).

   **Scenario:** A user keeps old `app-*` executables and repeatedly creates newer versions. Each scan returns at most 256 paths, but previously installed blocks survive outside that set. Repeating this grows persistent filters and the permit baseline beyond 256 indefinitely—eight persistent filters per executable, plus dynamic permits.

   **Impact:** A non-admin user controlling their profile can force increasing LocalSystem/BFE work and persistent resource consumption. Actual exhaustion was not measured.

   **Fix:** Enforce a budget against the **existing-plus-proposed policy**, with per-profile accounting and explicit incomplete status when exhausted. Do not solve this by silently deleting existing protection.

5. **Low — DNS answer records are accepted without owner/class validation.**  
   **Location:** [probe.go:206](internal/engine/probe.go:206), `:228–240`.

   **Scenario:** A response echoes the correct transaction ID and question but contains an A/AAAA answer for an unrelated owner or non-IN class. The parser accepts its address and attempts HTTPS there. It also does not constrain opcode or question count.

   **Fix:** Require a standard response with one matching IN question; accept IN addresses only for the requested name or a validated CNAME chain.

   **Security limit:** This does not establish false `VERIFIED`: HTTPS still validates the original hostname, and an ordinary outside attacker cannot inject arbitrary authenticated WireGuard payloads. A hostile resolver/exit can already deny service. This is parser correctness and unnecessary-dial exposure, not a demonstrated TLS bypass.

**Requested checks without a confirmed defect**

- **Pinner:** Every `Pin` argument is a pointer. `&cp[0]` and `&conds[0]` pin their backing allocations; these are valid array-element pointers. Blob data and union pointees are pinned separately. Each backend operation has one deferred `Unpin`; no double-unpin path was found. These synchronous WFP calls do not require retaining caller buffers for the persistent filter/session lifetime. [Go Pinner contract](https://pkg.go.dev/runtime#Pinner).
- **Provider trust:** A public provider GUID alone does **not** let an ordinary unprivileged user plant filters. Adding requires filter-container `ADD` and `ADD_LINK` on the provider, layer and sublayer. Default WFP permissions also grant write capabilities to **Network Configuration Operators** and specified service identities; trust is therefore broader than “administrators only.” Actual host ACLs were not inspected. `providerData` is bounded UTF-8, but is not authenticated ownership evidence or validated path syntax. [WFP access control](https://learn.microsoft.com/en-us/windows/win32/fwp/access-control), [FwpmFilterAdd0 rights](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilteradd0).
- **Watcher handles:** Successful notification handles remain in the outer cleanup list, including handles dropped from wait groups; stop is signalled before joining and closing. No confirmed handle leak or intrinsic busy loop was found.
- **Mutex order:** Production paths acquire guard mutex → `lifecycleMu`; I found no reverse acquisition path. Callbacks run under the guard mutex, so re-entrant callbacks would be unsafe, but current callbacks do not re-enter it.
- **SCM:** `(true, 1)` correctly maps through cached `x/sys/windows/svc` to `ERROR_SERVICE_SPECIFIC_ERROR` plus service-specific code 1. `(false, 0)` is a clean requested stop. Recovery depends on the configured non-crash flag; Microsoft documents that changes to this flag take effect after system restart, so immediate post-install recovery remains a live-test requirement. [Failure-action semantics](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_failure_actions_flag).
- **Re-enable:** `start` changes Disabled → Automatic before starting. No permanent disable lockout was found; `restart` intentionally directs disabled users to `start`.

**Verdict: blocking defects remaining for a public BETA, pending live tests — YES.** Fix disabled-filter enforcement/status handling and align the public fail-closed promise with actual inventory coverage before treating live testing as the only remaining gate.