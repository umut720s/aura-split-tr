# Phase 3 independent review — Codex (gpt-6.1-sol)

Run: 2026-11-22, read-only, `codex exec -m gpt-6.1-sol -s read-only`. Reviewed the tree before the post-review fix round. Verbatim final output below (local absolute paths redacted).

**Verdict: blocking defects remain.** The WFP arbitration design is plausible, but the current implementation cannot yet support an unconditional fail-closed claim.

I read the requested application sources, the cached sing-box v1.14.4/sing-tun sources, and Windows SDK **10.0.26100.0** headers. `go env GOMODCACHE` returned `<GOMODCACHE>`. No files were modified, no elevated commands were run, and no live networking/service tests were performed.

Paths below are relative to the repository unless otherwise stated.

1. **High — WFP syscall wrapper loses Go pointer guarantees**

   **Location:** [fwpm_windows.go:217](internal/wfp/fwpm_windows.go:217), [backend_windows.go:42](internal/wfp/backend_windows.go:42), `backend_windows.go:58,112,126,152,162,257`.

   **Root cause:** `fwpCall` accepts pointers already converted to `uintptr`, then calls `Find()` and `LazyProc.Call`. It lacks the compiler treatment provided by `//go:uintptrescapes` on `windows.LazyProc.Call`. Pointer conversion through this intermediate function does not preserve the original syscall expression’s guarantees.

   **Failure scenario:** Output cells such as `&h`, `&blob`, `&entries`, `&n`, and `&id` can remain on a movable Go stack. Stack growth inside the wrapper or lazy loading can leave the numeric address pointing at the old stack. Native code may then write through a stale address in the LocalSystem process. `KeepAlive(s)` does not pin `&h`; similarly, the `keep []any` comment does not establish that all objects escape to stable heap storage.

   **Fix:** Use typed bindings that retain pointer types until conversion directly in `LazyProc.Call`/the generated syscall. Explicitly retain and pin Go allocations referenced through the `uintptr` union fields where necessary. Do not treat `KeepAlive` alone as pinning.

   **Evidence:** Cached `x/sys/windows/dll_windows.go:305–316` explicitly marks `LazyProc.Call` with `//go:uintptrescapes`; this wrapper does not. Cached sing-tun generated bindings use typed parameters and direct syscall conversions. Go documents that `uintptr` neither retains nor follows moved objects and requires conversion in the recognized syscall expression. [Go unsafe pointer rules](https://pkg.go.dev/unsafe#Pointer). This is a source-level memory-safety defect; I did not reproduce native memory corruption.

2. **High — First reconciliation can delete persisted protection on incomplete discovery**

   **Location:** [guard.go:96](internal/wfp/guard.go:96), [protect_windows.go:81](cmd/aurasplit/protect_windows.go:81), `policy.go:349–370`.

   **Root cause:** On discovery error, `Reconcile` merges results with `g.paths`. A newly created guard has no previous paths, even when WFP contains a persistent policy from the previous process. `applyPolicyOnce` also calls `Apply(paths)` before returning the discovery error.

   **Failure scenario:** After a service restart, a transient profile-directory access failure produces an empty or partial discovery. `Apply` treats that as the complete desired set and transactionally deletes existing blocks for omitted executables. Those applications can subsequently connect directly when the TUN is unavailable.

   **Fix:** Incomplete discovery must never authorize deletions, including the first reconciliation and setup. Separate additive reconciliation from authoritative pruning, or preserve the existing persistent filters until a complete inventory succeeds.

   **Evidence:** `guard.go:100–104` preserves only this guard’s in-memory paths; `protect_windows.go:82–86` applies partial results regardless of `derr`; `policy.go:286–307` identifies every omitted persistent key for deletion.

3. **High — App-ID resolution failures silently remove protection and suppress retry**

   **Location:** [policy.go:214](internal/wfp/policy.go:214), `policy.go:328–349`, [guard.go:134](internal/wfp/guard.go:134).

   **Root cause:** `resolve` logs and skips every App-ID error, without returning failure. `Apply` then constructs the desired policy from the reduced set. The guard records the original paths as successfully applied.

   **Failure scenario:** Discord is discovered, but `FwpmGetAppIdFromFileName0` temporarily fails. Existing blocks for that executable are deleted, or new blocks are never created. The guard nevertheless sets `Applied=true`, clears its error, and saves the path. Subsequent scans with unchanged paths return at `guard.go:105`, so resolution is never retried.

   **Fix:** Propagate resolution failures. Preserve existing blocks for unresolved paths, report incomplete protection, and retry unresolved entries even when the path inventory is unchanged.

   **Evidence:** `policy.go:219–221` discards the error; `Apply` receives no indication of incompleteness; `guard.go:134–137` commits a successful status. This can produce a false `PROTECTION_ACTIVE` report as well as missing enforcement.

4. **High — Exact-path polling leaves normal Discord updates outside persistent protection**

   **Location:** [guard.go:14](internal/wfp/guard.go:14), [discover.go:96](internal/wfp/discover.go:96), `discover.go:138–139`, `policy.go:260–263`.

   **Root cause:** Protection covers only already-discovered executable paths. A new `app-*` directory is discovered at most once per minute while the guard runs. No discovery occurs while the service is stopped. Discovery caps also silently omit executable paths.

   **Failure scenario:** Discord’s updater launches a new version before the next scan. If the tunnel/service fails during that interval, the new executable has no persistent block and can use the physical interface. A previously staged update launched while the service is stopped remains uncovered indefinitely. Keeping only four versions can also remove protection from an older version that still exists or runs.

   **Fix:** An unconditional guarantee requires enforcement that covers future versions before their first connection. A directory watcher alone reduces latency but does not close that race. Until such enforcement exists, restrict the advertised guarantee to the verified executable inventory and explicitly surface coverage gaps.

   **Evidence:** Persistent keys include the exact App-ID; discovery is timer-driven; cap truncation is returned without an incompleteness error. This is an architectural limitation, not something a successful current-version live test would eliminate.

5. **Medium — Failed permit extension is never retried for an unchanged inventory**

   **Location:** [guard.go:105](internal/wfp/guard.go:105), `guard.go:111–138`.

   **Root cause:** If `PermitOnTunnel` fails during reconciliation, the guard still applies new blocks, saves the new inventory, clears `lastErr`, and returns success.

   **Failure scenario:** Discord updates; extending the permit fails once. The new executable receives a persistent block but no TUN permit. Later reconciliations immediately return because paths match. Discord stays blocked until a tunnel/service restart or another inventory change, while the status can show an open permit belonging only to the older inventory.

   **Fix:** Track the block and permit inventories separately. Preserve a permit-dirty/error state and retry permit installation independently of path changes.

   **Evidence:** The failure at lines 112–115 does not prevent lines 134–138; the next call exits at lines 105–106.

6. **Medium — Stop timeout can trigger recovery after `disable` or `recover`**

   **Location:** [service_windows.go:146](internal/service/service_windows.go:146), `service_windows.go:157,414–420`, [commands.go:256](cmd/aurasplit/commands.go:256), `commands.go:278–290`.

   **Root cause:** The service configures restart recovery, including non-crash failures. A requested stop that times out reports a nonzero exit code. `disable`/`recover` switch to **manual**, which does not prohibit a queued recovery start.

   **Failure scenario:** A stuck shutdown reaches the handler timeout. SCM observes Stopped, allowing the CLI to remove the policy and announce direct connectivity. The configured recovery action subsequently restarts the service and reinstalls blocking.

   **Fix:** Make intentional disable/recovery resistant to queued restarts—for example, transition to Disabled before stopping/removing policy, with an explicit re-enable path. Distinguish intentional stop timeout from recoverable operational failure.

   **Evidence:** Recovery delay is five seconds; timeout returns `ERROR_SERVICE_REQUEST_TIMEOUT`; `SetAutoStart(false)` selects `StartManual`. Microsoft documents that nonzero Stopped status queues configured failure actions when the flag is enabled. [Service failure-action flag](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_failure_actions_flag).

7. **Medium — Close timeout does not establish exclusive TUN ownership before retry**

   **Location:** [engine.go:162](internal/engine/engine.go:162), `engine.go:324,419–420`.

   **Root cause:** `closeBounded` leaves `Close` running after timeout. Retry paths ignore the close error and start another instance using the same interface and routing resources.

   **Failure scenario:** A fallback close hangs beyond ten seconds. The next tunnel starts while the old instance remains alive. The old close can later continue removing shared routes/interface resources after the replacement starts. Repeated timeouts can also accumulate close goroutines and instances.

   **Fix:** Treat close timeout as terminal for that service process; do not reuse shared TUN resources without proving the previous instance has released ownership. Let process exit and supervision establish a clean boundary.

   **Evidence:** The timeout only ends the caller’s wait; it does not cancel or terminate the closer. The comment acknowledges background execution, but the retry path continues in the same process.

8. **Medium — Failed executable rollback deletes the retained backup**

   **Location:** [setup.go:152](cmd/aurasplit/setup.go:152), `setup.go:159–167`.

   **Root cause:** The deferred cleanup removes `backup` whenever it remains nonempty. A failed rollback leaves precisely that condition.

   **Failure scenario:** Installing the new binary succeeds, a later setup step fails, and restoring the previous executable fails because of sharing/access interference. Setup reports the restore failure, then deletes the backup containing the previous working binary.

   **Fix:** Preserve the backup after failed restoration and print its recovery location. Remove it only after successful installation or successful rollback.

   **Evidence:** Failed `ReplaceFile` does not clear `backup`; the unconditional defer subsequently calls `os.Remove(backup)`.

The specifically requested WFP and probe checks produced these additional conclusions:

- **amd64 structure layouts:** I found no field-layout mismatch against the installed SDK declarations. `FWPM_FILTER0` is 200 bytes, with `action` at 128, context union at 152, `filterId` at 176, and effective weight at 184. Condition/value/blob/session/sublayer/provider/enum-template layouts also match. DWORD handling and amd64 argument shapes appear correct. **Finding 1 concerns Go pointer transport, not C structure offsets.**
- **App-ID ownership:** `AppID` copies the native blob and defers `FwpmFreeMemory0` correctly. `AddFilter` retains the copied blob/data through `KeepAlive`; however, the pointer-pinning problem in finding 1 prevents declaring the complete lifetime handling safe.
- **Weights and session lifetime:** `FWP_UINT8` values are weight-range indices, not literal 64-bit weights. Distinct ranges 15/10/1 still establish the intended ordering. Persistent objects use a non-dynamic session; tunnel permits use a dynamic session without the persistent flag. [Microsoft weight semantics](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0).
- **sing-tun arbitration:** Cached `sing-tun/tun_windows.go:234–237` uses sublayer weight `0xFFFF`. Its TUN permits at lines 367–392 **do not set** `CLEAR_ACTION_RIGHT`; its own-process permits at lines 256–280 **do set it**. Therefore, ordinary Discord TUN traffic receives a soft permit, which AURA’s lower sublayer can block. A higher-priority hard permit would defeat an ordinary lower-sublayer block; “BLOCK always wins” is not generally true. The actual Discord path is compatible with the intended design. [Microsoft arbitration rules](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration).
- **Enumeration/reconciliation:** Provider restriction and action mask are correct, but enumeration excludes disabled filters, and snapshots are taken before the write transaction. Consequently, cleanup is not literally “every provider filter,” and concurrent lifecycle operations are not serialized. Include disabled filters for cleanup and move snapshot/diff work inside the transaction.
- **Provider without service name:** Microsoft’s *Object Management* page supports the current choice, while its provider/filter structure pages contain contradictory wording. I would **not** classify the nil service name as a confirmed defect from those documents alone. Reboot/BFE restart enforcement needs direct verification. [Object lifetime rules](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management).
- **Probe:** The HTTPS connection goes through `wg` → the WireGuard endpoint’s userspace stack, without a direct TCP fallback. Default TLS validation and redirect refusal prevent an ordinary hostile network from fabricating VERIFIED. **DNS is an exception to “wg only”:** sing-box `protocol/wireguard/endpoint.go:287` resolves the probe hostname through the DNS router, and AURA’s default DNS final is local. The probe hostname can therefore reach the local resolver. The result proves endpoint connectivity, not Discord classification or WFP enforcement.

**Final verdict:** The arbitration strategy is plausibly correct, but the implementation has blocking memory-safety and fail-open coverage defects—particularly findings **1–4**. It needs code corrections before it can reasonably be described as correct pending live testing. No Critical exploit was established in this read-only review.
**Verdict: blocking defects remain.** The WFP arbitration design is plausible, but the current implementation cannot yet support an unconditional fail-closed claim.

I read the requested application sources, the cached sing-box v1.14.4/sing-tun sources, and Windows SDK **10.0.26100.0** headers. `go env GOMODCACHE` returned `<GOMODCACHE>`. No files were modified, no elevated commands were run, and no live networking/service tests were performed.

Paths below are relative to the repository unless otherwise stated.

1. **High — WFP syscall wrapper loses Go pointer guarantees**

   **Location:** [fwpm_windows.go:217](internal/wfp/fwpm_windows.go:217), [backend_windows.go:42](internal/wfp/backend_windows.go:42), `backend_windows.go:58,112,126,152,162,257`.

   **Root cause:** `fwpCall` accepts pointers already converted to `uintptr`, then calls `Find()` and `LazyProc.Call`. It lacks the compiler treatment provided by `//go:uintptrescapes` on `windows.LazyProc.Call`. Pointer conversion through this intermediate function does not preserve the original syscall expression’s guarantees.

   **Failure scenario:** Output cells such as `&h`, `&blob`, `&entries`, `&n`, and `&id` can remain on a movable Go stack. Stack growth inside the wrapper or lazy loading can leave the numeric address pointing at the old stack. Native code may then write through a stale address in the LocalSystem process. `KeepAlive(s)` does not pin `&h`; similarly, the `keep []any` comment does not establish that all objects escape to stable heap storage.

   **Fix:** Use typed bindings that retain pointer types until conversion directly in `LazyProc.Call`/the generated syscall. Explicitly retain and pin Go allocations referenced through the `uintptr` union fields where necessary. Do not treat `KeepAlive` alone as pinning.

   **Evidence:** Cached `x/sys/windows/dll_windows.go:305–316` explicitly marks `LazyProc.Call` with `//go:uintptrescapes`; this wrapper does not. Cached sing-tun generated bindings use typed parameters and direct syscall conversions. Go documents that `uintptr` neither retains nor follows moved objects and requires conversion in the recognized syscall expression. [Go unsafe pointer rules](https://pkg.go.dev/unsafe#Pointer). This is a source-level memory-safety defect; I did not reproduce native memory corruption.

2. **High — First reconciliation can delete persisted protection on incomplete discovery**

   **Location:** [guard.go:96](internal/wfp/guard.go:96), [protect_windows.go:81](cmd/aurasplit/protect_windows.go:81), `policy.go:349–370`.

   **Root cause:** On discovery error, `Reconcile` merges results with `g.paths`. A newly created guard has no previous paths, even when WFP contains a persistent policy from the previous process. `applyPolicyOnce` also calls `Apply(paths)` before returning the discovery error.

   **Failure scenario:** After a service restart, a transient profile-directory access failure produces an empty or partial discovery. `Apply` treats that as the complete desired set and transactionally deletes existing blocks for omitted executables. Those applications can subsequently connect directly when the TUN is unavailable.

   **Fix:** Incomplete discovery must never authorize deletions, including the first reconciliation and setup. Separate additive reconciliation from authoritative pruning, or preserve the existing persistent filters until a complete inventory succeeds.

   **Evidence:** `guard.go:100–104` preserves only this guard’s in-memory paths; `protect_windows.go:82–86` applies partial results regardless of `derr`; `policy.go:286–307` identifies every omitted persistent key for deletion.

3. **High — App-ID resolution failures silently remove protection and suppress retry**

   **Location:** [policy.go:214](internal/wfp/policy.go:214), `policy.go:328–349`, [guard.go:134](internal/wfp/guard.go:134).

   **Root cause:** `resolve` logs and skips every App-ID error, without returning failure. `Apply` then constructs the desired policy from the reduced set. The guard records the original paths as successfully applied.

   **Failure scenario:** Discord is discovered, but `FwpmGetAppIdFromFileName0` temporarily fails. Existing blocks for that executable are deleted, or new blocks are never created. The guard nevertheless sets `Applied=true`, clears its error, and saves the path. Subsequent scans with unchanged paths return at `guard.go:105`, so resolution is never retried.

   **Fix:** Propagate resolution failures. Preserve existing blocks for unresolved paths, report incomplete protection, and retry unresolved entries even when the path inventory is unchanged.

   **Evidence:** `policy.go:219–221` discards the error; `Apply` receives no indication of incompleteness; `guard.go:134–137` commits a successful status. This can produce a false `PROTECTION_ACTIVE` report as well as missing enforcement.

4. **High — Exact-path polling leaves normal Discord updates outside persistent protection**

   **Location:** [guard.go:14](internal/wfp/guard.go:14), [discover.go:96](internal/wfp/discover.go:96), `discover.go:138–139`, `policy.go:260–263`.

   **Root cause:** Protection covers only already-discovered executable paths. A new `app-*` directory is discovered at most once per minute while the guard runs. No discovery occurs while the service is stopped. Discovery caps also silently omit executable paths.

   **Failure scenario:** Discord’s updater launches a new version before the next scan. If the tunnel/service fails during that interval, the new executable has no persistent block and can use the physical interface. A previously staged update launched while the service is stopped remains uncovered indefinitely. Keeping only four versions can also remove protection from an older version that still exists or runs.

   **Fix:** An unconditional guarantee requires enforcement that covers future versions before their first connection. A directory watcher alone reduces latency but does not close that race. Until such enforcement exists, restrict the advertised guarantee to the verified executable inventory and explicitly surface coverage gaps.

   **Evidence:** Persistent keys include the exact App-ID; discovery is timer-driven; cap truncation is returned without an incompleteness error. This is an architectural limitation, not something a successful current-version live test would eliminate.

5. **Medium — Failed permit extension is never retried for an unchanged inventory**

   **Location:** [guard.go:105](internal/wfp/guard.go:105), `guard.go:111–138`.

   **Root cause:** If `PermitOnTunnel` fails during reconciliation, the guard still applies new blocks, saves the new inventory, clears `lastErr`, and returns success.

   **Failure scenario:** Discord updates; extending the permit fails once. The new executable receives a persistent block but no TUN permit. Later reconciliations immediately return because paths match. Discord stays blocked until a tunnel/service restart or another inventory change, while the status can show an open permit belonging only to the older inventory.

   **Fix:** Track the block and permit inventories separately. Preserve a permit-dirty/error state and retry permit installation independently of path changes.

   **Evidence:** The failure at lines 112–115 does not prevent lines 134–138; the next call exits at lines 105–106.

6. **Medium — Stop timeout can trigger recovery after `disable` or `recover`**

   **Location:** [service_windows.go:146](internal/service/service_windows.go:146), `service_windows.go:157,414–420`, [commands.go:256](cmd/aurasplit/commands.go:256), `commands.go:278–290`.

   **Root cause:** The service configures restart recovery, including non-crash failures. A requested stop that times out reports a nonzero exit code. `disable`/`recover` switch to **manual**, which does not prohibit a queued recovery start.

   **Failure scenario:** A stuck shutdown reaches the handler timeout. SCM observes Stopped, allowing the CLI to remove the policy and announce direct connectivity. The configured recovery action subsequently restarts the service and reinstalls blocking.

   **Fix:** Make intentional disable/recovery resistant to queued restarts—for example, transition to Disabled before stopping/removing policy, with an explicit re-enable path. Distinguish intentional stop timeout from recoverable operational failure.

   **Evidence:** Recovery delay is five seconds; timeout returns `ERROR_SERVICE_REQUEST_TIMEOUT`; `SetAutoStart(false)` selects `StartManual`. Microsoft documents that nonzero Stopped status queues configured failure actions when the flag is enabled. [Service failure-action flag](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_failure_actions_flag).

7. **Medium — Close timeout does not establish exclusive TUN ownership before retry**

   **Location:** [engine.go:162](internal/engine/engine.go:162), `engine.go:324,419–420`.

   **Root cause:** `closeBounded` leaves `Close` running after timeout. Retry paths ignore the close error and start another instance using the same interface and routing resources.

   **Failure scenario:** A fallback close hangs beyond ten seconds. The next tunnel starts while the old instance remains alive. The old close can later continue removing shared routes/interface resources after the replacement starts. Repeated timeouts can also accumulate close goroutines and instances.

   **Fix:** Treat close timeout as terminal for that service process; do not reuse shared TUN resources without proving the previous instance has released ownership. Let process exit and supervision establish a clean boundary.

   **Evidence:** The timeout only ends the caller’s wait; it does not cancel or terminate the closer. The comment acknowledges background execution, but the retry path continues in the same process.

8. **Medium — Failed executable rollback deletes the retained backup**

   **Location:** [setup.go:152](cmd/aurasplit/setup.go:152), `setup.go:159–167`.

   **Root cause:** The deferred cleanup removes `backup` whenever it remains nonempty. A failed rollback leaves precisely that condition.

   **Failure scenario:** Installing the new binary succeeds, a later setup step fails, and restoring the previous executable fails because of sharing/access interference. Setup reports the restore failure, then deletes the backup containing the previous working binary.

   **Fix:** Preserve the backup after failed restoration and print its recovery location. Remove it only after successful installation or successful rollback.

   **Evidence:** Failed `ReplaceFile` does not clear `backup`; the unconditional defer subsequently calls `os.Remove(backup)`.

The specifically requested WFP and probe checks produced these additional conclusions:

- **amd64 structure layouts:** I found no field-layout mismatch against the installed SDK declarations. `FWPM_FILTER0` is 200 bytes, with `action` at 128, context union at 152, `filterId` at 176, and effective weight at 184. Condition/value/blob/session/sublayer/provider/enum-template layouts also match. DWORD handling and amd64 argument shapes appear correct. **Finding 1 concerns Go pointer transport, not C structure offsets.**
- **App-ID ownership:** `AppID` copies the native blob and defers `FwpmFreeMemory0` correctly. `AddFilter` retains the copied blob/data through `KeepAlive`; however, the pointer-pinning problem in finding 1 prevents declaring the complete lifetime handling safe.
- **Weights and session lifetime:** `FWP_UINT8` values are weight-range indices, not literal 64-bit weights. Distinct ranges 15/10/1 still establish the intended ordering. Persistent objects use a non-dynamic session; tunnel permits use a dynamic session without the persistent flag. [Microsoft weight semantics](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0).
- **sing-tun arbitration:** Cached `sing-tun/tun_windows.go:234–237` uses sublayer weight `0xFFFF`. Its TUN permits at lines 367–392 **do not set** `CLEAR_ACTION_RIGHT`; its own-process permits at lines 256–280 **do set it**. Therefore, ordinary Discord TUN traffic receives a soft permit, which AURA’s lower sublayer can block. A higher-priority hard permit would defeat an ordinary lower-sublayer block; “BLOCK always wins” is not generally true. The actual Discord path is compatible with the intended design. [Microsoft arbitration rules](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration).
- **Enumeration/reconciliation:** Provider restriction and action mask are correct, but enumeration excludes disabled filters, and snapshots are taken before the write transaction. Consequently, cleanup is not literally “every provider filter,” and concurrent lifecycle operations are not serialized. Include disabled filters for cleanup and move snapshot/diff work inside the transaction.
- **Provider without service name:** Microsoft’s *Object Management* page supports the current choice, while its provider/filter structure pages contain contradictory wording. I would **not** classify the nil service name as a confirmed defect from those documents alone. Reboot/BFE restart enforcement needs direct verification. [Object lifetime rules](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management).
- **Probe:** The HTTPS connection goes through `wg` → the WireGuard endpoint’s userspace stack, without a direct TCP fallback. Default TLS validation and redirect refusal prevent an ordinary hostile network from fabricating VERIFIED. **DNS is an exception to “wg only”:** sing-box `protocol/wireguard/endpoint.go:287` resolves the probe hostname through the DNS router, and AURA’s default DNS final is local. The probe hostname can therefore reach the local resolver. The result proves endpoint connectivity, not Discord classification or WFP enforcement.

**Final verdict:** The arbitration strategy is plausibly correct, but the implementation has blocking memory-safety and fail-open coverage defects—particularly findings **1–4**. It needs code corrections before it can reasonably be described as correct pending live testing. No Critical exploit was established in this read-only review.