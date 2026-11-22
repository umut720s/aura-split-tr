# Phase 3 independent review — Codex (gpt-6.1-sol), round 4

Run: 2026-11-22, read-only, after live testing (Bugs 1-3) and the MSI move. Verbatim final output (local paths redacted).

Read-only review completed against the current code and cached sing-box v1.14.4 source. No files changed, tests executed, elevated commands, or installations.

1. **High — Untrusted ProgramData cleanup has a junction-swap window.** `installer/AuraSplitTR.wxs:217`  
   **Scenario:** MSI installation does not create or secure the data directory. Before setup ever runs, a standard user can create `%ProgramData%\AuraSplitTR`. WiX 5.0.2 rejects an already-present junction, but checks attributes and enumerates paths before adding pathname-based `RemoveFile` rows; it holds no handle preventing replacement. An attacker-controlled directory can therefore be swapped after inspection, exposing SYSTEM cleanup to redirected paths. This is a source-level race finding; exploitation was not demonstrated.  
   **Fix:** Remove recursive MSI cleanup of an untrusted tree. Validate ownership and reparse status through no-follow handles, prevent replacement during deletion, and leave untrusted directories for manual inspection. A one-time junction check is insufficient. [Pinned WiX cleanup source](https://raw.githubusercontent.com/wixtoolset/wix/v5.0.2/src/ext/Util/ca/RemoveFoldersEx.cpp).

2. **Medium — Uninstall can report success while leaving persistent Discord blocks.** `installer/AuraSplitTR.wxs:242`, `cmd/aurasplit/commands.go:365`  
   **Scenario:** `recover --msi` fails to remove WFP policy—or cannot execute because antivirus quarantined the executable. `Return="ignore"` still permits removal of the service, executable, and profile. Discord remains blocked after an apparently successful uninstall.  
   **Fix:** Require successful policy removal before deleting the recovery executable; propagate cleanup failure and retain a usable recovery path.

3. **Medium — Failed upgrades can remove the working installation permanently.** `installer/AuraSplitTR.wxs:68`  
   **Scenario:** The default `MajorUpgrade` schedule removes the old product after `InstallValidate`, outside rollback protection. If installation subsequently fails, the old service/executable are not restored, while persistent WFP blocks deliberately survive the upgrade removal.  
   **Fix:** Use `Schedule="afterInstallInitialize"` and provide rollback restoration of the prior service’s running/start state. Verify with an injected failure after old-product removal. [WiX scheduling documentation](https://docs.firegiant.com/wix/schema/wxs/majorupgrade/).

4. **Medium — Endpoint resolution failure silently restores the problematic WARP path; pinned addresses cannot refresh during degradation.** `internal/engine/config.go:299`, `internal/engine/engine.go:373`  
   **Scenario:** Boot-time DNS lookup fails, so configuration retains the hostname and selects ClientBind’s unconnected socket path—the path implicated in Bug 3. Endpoint startup does not require a successful handshake, and `serve` waits for cancellation; connectivity failures do not rebuild configuration. Similarly, a successfully resolved address that later stops working stays pinned indefinitely. Sing-box’s interface-change handling updates the bind, not this literal peer address.  
   **Fix:** Treat failed endpoint pre-resolution as a retryable preparation error. Add bounded re-resolution/rebuild after sustained connectivity failure or relevant network changes, preserving WFP protection throughout.

5. **Medium — IPv6 detection does not establish usable IPv6 on the selected egress.** `internal/engine/hostipv6.go:51`, `internal/engine/hostipv6.go:72`  
   **Scenario:** Ethernet is IPv4-only, but another up adapter has a global IPv6 address—for example a virtual adapter or a secondary interface without a working default route. Detection returns true, enabling the TUN IPv6 route and disabling global AAAA suppression, potentially reproducing the browser outage. A subsequent IPv6-to-IPv4 network transition leaves the same configuration active.  
   **Fix:** Base capability on the actual outbound interface and usable IPv6 route/address state; rebuild when that capability changes.

6. **Low — The saturation test does not reliably reproduce the round-3 defect.** `internal/wfp/wfp_watch_test.go:136`  
   **Scenario:** Generation 1 floods failures, then waits for cancellation. The consumer normally drains those reports during the retry backoff before generation 2 starts. The test neither changes targets nor forces a full obsolete queue at the generation boundary, so the pre-fix implementation can also pass.  
   **Fix:** Coordinate cancellation/target replacement and enqueue the old generation’s flood while `start()` is joining it; make the replacement terminate immediately. Require the test to fail when the drain is removed.

Other requested checks:

- **A:** The production drain at `watch.go:104–116` fixes the reported race: the Windows watcher joins its reporting goroutines before returning.
- **B:** The detour selects ClientBind. Its direct outbound retains `auto_detect_interface` socket binding; I found no newly introduced TUN routing loop for ordinary external peers. Sing-tun’s application-ID hard permits still cover AURA sockets. WARP reserved bytes, keepalive, and configured WireGuard MTU survive this path.
- **DNS:** Global empty AAAA answers precede Discord rules only when host IPv6 detection is false; they perform no upstream lookup. IPv6-capable hosts retain Discord-specific handling. Initial peer resolution occurs before this instance starts its TUN; retry preparation occurs while fallback is active. Sing-box’s local resolver excludes its own TUN DNS interface and uses bound outbound sockets, so I found no inherent recursive DNS loop.
- **C:** Deferred, non-impersonated QuietExec actions and executable quoting are correct. The full-uninstall condition excludes upgrade removal. Install ACL and service definition match the CLI checks; no self-copy/service-registration implementation remains. Lower MSI version triples are blocked; equal-version replacement intentionally permits older builds sharing that triple.
- **Signing/workflows:** No fabricated signature path found. Configured PFX signing checks signing and verification failures, removes the temporary PFX, and precedes final hashes/attestation. CI receives no signing secrets. The release job does not itself declare the protected signing environment suggested by its comments; configure that before enabling signing.

**Blocking defects for public BETA pending remaining live tests: YES**

The uninstall trust-boundary race, ignored WFP cleanup failures, non-rollback-safe upgrade removal, and endpoint recovery gap require source corrections independently of the remaining live tests. The watcher’s production correction is sound, but its regression test needs stronger coordination. Successful reported MSI/WARP runs do not exercise these failure scenarios; remaining boot, reconnection, rollback, and packet-capture tests are still release gates.