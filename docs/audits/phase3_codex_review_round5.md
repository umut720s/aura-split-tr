# Phase 3 independent review — Codex (gpt-6.1-sol), round 5

Run: 2026-11-22, read-only, after the round-4 fix pass. Historical review output (local paths and the removed recovery-property name redacted).

Read-only source review completed. No files changed, tests run, installations performed, or elevated commands executed. **No new Critical/High defects found; three new Medium defects found.**

| Round-4 item | Verdict | Evidence |
|---|---|---|
| **1. ProgramData cleanup race** | **FIXED** | [cleanup_windows.go:107](/internal/paths/cleanup_windows.go:107) holds the inspected directory without delete sharing. Children are opened relative to that handle, checked, retained, and deleted through those same handles: `:152`, `:176`, `:210`, `:239`. The recursive pathname-based MSI cleanup is gone. |
| **2. Ignored WFP cleanup failure** | **PARTIAL** | [AuraSplitTR.wxs:261](/installer/AuraSplitTR.wxs:261) now uses `Return="check"`; [commands.go:375](/cmd/aurasplit/commands.go:375) propagates removal/stop failures. However, the missing-EXE escape hatch permits uninstall without verifying cleanup—new finding 1 below. |
| **3. MajorUpgrade outside rollback** | **PARTIAL** | [AuraSplitTR.wxs:83](/installer/AuraSplitTR.wxs:83) fixes the transaction boundary. `AuraResume` at `:314` handles successful commit only. Restoration of the previous service’s actual start/running state remains unproven; no explicit rollback restoration is authored. This is an outstanding acceptance-proof gap, not a demonstrated failure of native MSI rollback. |
| **4. Endpoint resolution/refresh** | **FIXED** | [config.go:275](/internal/engine/config.go:275) rejects failed strict resolution. [engine.go:462](/internal/engine/engine.go:462) triggers rebuilding after disconnection; `:486` handles IPv6 capability changes; `:527` enforces the rebuild interval. Preparation failure retains the existing tunnel. |
| **5. IPv6 detection** | **PARTIAL** | [hostipv6.go:100](/internal/engine/hostipv6.go:100) now requires an address and default route on the same interface, and changes trigger rebuilding. It still accepts **any** eligible interface, rather than the interface actually selected by sing-box. See explanation below. |
| **6. Watcher regression test** | **FIXED** | [wfp_watch_test.go:160](/internal/wfp/wfp_watch_test.go:160) floods during cancellation/join and holds the consumer until generation 2 reports its failure. This now creates the intended full obsolete queue at the generation boundary. Mutation testing was not executed. |

The remaining **Medium** IPv6 defect is concrete: Ethernet can be the selected IPv4 egress while another up adapter has a global IPv6 address and `::/0`. Detection returns true, enabling TUN IPv6 and AAAA answers, although direct sockets bind to Ethernet. The cached, pinned sing-tun implementation selects its default interface from **AF_INET** routes (`monitor_windows.go:157–198`); sing-box binds ordinary external destinations to that interface (`route/network.go:351–363`). The new monitor also sees no capability change while the unrelated adapter remains eligible. Detection must agree with the actual outbound interface, or outbound selection must become family-aware.

**New Medium defects**

1. **The “administrator” escape hatch trusts a client-controlled property.**  
   [AuraSplitTR.wxs:236](/installer/AuraSplitTR.wxs:236), `:323`, `:325`, `:327`.

   With the EXE absent, supplying any nonempty the former client-supplied recovery property bypasses `AuraExeMissing`; both cleanup actions are then skipped because `AURAEXEFOUND` is false. Nothing verifies that WFP policy was actually removed. Uninstall can therefore succeed while retaining persistent blocks.

   **Yes, a standard-user client can supply this property to an otherwise authorized elevated uninstall.** WiX `Secure="yes"` adds it to `SecureCustomProperties`, expressly permitting client-to-server propagation under restricted elevated installation rules. It does not authenticate the supplier or establish administrator approval of the assertion. This property grants no independent elevation; normal uninstall authorization still applies. [WiX Property documentation](https://docs.firegiant.com/wix/schema/wxs/property/), [Microsoft SecureCustomProperties](https://learn.microsoft.com/en-us/windows/win32/msi/securecustomproperties).

   **Fix:** Verify policy absence in trusted elevated code independently of this assertion before permitting removal.

2. **A failed uninstall leaves custom recovery changes outside rollback.**  
   [commands.go:379](/cmd/aurasplit/commands.go:379), `:382`, `:390`; [AuraSplitTR.wxs:324](/installer/AuraSplitTR.wxs:324).

   `AuraRecover` disables and stops the service **before** MSI `StopServices`. If WFP removal then fails, `Return="check"` aborts the uninstall, but there is no rollback action restoring those CLI changes. The executable remains, yet a formerly working installation can remain stopped/Disabled with its persistent blocks intact—even after reboot.

   **Fix:** Capture the preceding service state and author a rollback action before recovery that restores it, including protection when recovery had already removed policy. Direct system changes made by custom actions require corresponding rollback authoring. [Microsoft rollback guidance](https://learn.microsoft.com/en-us/windows/win32/msi/rollback-custom-actions).

3. **Rollback-disabled upgrades skip the only service-resume action.**  
   [AuraSplitTR.wxs:156](/installer/AuraSplitTR.wxs:156), `:186`, `:314`, `:328`.

   An upgrade stops/reinstalls the configured service as demand-start while retaining persistent blocks. With rollback disabled, Windows Installer skips `AuraResume` because it is a commit action. The upgrade nevertheless succeeds, leaving the service stopped and Discord blocked; automatic recovery at reboot is also lost.

   **Fix:** Reject this upgrade/repair mode using `RollbackDisabled`, or provide a supported resume path that executes in that mode. Documentation requiring manual `start` does not preserve the upgrade’s previous behavior. [Microsoft commit-action semantics](https://learn.microsoft.com/en-us/windows/win32/msi/commit-custom-actions).

Other requested checks:

- **CleanDataDir:** Handle-relative names, `OBJECT_ATTRIBUTES.Length`, synchronous access/options, directory-record offsets, and handle-based disposition are consistent. Inspection errors preserve data. `checkAncestors` remains pathname-based, so it is not a general ancestor-race solution; I found no standard-user exploit against the normal protected ProgramData ancestor chain.
- **Commit identity:** `Execute="commit"` plus `Impersonate="no"` correctly requests system context. Commit execution itself is valid; its rollback-disabled omission is the defect above. [Microsoft execution flags](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-in-script-execution-options).
- **Rebuild/WFP ordering:** Replacement preparation precedes permit closure; permit closure precedes old-tunnel closure; the replacement starts before its new permit opens. Close timeout prevents starting a competing instance. No new ordering defect established.
- **IP Helper ABI/free:** The code uses pinned x/sys structures with the required x64 alignment. IPv6 address/route extraction is consistent, results are copied before freeing, and both successful table allocations have deferred `FreeMibTable`. No layout, premature-free, or double-free defect found.

**Blocking defects for public BETA pending remaining live tests: YES**

The selected-egress IPv6 mismatch and the three Medium lifecycle defects need correction independently of live testing. Upgrade rollback still needs evidence that the previous service configuration and running state return. Remaining MSI failure injection, missing-EXE/property propagation, rollback-disabled upgrade, network-transition/reconnection, and packet-capture tests remain release gates; this source review does not establish those live outcomes.