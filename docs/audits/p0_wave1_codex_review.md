# P0 wave 1 — independent Codex (gpt-6.1-sol) review

Run: 2026-11-26, read-only, on uncommitted changes. Verbatim final output (local paths redacted).

- **High — [internal/wfp/discover.go:252](/internal/wfp/discover.go:252):** Discovery now enrolls arbitrary `Discord*` roots, but the engine’s `DiscordPathRegex` still recognizes only four canonical roots. An IP-only helper flow from `DiscordCustom\app-1\audio_effects_helper.exe` can enter TUN, miss engine classification, and leave through `direct` while its class reports `protected`. **Fix:** align enrollment and engine classification through one executable manifest, or restrict discovery to supported roots.

- **High — [internal/oldflow/source_windows.go:119](/internal/oldflow/source_windows.go:119):** Rechecking and holding the process handle does not preserve ownership of the captured TCP tuple. If that connection disappears and another process acquires the tuple, `SetTcpEntry` can delete the replacement connection; its API accepts connection fields, not PID. **Fix:** use termination through the consented, verified process handle unless socket ownership can be guaranteed atomically. [Microsoft API contract](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-settcpentry).

- **High — [internal/oldflow/gate.go:37](/internal/oldflow/gate.go:37):** Any executable beneath an inferred `Local\Discord*` root counts as Discord, including unrelated utilities or applications in a similarly named directory. This enables automatic TCP resets and, after a generic Discord-close consent, termination of unrelated processes. **Fix:** verify installation identity and restrict destructive actions to explicitly identified executables; ancestry/path-prefix membership alone is insufficient.

- **High — [internal/oldflow/source_windows.go:51](/internal/oldflow/source_windows.go:51):** Image-query failures are silently ignored unless the basename matches a heuristic. An inaccessible, unenrolled child with another name can therefore disappear from the inventory, allowing the zero-process gate to complete despite surviving IPv6/UDP flows. **Fix:** track relevant process identities and require confirmed retirement; unresolved potentially protected children must keep readiness pending.

- **Medium — [tools/leaktest/analyze.py:476](/tools/leaktest/analyze.py:476):** `protected()` excludes newly enrolled noncanonical `Discord*` roots. Their physical traffic is not automatically classified as a leak and can qualify as a supposedly unrelated positive control, permitting PASS with otherwise satisfied review gates. **Fix:** record and consume the actual executable manifest instead of maintaining a separate protection heuristic.

- **Medium — [tools/leaktest/capture.ps1:122](/tools/leaktest/capture.ps1:122):** Requiring TUN before recording prevents capturing the initial L1 enable interval and its pre-existing direct flows. The documented L1 procedure therefore cannot supply P0-C acceptance evidence using this recorder alone. **Fix:** begin physical capture before activation and discover TUN subsequently; remain INCONCLUSIVE if required TUN evidence never arrives.

Default-No consent, redacted exports, suffix/exact-host domain matching, and existing-block budget retention look conservative. No new lock cycle or automatic elevation path was identified. Documentation’s ownership-verification claims exceed the guarantees above.

Read-only review; no elevated actions or prohibited test binaries executed. Python fixture execution was unavailable, so these findings are static.

Blocking justification: wrong-process destructive actions and falsely protected executable coverage remain possible.
Blocking defects in this change: YES