# R3 fixes — independent Codex (gpt-6.1-sol) review

Run: 2026-11-27, read-only. Verbatim final output (local paths redacted).

- **Medium — false protected:** [gate.go:78](/internal/oldflow/gate.go:78) drops first-seen unreadable Discord processes unless their ancestry reaches a readable Discord process. For example, `Name="Discord.exe", Image="", Unresolved=true` with an unrelated parent now passes the gate. Pre-protection sockets can remain direct while `OldFlowsComplete` and subsequently `Ready` become true. Retain fail-closed handling for unresolved Discord candidates while excluding identified system processes.
- **Medium — false protected:** The same condition excludes **readable, manifest-matching session-0 processes**, regardless of creation time. A supported updater/installer running there before enrollment can retain old flows while readiness passes. Apply the creation-time gate to positively matched images regardless of session.

**Multi-NIC diagnostics are insufficient.** [multinic.go:84](/internal/engine/multinic.go:84) uses `nm.NetworkInterfaces()`, but pinned sing-box populates that list only through its platform-interface branch (`route/network.go:270–295`). AURA supplies no platform interface. Consequently, normal Windows execution logs the selected index but performs **zero NIC/DNS probes**. Enumerate Windows adapters and obtain their gateway/DNS metadata explicitly.

**Missed mechanism:** pinned sing-tun’s `tun_bind_windows.go:31–63` explicitly identifies forwarding-enabled interfaces as making Windows ignore socket interface binding and route outbound connections back into the TUN. The analysis should include this mechanism and inspect per-family forwarding/weak-host state. Code confirms the mechanism, **not that it caused R3**; that requires live evidence.

Read-only inspection completed; no tests or elevated commands executed.

Blocking defects in this change: YES