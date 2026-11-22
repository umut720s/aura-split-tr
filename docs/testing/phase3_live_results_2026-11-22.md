# Phase 3 — Live test results (2026-11-22)

Environment: the maintainer's own Windows 11 x64 PC (not a VM — no Hyper-V /
Windows Sandbox available), user-authorized step by step; every elevated
step was approved through UAC by the user. Ethernet, IPv4 only (IPv6 unbound
from the physical adapter). A Wintun 0.14.0 driver package from another
application was already present. Evidence (private, outside the repo):
`C:\AuraTest\evidence\` — contains IPs and host names; not to be published.

Provider tested: **Proton VPN (Plus) WireGuard config**. Cloudflare WARP and
generic WireGuard: NOT TESTED yet.

| ID | Scenario | Result | Evidence / notes |
|---|---|---|---|
| S00 | Baseline capture | PASS | `S00-before-*`: no AURA WFP objects, no VPN client running |
| S1 | Fresh install (setup wizard) | **FAIL → workaround** | Profile written, WFP policy applied (2 Discord programs), service installed with BFE dependency — but the service was **never started** by setup (no log, SCM 7045 only). Cause not yet identified (wizard output not captured). Service started manually with `aurasplit start`. **Open bug.** |
| S3/S2 | Proton first connection | **FAIL → fixed → PASS** | Bug 1 (below): WireGuard bind failed on IPv6-less host → `VPN_DEGRADED` (timeout ×2). After fix: `VPN_CONNECTIVITY_VERIFIED` within 3 s of start. |
| S6 | Discord Stable startup | PASS | All established Discord TCP sockets had local address `172.19.0.1` (TUN); none on Ethernet. TUN carried ~13 MB. |
| S7 | Discord voice | PASS (user-observed) | User joined a voice channel successfully. Voice UDP sockets are wildcard-bound; tunnel path inferred from the off-TUN WFP block (not packet-captured). Screen share NOT TESTED. |
| S14a | `stop` keeps Discord blocked | PASS | 25 s stopped: Discord had no remote TCP connections (only loopback listener); TUN adapter removed; restart → VERIFIED in 4 s. WFP drop net-events were not recorded (0) — likely auditing off; evidence is indirect. |
| S11 | Service crash (`taskkill /F`) | PASS | SCM 7031 + restart in ~4–5 s; per-second sampling: 0 Discord TCP on Ethernet during the gap; reconnect via TUN; VERIFIED again within 6 s. |
| S8b | AuraSplit upgrade (stop → replace exe → start) | PASS (manual path) | Done twice by copying the exe while stopped; upgrade via the setup wizard NOT TESTED. |
| — | Unrelated traffic unaffected | **FAIL → fixed → PASS** | Bug 2 (below): YouTube in the browser reported "not connected". After fix: user confirmed YouTube and Discord both work; 0 IPv6 dial errors after restart (391 of the last 400 log lines before). |
| 3G | Resource use (voice active) | Partial | Working set ≈ 63–64 MB, private ≈ 80 MB, 600 handles, 24 threads. CPU: NOT MEASURED (SYSTEM process CPU time not readable unelevated). |
| S4 | Cloudflare WARP | NOT TESTED | |
| S5 | Generic WireGuard | NOT TESTED | |
| S9/S10 | VPN disconnection / reconnection | NOT TESTED | |
| S12 | Windows restart | NOT TESTED | |
| S13 | Invalid VPN configuration | NOT TESTED | |
| S14b-d | `disable`, `recover`, `uninstall` | NOT TESTED | |
| S15 | Installation rollback | NOT TESTED | |
| 4.x | Packet-capture leak tests (DNS/IPv6/browser/ECH) | NOT TESTED | |

## Bugs found in live testing (fixed in code, re-verified live)

1. **WireGuard never connected on hosts without IPv6 on the physical adapter.**
   sing-box used wireguard-go's `StdNetBind`, which always opens a UDP6
   socket bound (auto-detect interface) to the physical adapter; with IPv6
   unbound this fails with WSAEINVAL ("Geçersiz bir değişken sağlandı") and
   the whole bind — IPv4 included — is lost. Fix (`internal/engine/config.go`):
   the endpoint now dials through a dedicated non-empty direct outbound
   `wg-direct` (`detour`), which makes sing-box use its `ClientBind` (socket
   family of the peer only).
2. **Browsers lost connectivity for non-Discord sites ("not connected").**
   The TUN always had an IPv6 address/route; browsers resolving AAAA via
   their own DoH connected over IPv6 into the TUN, the stack accepted the
   connection, the direct outbound failed, and the browser did not fall back
   to IPv4. Fix: detect host IPv6 at config build (`internal/engine/hostipv6.go`);
   without it the TUN gets no IPv6 address and every AAAA answer from the
   hijacked resolver is empty. Limitation: detection happens at service
   start / tunnel retry only; network changes afterwards need a restart.

## Open items from this session

- S1 setup did not start the service (investigate; capture wizard output).
  → see the follow-up below.
- These two fixes have not been independently reviewed by Codex yet.

## Follow-up: S1 root cause (added 2026-11-22, NOT yet re-tested)

Observed on the same PC (Kaspersky Plus active) in a later attempt:

- During `aurasplit.exe setup` (self-elevation through UAC + the exe copying
  itself into `%ProgramFiles%\AuraSplitTR` + creating a LocalSystem service +
  adding persistent WFP filters), Kaspersky raised a behaviour detection
  **`PDM:Trojan.Win32.Generic`** on `dist\aurasplit.exe`.
- Kaspersky held the freshly written service executable in the "Initialized"
  state, so the service stayed **`START_PENDING`**. This is the most likely
  explanation of the earlier S1 failure "setup did not start the service":
  `service.Start` timed out while the process never reached the service
  dispatcher (our handler reports RUNNING immediately after START_PENDING).
  The old setup did not distinguish this case clearly.

Decision (maintainer): no AV exclusions or bypasses. Mitigation:

1. Installation moved to a standard Windows Installer package
   (`installer/AuraSplitTR.wxs`, `AuraSplitTR-<ver>-x64.msi`): Windows
   Installer creates the files and the service; `aurasplit.exe` no longer
   copies itself or creates a service. The service is registered as manual
   start; `setup` (Start Menu "AURA Split TR - Yapılandır") only configures,
   sets automatic start, starts it and now reports a service stuck in
   START_PENDING with an explicit antivirus hint and a non-zero exit code.
2. Authenticode signing of the exe and the MSI (prepared in the release
   workflow, skipped until a certificate/service is configured).

Status (initially NOT TESTED) — **re-tested live the same day after a reboot**, see below.

## MSI live run (2026-11-22, 12:25–12:32, after reboot; Kaspersky Plus active)

| ID | Scenario | Result | Evidence / notes |
|---|---|---|---|
| S1-msi | `msiexec /i` fresh install | PASS (2nd attempt) | 1st attempt exit 1602: Windows Installer error 1704 — a *suspended Kaspersky VPN installation* blocked all MSI installs; the user chose to undo it. 2nd attempt exit 0 in ~1 s. Service: manual, LocalSystem, BFE dependency, restart ×3/5 s; not started; no WFP objects; Start Menu shortcut present. **No Kaspersky alert** during install. |
| S4 | Configure Cloudflare WARP via Start Menu `setup` | **FAIL → fixed → PASS** | `setup` started the service (RUNNING, no START_PENDING hang, no Kaspersky alert). WARP did not connect (`VPN_DEGRADED`): Bug 3 below. After the fix: `VPN_CONNECTIVITY_VERIFIED` 3 s after start. |
| S6/S7 (WARP) | Discord + voice over WARP | PASS | 6/6 established Discord TCP sockets local `172.19.0.1`; user confirmed Discord and voice work; YouTube works (user). |
| S8b-msi | MSI upgrade (same version, new build) | PASS | `msiexec /i` exit 0 in 20 s; exe replaced; start type stayed AUTO; service restarted with the existing WARP profile (`start --msi`) and verified. |
| S14-msi | `msiexec /x` uninstall | PASS | exit 0 in 2 s; `recover --msi` custom action ran first (log); service, install dir, Start Menu shortcut, TUN adapter gone; **`%ProgramData%\AuraSplitTR` (private key) removed**; 0 AURA provider filters / sublayer in `netsh wfp` capture. |

Bug 3 — **WARP (host-name endpoint) never completed a handshake.** With a
host-name peer sing-box takes an unconnected listen-socket path that was
observed closing and re-opening every ~5 s. Fix
(`internal/engine/config.go`, `hostipv6.go`): the peer host is resolved
(IPv4 preferred / IPv4-only on IPv6-less hosts) when the configuration is
built and the literal IP is used; on resolution failure the name is kept.
Limitation: the WARP IP is fixed until the next service start / tunnel retry.

Still NOT TESTED live: generic WireGuard (S5), VPN disconnection /
reconnection (S9/S10), Windows restart with the service enabled (S12),
invalid configuration (S13), `disable` (S14b), MSI rollback (S15), packet
capture leak tests (§4), CPU measurement. The three live-test fixes and the
MSI conversion have **not** been reviewed by Codex yet.
