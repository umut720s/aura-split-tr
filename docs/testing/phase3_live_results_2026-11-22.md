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

## Live run 2 (2026-11-22, 17:15-17:36) - commit 87e24f8, MSI 87f18a56...

Environment as before (same PC, Kaspersky Plus active, IPv4-only Ethernet). User-approved, UAC per elevated step.

| ID | Scenario | Result | Evidence / notes |
|---|---|---|---|
| S1 | MSI install (new build with icon/version resource) | PASS | exit 0; service demand-start, BFE dependency, stopped; 0 AURA WFP filters; exe version 0.1.0.0; no AV alert. |
| S4 | Configure Cloudflare WARP (new registration) | PASS (self-recovered) | First 3 probes timed out (`VPN_DEGRADED`); the engine rebuilt the tunnel automatically (log: "rebuilding the tunnel: VPN connectivity lost (3 consecutive probe failures)") and was `VPN_CONNECTIVITY_VERIFIED` 5 s later. Likely cause: a freshly registered WARP key needs a short time to become active (not proven). User ran a speed test and used Discord. |
| S12 | Windows restart with the service enabled | PASS | Boot 17:21:52, tunnel started 17:22:04 (12 s), VPN verified; after the user opened Discord: 6/6 established Discord TCP sockets via TUN `172.19.0.1`. Boot-window leak capture (pktmon) NOT TESTED. |
| S14b | `disable` then `start` | PASS | `disable`: start type DISABLED, 0 AURA WFP filters, Discord 3/3 sockets direct. `start`: AUTO_START, VPN verified in 8 s, Discord 3/3 sockets via TUN. |
| S14 | `msiexec /x` uninstall | PASS | exit 0; custom actions ran in order (save state -> recover -> clean data; rollback action only scheduled); service, install dir, Start Menu entry, TUN adapter and `%ProgramData%\AuraSplitTR` gone; 0 AURA filters/sublayer; IP addresses, DNS servers and routes identical to the pre-install capture. |

Still NOT TESTED live: MSI rollback paths (forced failure during uninstall/upgrade), generic WireGuard (S5), VPN disconnection/reconnection by network loss (S9/S10), invalid configuration (S13), packet-capture leak tests (section 4), CPU measurement.

## Live run 3 (2026-11-22, 17:37-17:48) - same build as run 2

| ID | Scenario | Result | Evidence / notes |
|---|---|---|---|
| S5 | Generic WireGuard (configurator option 3, Proton .conf used as a generic config) | PASS | Service running, protection complete; first probe 8 s after start failed ("connection failed"), second probe 30 s later `VPN_CONNECTIVITY_VERIFIED`; Discord 2/2 sockets via TUN; user confirmed Discord works. |
| S9/S10 | Network loss and recovery (Ethernet unplugged ~40 s: 17:42:51-17:43:31) | PASS (protection) / gap (status) | Per-second sampling: 0 Discord sockets outside the TUN for the whole run; direct outbound for other apps failed with "no route to internet" while unplugged (expected); after replug the WireGuard socket was re-created and TUN traffic resumed within seconds. The status did NOT show VPN_DISCONNECTED: the probe runs every 5 min, so a 40 s outage is not reflected. |
| S13 | Invalid configuration file | PASS | Configurator rejected it ("Bu dosya geçerli bir WireGuard yapılandırması değil", no key material echoed); the running Proton/generic profile, WFP policy and Discord TUN routing were unchanged. |
| S14 | Uninstall | PASS | exit 0; service, files, data dir, Start Menu entry, TUN adapter and AURA WFP objects removed. |

UX defects found:
1. **Drag-and-drop into the configurator does not work**: the configurator runs elevated and Windows (UIPI) blocks drag-and-drop from the non-elevated Explorer. Workaround used: "Copy as path" + paste. README currently tells users to drag the file.
2. **First connectivity probe is too early** (3 s after tunnel start): it regularly reports `VPN_DEGRADED` for the first ~30-120 s before the WireGuard handshake completes (seen with WARP, Proton and generic).
3. **Short outages are not reflected in the status** (5-min probe interval, no probe on network change).

## Live run 4 (2026-11-22, 18:05-18:21) - commit 94399c2 (UX fixes)

| ID | Scenario | Result | Evidence / notes |
|---|---|---|---|
| S1 | MSI install | PASS | exit 0, service stopped/manual until configured. |
| UX-1 | Configurator file picker | PASS (user-observed) | The native "Open file" dialog opened from the elevated configurator; the Proton .conf was selected and setup completed. |
| UX-2 | Start-up grace (VPN_CONNECTING) | PASS | Elevated status poll every 3 s: 18:06:44 service RUNNING + `VPN_CONNECTING — bağlanıyor`; 18:06:55 `VPN_CONNECTIVITY_VERIFIED`. No VPN_DEGRADED shown. |
| UX-3 / S9-S10 | Network loss: Ethernet unplugged 18:19:43-18:20:22 | PASS | Status `VPN_DISCONNECTED` at 18:19:43 (same second as link down; first poll 18:19:46); `VPN_CONNECTIVITY_VERIFIED` at 18:20:28, 6 s after replug. Per-second socket sampling: 0 Discord TCP sockets outside the TUN for the whole run; Discord reconnected via TUN after replug. |

Notes: two UAC prompts for the status poller were cancelled/timed out during this run and were re-issued; that did not affect the measurements above.

## Live run 5 - packet-capture leak tests (2026-11-22, 18:37-18:50), commit 4ee37d8

Tooling: `tools/leaktest/capture.ps1` (pktmon on the physical "Ethernet" NIC, 256-byte snaplen) + `tools/leaktest/analyze.py` (DNS qnames, TLS ClientHello SNI, HTTP Host; QUIC SNI not parsed). Captures stay outside the repo (they contain the user's browsing host names). Before the run the installed app was upgraded via MSI to the round-7 build (exit 0, service restarted, VPN verified in 13 s).

| ID | Scenario | Result | Evidence / notes |
|---|---|---|---|
| L1+L4 | Service running; Discord restarted, voice joined ~30 s, browser opened https://discord.com and unrelated sites (120 s) | PASS (no indicators) | 155,505 packets, 68,045 to the WireGuard endpoint; 0 Discord DNS queries, 0 Discord TLS SNI, 0 Discord HTTP Host on the physical NIC; 0 IPv6 packets. 2 QUIC (UDP 443) flows with unparsed SNI were later attributed to Spotify by socket owner (35.186.224.x). Analyzer caveats: ECH/encrypted DNS/truncation can hide names. |
| L2 (first try) | Service stopped (`stop`), Discord app restarted, a discord.com browser tab was still open (90 s) | Expected limitation | Discord DNS names (gateway.discord.gg, discordapp.com, status.discord.com, a voice host) went to the DNS server on the physical NIC; 4 TLS ClientHellos with SNI discord.com / cdn.discordapp.com also went out. A follow-up socket-owner check showed no Discord.exe connections off the TUN and no loopback proxy (Kaspersky HTTPS scanning ruled out); the TLS flows are attributed to the still-open browser tab (browser Discord is not covered by the WFP policy - documented). |
| L2b | Service stopped, browser Discord tab closed, Discord app restarted (75 s) | PASS for the app / DNS leak as documented | 0 Discord TLS SNI, 0 HTTP Host; 9 Discord DNS queries (gateway*.discord.gg, discord.com, discordapp.com, cdn.discordapp.com, updates.discord.com) to the DNS server - the Windows DNS Client resolves names even though WFP blocks the connections. |

Conclusions: with the service running, no Discord names were visible on the physical NIC in this capture. With the service stopped, the Discord app could not connect (no TLS), but Discord host names leak in plaintext DNS, and browser Discord tabs connect directly. Not covered: boot-window capture, QUIC SNI, ECH, other machines/AV products.

## Live run 6 (2026-11-22, 22:05-22:10) - commit 3bc143c (small auraclean MSI helper, MSI 14 MB)

| ID | Scenario | Result | Evidence / notes |
|---|---|---|---|
| S8b | MSI upgrade over the previous build (14 MB MSI) | PASS | exit 0 in ~6 s; Proton profile kept; service restarted; `VPN_CONNECTIVITY_VERIFIED` 10 s later. |
| S14 | `msiexec /x` with the new `auraclean.exe` data-cleanup helper | PASS | exit 0; custom actions in order (save state -> recover -> AuraCleanData via auraclean `uninstall --msi`); service, install dir, Start Menu entry, TUN adapter and `%ProgramData%\AuraSplitTR` (private key) removed; 0 AURA WFP provider filters / sublayer. |
| S1 + S3 | Reinstall + reconfigure Proton via the file picker | PASS | Service running, VPN verified 11 s after start, protection complete. |
| obs. | Pre-existing Discord connection after enabling protection | Observed limitation | One Discord TCP socket opened at 22:06:09 (while AURA was uninstalled) stayed on the physical NIC after protection was enabled at 22:07:15; new sockets used the TUN. WFP authorizes new connections only. After the user restarted Discord: 6/6 sockets via TUN. Matches the existing instruction to fully restart Discord after setup. Possible improvement: close Discord's off-TUN TCP connections when protection is enabled. |

## Live run R3 (2026-11-27, commit cab9827, MSI d1ed59da…; Kaspersky Plus active)

Environment change vs. earlier runs: **two physical NICs up on the same subnet** (Ethernet 192.168.1.x metric 25, Wi-Fi 192.168.1.x metric 55, both with a default route to the same gateway; NCSI: Ethernet "NoTraffic", Wi-Fi "Internet"); Ethernet DNS set to 1.1.1.1/1.0.0.1, Wi-Fi DNS = router; Proton VPN app running but **not** connected; two NRPT rules for Microsoft update hosts (not created by AURA).

| ID | Scenario | Result | Evidence / notes |
|---|---|---|---|
| R3-1 | Fresh MSI install | PASS | exit 0; service manual/stopped; new per-class `status` shows every class not-covered before setup; browser/DNS labelled best-effort. |
| R3-2 | Setup with Discord already running (P0-C) | **FAIL (bug)** | Policy applied: **9 programs** enrolled incl. helpers (P0-E works). Old-flow gate stuck pending on unreadable **system** processes (Secure System, Registry, Memory Compression) treated as "possible Discord" → readiness can never become true. Setup console window closed by itself, so the user could not read the prompt/consent. |
| R3-3 | Status text | **FAIL (bug)** | Some per-class lines are double-encoded (mojibake, e.g. "haz├ä┬▒r de├ä┼©il") while others render correctly. |
| R3-4 | Non-Discord traffic while AURA runs | **FAIL (critical, environment-dependent)** | With AURA running, **all name resolution on the PC failed** ("remote name could not be resolved" for google/youtube/example); sing-box direct dials timed out (incl. a Proton API address); WARP stayed VPN_CONNECTING. `aurasplit stop` restored DNS/internet immediately. Leading hypothesis: multi-NIC same-subnet default-interface selection / local DNS path in sing-box(auto_detect_interface) or strict_route DNS blocking with two egress NICs. Not yet confirmed; Proton app running (disconnected) not excluded. |

Follow-up: reproduce with Wi-Fi disabled vs. enabled (user-controlled) to confirm the multi-NIC hypothesis; fix gate false-pending on protected system processes; keep the setup console open; fix double encoding.

### R3 follow-up — Wi-Fi disabled (Ethernet only), same session

| ID | Scenario | Result | Evidence / notes |
|---|---|---|---|
| R3-5 | AURA running, only Ethernet up | PASS (socket-level) | Name resolution OK (google/example/discord), https google 200 / youtube 200; WARP `VPN_CONNECTIVITY_VERIFIED` 18 s after start. Strongly supports R3-4 being a **multi-NIC (two egress NICs on the same subnet)** defect. Root cause still to be found. |
| R3-6 | `start` run non-interactively | **FAIL (bug)** | `aurasplit start` printed the old-flow gate guidance and then blocked waiting for a console answer (consent prompt) in a hidden elevated process; it must not prompt when non-interactive. |
| R3-7 | Enrolled program count | Observation | 9 programs at setup (21:34), 6 at the later start (21:41) — cause not yet explained (manifest/discovery drift?). |
| R3-8 | `disable` | PASS | Service stopped + Disabled, persistent WFP policy removed, status shows no policy. |

## Live run R4 (2026-11-27 22:25, commit edb457b) — both NICs connected

Ethernet (metric 25) and Wi-Fi (metric 55) both connected with Internet connectivity; IPv4 Forwarding / WeakHost = Disabled on both **while connected** (rules out the sing-tun forwarding mechanism for this PC).

| ID | Scenario | Result | Evidence / notes |
|---|---|---|---|
| R4-1 | MSI upgrade over disabled install | PASS | exit 0 |
| R4-2 | `start` non-interactive | PASS | printed guidance, no prompt, exit code 3 (R3-6 fixed) |
| R4-3 | AURA running with 2 NICs | PASS (socket-level) | DNS 3/3 OK, https 200, WARP verified 14 s after start; R3-4 **not reproduced**. |
| R4-4 | Multi-NIC diagnostics | Evidence | sing-tun default interface = Ethernet; direct, wg-direct and local DNS auto-bind to Ethernet; bound DNS queries via Ethernet OK; a query bound to Wi-Fi's on-link DNS server timed out while the same server via auto-egress (Ethernet) worked. |

**Interpretation (assumption, not proven):** AURA pins all direct traffic and its local DNS to the single lowest-metric interface; with strict_route, Windows' own multi-adapter DNS fallback is unavailable. During R3 Windows reported Ethernet "NoTraffic" — if the selected interface is up but not passing traffic, AURA has no failover and all resolution fails, while stopping AURA lets Windows fall back to Wi-Fi. Proposed fix: health-aware egress selection (fail over to another default-route interface when probes on the selected one fail), plus a status warning. Needs a reproducible "selected NIC up but dead" test (e.g. unplug the Ethernet uplink at the switch while the NIC stays up).
