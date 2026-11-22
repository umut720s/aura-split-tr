# AURA Split TR — Phase 3 Final Report

Date: 2026-11-22 · Target: `v0.1.0-beta` (not released) · Platform: Windows 11 x64

Status vocabulary: **PASS**, **FAIL**, **BLOCKED**, **NOT TESTED**, **NOT APPLICABLE**.
Nothing below is marked PASS on the basis of compilation alone.

## 1. Executive summary

- Recorded pre-live checks passed builds and non-privileged tests;
  govulncheck reported 27 → 0 vulnerabilities in called code. These historical
  checks were not rerun for this documentation update.
- A persistent **WFP fail-closed** layer, separate status states and a
  tunnel-only connectivity probe were implemented in this phase.
- Four audit workstreams (networking, Go security, reliability, release) and
  **three independent Codex (`gpt-6.1-sol`) review rounds actually ran**. All
  Codex findings from rounds 1–3 have source-level fixes. The fix for the
  round-3 finding (watcher queue) was made after round 3 and has **not** been
  re-reviewed by Codex.
- Live runs 1–3 exercised real providers, WFP, SCM, TUN and MSI on **one Windows
  11 x64 PC, IPv4-only Ethernet, Kaspersky Plus active, unsigned beta**.
  TCP socket observations passed the scenarios in §7/§9; they are not packet captures.
- **GitHub release readiness: validation incomplete; not production-ready.**
  Packet-capture and broader-environment checks remain open. Public release is
  the maintainer's decision. [Live record](../testing/phase3_live_results_2026-11-22.md).

## 2. Actual architecture

Details: [`docs/audits/phase3_architecture.md`](../audits/phase3_architecture.md)
(code-verified, with a mermaid traffic diagram) and [`ARCHITECTURE.md`](../../ARCHITECTURE.md).

- Single Go binary `aurasplit.exe` (CLI + LocalSystem service `AuraSplitTR`,
  depends on BFE). Embeds sing-box v1.14.4 (tags `with_gvisor,with_wireguard,with_external_windivert`)
  and sing-tun/Wintun.
- sing-box `tun` inbound with `auto_route` + `strict_route`. On Windows,
  strict_route adds **dynamic** WFP filters (sublayer weight 0xFFFF) that block
  off-TUN port 53 only while the process runs — it is *not* a kill switch.
- Routing: process rules (Discord path regex, process names, installer regex)
  and Discord domain rules → WireGuard endpoint `wg`; everything else → `direct`.
  Discord-domain DNS goes through the tunnel; other DNS via the local resolver.
- **New in Phase 3** — `internal/wfp`: persistent provider + sublayer (weight
  0xF000) with per-executable BLOCK filters for discovered Discord binaries
  (ALE connect/accept, v4/v6) and a loopback permit; a dynamic session adds a
  PERMIT on the TUN interface LUID only while the tunnel is up. Discovery scans
  all user profiles, is watched with `FindFirstChangeNotification`, and is
  backstopped by a 60 s rescan. Incomplete discovery is add-only.
- No auto-update mechanism exists. The only network access outside the
  tunnel by the app itself is WARP registration during setup.

## 3. Security findings

| Source | Critical | High | Medium | Low/Info | Status |
|---|---|---|---|---|---|
| Agent B — Go security ([phase3_security.md](../audits/phase3_security.md)) | 0 | 0 | 1 (deps) | 7 + 4 info | Deps fixed; S-2…S-8, S-11 fixed; S-9, S-10, S-12 open (Low/Info) |
| Agent C — reliability ([phase3_reliability.md](../audits/phase3_reliability.md)) | 0 | 0 | 1 (C-1) | 2 | C-1, C-2 fixed |
| Agent A — networking ([phase3_architecture.md](../audits/phase3_architecture.md)) | — | fail-open windows | — | — | WFP exercised live at TCP socket level (§9); packet capture pending |
| Codex round 1 ([round1](../audits/phase3_codex_review_round1.md)) | 0 | 4 | 4 | — | All fixed in source; #4 partial (architectural) |
| Codex round 2 ([round2](../audits/phase3_codex_review_round2.md)) | 0 | 1 | 3 | 1 | All fixed in source |
| Codex round 3 ([round3](../audits/phase3_codex_review_round3.md)) | 0 | 0 | 1 | — | Fixed after the review; **not re-reviewed** |

Open / accepted items:

- **Architectural (High, documented):** fail-closed covers only the
  *discovered* Discord executable inventory. A new Discord version launched
  before the ~1 s watcher reconcile while the tunnel is down, or a version
  staged while the service is stopped, is not blocked until reconciled.
- **Low/Info:** private key held in non-wipeable Go strings (S-9); service runs
  as full LocalSystem without privilege trimming (S-10); unsigned binary means
  UAC cannot distinguish a swapped exe (S-12).
- **Trust boundary note (Codex r2):** WFP filters under our provider can be
  added by Administrators, Network Configuration Operators and some service
  identities; `providerData` is not authenticated ownership evidence.

## 4. Changes implemented in Phase 3

- `internal/wfp` (new): typed fwpuclnt bindings (adapted from
  wireguard-windows, MIT), `runtime.Pinner` marshalling, persistent/dynamic
  policy, discovery, watcher, budgets, incomplete-status reporting.
- New CLI commands `disable` and `recover`; `stop` keeps Discord blocked;
  MSI uninstall runs `recover --msi` before removing the service/exe, while the
  interactive `uninstall` command explains MSI removal; `run --debug` applies
  the same policy and permit.
- Status states: SERVICE_RUNNING, TUNNEL_INITIALIZED,
  VPN_CONNECTIVITY_VERIFIED, VPN_DEGRADED, VPN_DISCONNECTED, PROTECTION_ACTIVE.
  Probe: HTTPS to `www.cloudflare.com/cdn-cgi/trace` dialled only through
  `wg`, DNS resolved through the tunnel; IP never stored or logged.
- Service: BFE dependency, ordered/bounded shutdown, close-timeout is fatal
  (fresh process via SCM recovery), `Disable` before stop in disable/recover.
- MSI owns installation and service registration; setup configures the profile and
  applies policy before start. Forced-failure MSI rollback remains NOT TESTED live.
- Filesystem hardening fixes S-2…S-5; event-log and sing-box log redaction.
- Toolchain go1.26.11; x/net, x/crypto, grpc, compress, brotli bumped.
- WinDivert driver no longer embedded (`with_external_windivert`).
- Tests: ACL/privilege tests moved behind `acltests`; `internal/testutil`
  with retrying TempDir and open-handle assertions; many new unit tests.
- Release/compliance files and CI (see §10, §13).

## 5. Tests executed

Historical checks from the phase record; no builds or tests were run for this
documentation-only update. Live results are separately recorded in §7/§9.

| Check | Result | Notes |
|---|---|---|
| `gofmt -l` | PASS | |
| `go vet` (release tags; also `acltests`, GOOS=linux) | PASS | |
| `go test -count=1` (release tags), all packages except `internal/wfp` | PASS | |
| `internal/wfp` tests | PASS | Via a compiled test binary in a non-temp directory; launching from the go-build temp dir is refused by the OS ("Erişim engellendi"), see §6 |
| Reliability stress (Agent C): suite ×20, logfile/cmd ×100 | PASS | 2060 pass / 0 fail after test-side fixes |
| `govulncheck` (release tags) | PASS | 0 called; 1 in a required module, not called |
| `build.ps1` | PASS | Local reproducibility of identical hash confirmed once by Agent D (go1.26.5 era); not re-checked after the bump |
| Personal-data scan (sources + exe) | PASS | No local user name/paths; upstream author e-mails in license texts are required notices; Wintun DLL carries its upstream PDB path |

## 6. Tests blocked

| Check | Status | Reason |
|---|---|---|
| `go test -race ./...` | BLOCKED | Requires cgo; no gcc on this machine |
| `go test -tags acltests ./internal/paths` (elevated cases) | BLOCKED | Needs an elevated shell; 1 test fails unelevated with an ownership-assignment error |
| `go test ./internal/wfp` from go-build temp dir | BLOCKED (env) | OS refuses to launch the test binary (likely Kaspersky heuristic; earlier it flagged `paths.test.exe` as `VHO:Trojan.Win64.Convagent.gen`). Same tests PASS from another directory |
| Real WFP calls, SCM lifecycle, TUN | PASS (live scope) | Runs 1–3, §7/§9; forced-failure recovery/rollback paths remain NOT TESTED |
| GitHub Actions workflows | NOT TESTED | Not run on GitHub (YAML parses locally) |

## 7. Real VPN validation status

All live results below are limited to **one Windows 11 x64 PC, IPv4-only
Ethernet, Kaspersky Plus active, unsigned beta**. Source and chronology:
[live runs 1–3](../testing/phase3_live_results_2026-11-22.md).

| Item | Status | Observation / limit |
|---|---|---|
| Proton VPN, Cloudflare WARP, generic WireGuard | PASS | `Get-NetTCPConnection` sampling: established Discord TCP sockets had TUN local address `172.19.0.1`; generic option used a Proton `.conf`, not an additional provider |
| VPN_CONNECTIVITY_VERIFIED against real endpoints | PASS | Status/probe logs reported verified connectivity after connection/retry |
| Discord Stable + voice | PASS | TCP method above; successful voice join user-observed, UDP path inferred, not packet-captured |
| PTB / Canary, screen share, Discord update | NOT TESTED | Not established by runs 1–3 |
| Windows restart, service enabled | PASS | Service/tunnel up ~12 s after boot; Discord TCP via TUN after user opened it; boot-window leak capture NOT TESTED |
| `disable` then `start` | PASS | Disabled + filters removed + direct TCP; start restored automatic service and TUN TCP |
| MSI install / upgrade / uninstall | PASS | MSI logs/lifecycle checks; after uninstall `netsh wfp show filters/state`: 0 AURA provider filters/sublayer; IPs, DNS servers and routes identical to pre-install capture; `%ProgramData%\AuraSplitTR` (private key) removed |
| Invalid configuration | PASS | Rejected without changing running profile, WFP policy or Discord TUN routing |
| Forced-failure MSI uninstall/upgrade rollback; repair/error paths | NOT TESTED | Successful uninstall did not exercise rollback |
| Packet-capture leaks: DNS/IPv6/UDP, boot window, browser/ECH | NOT TESTED | TCP socket sampling is not packet capture |
| CPU measurement; native IPv6 hosts; other AV products; multiple machines | NOT TESTED | No broader validation claimed |
| Post-run-3 file picker, VPN_CONNECTING start-up grace, network-change probe | NOT TESTED | Implemented after the tested build; run 3 status missed the ~40 s outage |

Live-test bugs fixed:

- IPv6-less host WireGuard bind: corrected connection path, re-verified live.
- Browser IPv6 outage: host-aware TUN/DNS configuration, re-verified live.
- WARP host-name endpoint: IP resolution before configuration, re-verified live.
- AV hold on self-install: switched to MSI; no AV alert/start-up hold observed in MSI runs on the same Kaspersky PC.

Remaining procedure: [real-world test plan](../testing/phase3_realworld_test_plan.md).
Its original checklist is not the latest execution record.

## 8. DNS and IPv6 leakage assessment (design-level, not measured)

- While running: Discord-domain DNS → tunnel; off-TUN port 53 blocked by
  sing-tun's dynamic filters; AAAA answers suppressed when the tunnel has no
  IPv6; Discord executables blocked off-TUN on v4 and v6 by the WFP layer.
- While stopped: Discord connections blocked by persistent WFP (discovered
  inventory), but **Windows DNS Client may still send Discord name lookups to
  the ISP resolver** (names leak, connections do not).
- Browser Discord: routed by sniffed domain only; not covered by WFP. ECH,
  shared CDN IPs with `reverse_mapping`, browser DoH can misroute; precise
  browser isolation is **not guaranteed** (see architecture audit §5).
- Packet-capture validation: **NOT TESTED**. Live TCP socket results (§7/§9)
  do not establish DNS, IPv6 or UDP leak protection.

## 9. Fail-closed verification

PASS below means **TCP socket-level observation only** on the single PC in §7.
Per-second `Get-NetTCPConnection` sampling found **0 Discord TCP sockets outside
the TUN** in the stop/crash/outage scenarios. UDP and DNS were not captured;
these results are **not packet-capture leak tests**.

| Scenario | Status | Observation / limit |
|---|---|---|
| Service `stop` | PASS | 25 s stopped; no off-TUN Discord TCP sockets |
| Forced crash (`taskkill /F`) | PASS | ~4–5 s until SCM restart; no off-TUN Discord TCP sockets; reconnected via TUN |
| Physical network loss / recovery | PASS | Ethernet unplugged ~40 s; no off-TUN Discord TCP sockets; TUN traffic resumed after replug; status missed the short outage |
| Boot before service start | NOT TESTED | Service/tunnel up ~12 s after boot was observed, but no boot-window leak capture |
| VPN peer unreachable with physical network still up | NOT TESTED | Separate scenario from unplugging Ethernet |
| TUN creation failure | NOT TESTED | Not forced live |
| New Discord version / discovery race | NOT TESTED | Inventory limitation remains |
| Forced-failure uninstall/upgrade rollback | NOT TESTED | MSI success paths passed; rollback paths were not forced |
| WFP arbitration vs other hard/soft permits | NOT TESTED | No general interoperability proof from one Kaspersky PC |
| DNS/IPv6/UDP and browser/ECH packet-capture leak tests | NOT TESTED | No packet captures |

Persistent WFP enforcement was exercised live with the limited observations above.
Production readiness is not established; public release remains the maintainer's decision.

## 10. Dependency license assessment

[`THIRD_PARTY_LICENSES.md`](../../THIRD_PARTY_LICENSES.md), [`docs/audits/phase3_release.md`](../audits/phase3_release.md).

- 59 Go modules: GPL-3.0-or-later (SagerNet), MIT, BSD-3, Apache-2.0, ISC,
  MPL-2.0, Unlicense, CC0, mixed — **all compatible** with GPL-3.0-or-later.
- `LICENSE` = full unmodified GPLv3 (SHA-256 matches canonical gpl-3.0.txt).
- sing-box adds a name-use restriction (treated as a GPLv3 §7(e) term; see
  NOTICE/TRADEMARKS).
- **Maintainer decision needed:** embedded Wintun 0.14.1 is under the
  proprietary "Prebuilt Binaries License"; our use appears to fit its terms
  (same as upstream sing-box), but GPL-embedding and in-memory loading are
  unclear — legal review advised; verbatim license text still to be added.
- Versions in THIRD_PARTY_LICENSES were updated after the bump; texts of the
  bumped versions were not re-read.

## 11. Performance measurements

Live run 1 (voice active): working set ≈63–64 MB, private memory ≈80 MB,
600 handles, 24 threads. **CPU: NOT TESTED / not measured** (SYSTEM process CPU
time was not readable unelevated). These are single-machine observations, not a
performance benchmark; see the [live record](../testing/phase3_live_results_2026-11-22.md).

## 12. Remaining risks

1. Packet-capture leak checks and broader environments untested; live evidence
   is limited to TCP socket sampling on one IPv4-only Windows 11 PC.
2. Inventory-based fail-closed race for new Discord versions; DNS name leak via
   Windows DNS Client while stopped.
3. If the exe is deleted without `uninstall`, Discord stays blocked until
   `aurasplit recover` is run from a re-downloaded copy.
4. Browser Discord isolation not guaranteed.
5. Unsigned binary → AV heuristics (observed with Kaspersky on test binaries
   and self-install) and weaker UAC provenance; MSI runs on the same PC had
   no observed AV alert/start-up hold.
6. Wintun license ambiguity.
7. Last watcher fix not re-reviewed by Codex.

## 13. GitHub release readiness

| Item | Status |
|---|---|
| Repository scan for personal paths / credentials / configs / binaries | Historical scan PASS (`dist/` and `*.exe` git-ignored); not a current clean-worktree claim |
| LICENSE, NOTICE, THIRD_PARTY_LICENSES, README, CONTRIBUTING, SECURITY, TRADEMARKS, .gitignore | Prepared; repository: https://github.com/umut720s/aura-split-tr; project copyright is 2026 AURA Split TR contributors; private vulnerability reporting: see SECURITY.md |
| Build instructions / checksums | Prepared (`docs/BUILD.md`, `build.ps1`, `SHA256SUMS.txt`) |
| Release notes / known limitations | Prepared (`docs/RELEASE_NOTES_v0.1.0-beta.md`) |
| CI (build, test, vet, staticcheck, govulncheck, gofmt) | Prepared, NOT TESTED on GitHub |
| Release workflow (manual, draft-only, provenance, checksums) | Prepared, NOT TESTED; no auto-publish |
| Authenticode signing | NOT APPLICABLE / not configured |
| Real-network validation | PASS for §7/§9 live observations only; packet capture and broader coverage NOT TESTED |
| **Overall** | **Not production-ready; validation incomplete. Public release is the maintainer's decision** |

This report does not authorize or establish a public release.

## 14. Recommended next phase

1. Complete packet-capture leak tests (DNS/IPv6/UDP, boot window, browser/ECH)
   and forced-failure MSI uninstall/upgrade rollback paths.
2. Live-test the post-run-3 file picker, VPN_CONNECTING start-up grace and
   network-change probe; measure CPU and expand to native IPv6, other AVs and machines.
3. Complete remaining elevated/race checks and independent review of later fixes.
4. Settle remaining license/signing questions and validate release artifacts.
   Public release is the maintainer's decision; the beta is not production-ready.
