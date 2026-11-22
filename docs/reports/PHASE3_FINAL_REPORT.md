# AURA Split TR — Phase 3 Final Report

Date: 2026-11-22 · Target: `v0.1.0-beta` (not released) · Platform: Windows 11 x64

Status vocabulary: **PASS**, **FAIL**, **BLOCKED**, **NOT TESTED**, **NOT APPLICABLE**.
Nothing below is marked PASS on the basis of compilation alone.

## 1. Executive summary

- AURA Split TR builds, passes all non-privileged tests, and has **no known
  vulnerabilities in called code** (govulncheck: 27 → 0).
- A persistent **WFP fail-closed** layer, separate status states and a
  tunnel-only connectivity probe were implemented in this phase.
- Four audit workstreams (networking, Go security, reliability, release) and
  **three independent Codex (`gpt-6.1-sol`) review rounds actually ran**. All
  Codex findings from rounds 1–3 have source-level fixes. The fix for the
  round-3 finding (watcher queue) was made after round 3 and has **not** been
  re-reviewed by Codex.
- **No privileged or real-network test has been executed.** Installation, the
  Windows service, the TUN adapter, WFP enforcement and real VPN connectivity
  are **NOT TESTED**.
- **GitHub release readiness: BLOCKED** until the authorized real-world test
  plan passes. The application is **not** production-ready.

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
| Agent A — networking ([phase3_architecture.md](../audits/phase3_architecture.md)) | — | fail-open windows | — | — | Addressed by WFP layer (pending live test) |
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
  `uninstall` removes the policy before the exe; `run --debug` applies the same
  policy and permit.
- Status states: SERVICE_RUNNING, TUNNEL_INITIALIZED,
  VPN_CONNECTIVITY_VERIFIED, VPN_DEGRADED, VPN_DISCONNECTED, PROTECTION_ACTIVE.
  Probe: HTTPS to `www.cloudflare.com/cdn-cgi/trace` dialled only through
  `wg`, DNS resolved through the tunnel; IP never stored or logged.
- Service: BFE dependency, ordered/bounded shutdown, close-timeout is fatal
  (fresh process via SCM recovery), `Disable` before stop in disable/recover.
- Setup: policy applied before start, exe backup + rollback.
- Filesystem hardening fixes S-2…S-5; event-log and sing-box log redaction.
- Toolchain go1.26.11; x/net, x/crypto, grpc, compress, brotli bumped.
- WinDivert driver no longer embedded (`with_external_windivert`).
- Tests: ACL/privilege tests moved behind `acltests`; `internal/testutil`
  with retrying TempDir and open-handle assertions; many new unit tests.
- Release/compliance files and CI (see §10, §13).

## 5. Tests executed

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
| Real WFP calls, SCM lifecycle, TUN, recovery actions | NOT TESTED | Require admin + explicit user authorization |
| GitHub Actions workflows | NOT TESTED | Not run on GitHub (YAML parses locally) |

## 7. Real VPN validation status

| Item | Status |
|---|---|
| Proton VPN WireGuard | NOT TESTED |
| Cloudflare WARP | NOT TESTED |
| Generic WireGuard | NOT TESTED |
| VPN_CONNECTIVITY_VERIFIED probe against a real endpoint | NOT TESTED (unit-tested against fakes only) |
| Discord Stable / PTB / Canary, voice, screen share, update | NOT TESTED |

Plan: [`docs/testing/phase3_realworld_test_plan.md`](../testing/phase3_realworld_test_plan.md)
(15 scenarios, baseline capture, recovery, leak tests; all rows NOT TESTED).

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
- Status: **NOT TESTED** in a real network.

## 9. Fail-closed verification

| Scenario | Implemented | Verified |
|---|---|---|
| Boot before service start | Yes (persistent filters load with BFE) | NOT TESTED |
| Service crash / kill | Yes (persistent filters remain) | NOT TESTED |
| VPN peer unreachable, TUN up | Yes (traffic goes to `wg`, dropped) | NOT TESTED |
| TUN creation fails | Yes (no TUN permit → blocked) | NOT TESTED |
| New Discord version | Partial (watcher ~1 s + 60 s rescan) | NOT TESTED |
| `disable` / `recover` / `uninstall` rollback | Yes | NOT TESTED |
| WFP arbitration vs sing-tun hard/soft permits | Reasoned from source by Codex r1 | NOT TESTED |

Per the Phase 3 rule "if reliable fail-closed cannot be shown, block public
release": fail-closed is **implemented but unverified**, so release stays BLOCKED.

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

**NOT TESTED.** No numbers exist. Procedure and empty tables:
real-world test plan §5. No targets were invented.

## 12. Remaining risks

1. All privileged/network behaviour unverified (largest risk).
2. Inventory-based fail-closed race for new Discord versions; DNS name leak via
   Windows DNS Client while stopped.
3. If the exe is deleted without `uninstall`, Discord stays blocked until
   `aurasplit recover` is run from a re-downloaded copy.
4. Browser Discord isolation not guaranteed.
5. Unsigned binary → AV heuristics (observed with Kaspersky on test binaries)
   and weaker UAC provenance.
6. Wintun license ambiguity.
7. Last watcher fix not re-reviewed by Codex.

## 13. GitHub release readiness

| Item | Status |
|---|---|
| Repository clean of personal paths / credentials / configs / binaries | PASS (`dist/` and `*.exe` git-ignored; no commits yet) |
| LICENSE, NOTICE, THIRD_PARTY_LICENSES, README, CONTRIBUTING, SECURITY, TRADEMARKS, .gitignore | Prepared; repository: https://github.com/umut720s/aura-split-tr; project copyright is 2026 AURA Split TR contributors; private vulnerability reporting: see SECURITY.md |
| Build instructions / checksums | Prepared (`docs/BUILD.md`, `build.ps1`, `SHA256SUMS.txt`) |
| Release notes / known limitations | Prepared (`docs/RELEASE_NOTES_v0.1.0-beta.md`) |
| CI (build, test, vet, staticcheck, govulncheck, gofmt) | Prepared, NOT TESTED on GitHub |
| Release workflow (manual, draft-only, provenance, checksums) | Prepared, NOT TESTED; no auto-publish |
| Authenticode signing | NOT APPLICABLE / not configured |
| Real-network validation | BLOCKED |
| **Overall** | **BLOCKED** |

Nothing was pushed, published or released.

## 14. Recommended next phase

1. With explicit authorization, run the real-world test plan in a Hyper-V
   Windows 11 VM with a checkpoint (install → Proton/WARP/generic → Discord
   voice/update → kill/restart/reboot → disable/recover/uninstall), capturing
   `netsh wfp show filters` and physical-NIC packet captures.
2. Run elevated `acltests` and a `-race` build on a machine with mingw-w64.
3. Ask Codex to re-review the final watcher fix (and any fixes from step 1).
4. Fill placeholders, settle the Wintun license question, decide on code signing.
5. Only then create a private GitHub repo, let CI run, and produce a **draft**
   `v0.1.0-beta` for review before any public release.
