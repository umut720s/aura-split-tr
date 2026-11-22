# Phase 3 — open-source release readiness (licenses, build, CI)

Date: 2026-11-21/22. Scope: license inventory of the linked binary, LICENSE /
NOTICE / THIRD_PARTY_LICENSES / TRADEMARKS / CONTRIBUTING / SECURITY
disclosure, `.gitignore`, CI and manual release workflows, reproducibility,
repository hygiene scan. No Go code, `go.mod` or `go.sum` was changed. Nothing
was pushed or published.

## 1. Linked modules and licenses

Source: `go list -deps -tags with_gvisor,with_wireguard ./cmd/aurasplit`
(GOOS=windows, GOARCH=amd64), go.mod with sing-box v1.14.4, Go 1.26.5.
**59 third-party modules** + Go standard library + 2 embedded prebuilt binaries.
Full table with versions, copyright lines and verbatim texts:
`THIRD_PARTY_LICENSES.md`.

| License (SPDX) | Count | Modules (short) | GPL-3.0-or-later compatible |
|---|---|---|---|
| GPL-3.0-or-later | 11 | sing-box*, sing, sing-tun, sing-mux, sing-shadowsocks, sing-shadowsocks2, sing-shadowtls, sing-snell, sing-vmess, fswatch (SagerNet), sing-anytls | Yes (same license) |
| MIT | 22 | brotli, zerossl, bine, tfo-go, chi, render, go-ole, httphead, pool, gofrs/uuid, cpuid, libdns, bbolt, cors, smux, wireguard-go, ws, multierr, zap, zap/exp, wintun-go, lukechampine blake3 | Yes |
| BSD-3-Clause | 14 | ajg/form, fsnotify, utls, miekg/dns, netipx, x/crypto, x/exp, x/mod, x/net, x/sync, x/sys, x/text, x/time, protobuf (+ Go stdlib) | Yes |
| Apache-2.0 | 6 | certmagic, btree, acmez, netns, genproto rpc, grpc | Yes (GPLv3 only, which we are) — NOTICE of grpc reproduced |
| Apache-2.0 AND MIT AND BSD-3-Clause | 1 | sagernet/gvisor | Yes |
| BSD-3-Clause AND Apache-2.0 AND MIT | 1 | klauspost/compress (per-directory) | Yes |
| ISC | 1 | coder/websocket | Yes |
| MPL-2.0 | 1 | hashicorp/yamux (no Exhibit B notice) | Yes (MPL-2.0 §3.3) |
| Unlicense | 1 | logrusorgru/aurora | Yes |
| CC0-1.0 | 1 | zeebo/blake3 | Yes |
| LGPL-3.0-only OR GPL-2.0-only | embedded | WinDivert 2.2.2 `WinDivert64.sys` (via `sing-box/common/windivert`, `//go:embed`) | Yes, using the LGPL-3.0 option (sing-box states it uses that option) |
| LicenseRef Wintun Prebuilt Binaries License | embedded | `wintun.dll` 0.14.1 amd64 (via `sing-tun/internal/wintun`, `//go:embed`, loaded with memmod) | **Unclear — see 3.1** |

\* sing-box's LICENSE file is a GPL-3.0-or-later notice plus an added
sentence forbidding derivative works from using its name or implying
association without consent. Treated as a GPLv3 §7(e) term: do not use the
sing-box name for this project or suggest endorsement. Factual attribution is
kept.

**Verdict:** every Go module license is compatible with distributing the
combined binary under GPL-3.0-or-later. No incompatible license (e.g.
GPL-2.0-only code, SSPL, non-commercial) was found among Go modules.
Two items need a maintainer decision (3.1, 3.2).

Embedded binary hashes (from the module cache):

- `wintun.dll` amd64: `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce`
- `WinDivert64.sys`: `8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2`
  (matches `Asset64SHA256` in sing-box)

## 2. LICENSE / NOTICE

- The sing-box `LICENSE` file in GOMODCACHE is **not** the GPLv3 text (it is a
  14-line notice plus the name clause), so it was not copied.
- `LICENSE` is now the full GPLv3 text copied byte-for-byte from
  `sing-box@v1.14.4/common/windivert/assets/LICENSE.txt` (lines 175–848).
  Verified: 674 lines, 35 149 bytes, SHA-256
  `3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986`, which is
  the hash of the canonical `https://www.gnu.org/licenses/gpl-3.0.txt`.
- `NOTICE` holds the project header ("AURA Split TR — Copyright (C) 2026
  AURA Split TR contributors — GPL-3.0-or-later") and upstream attributions.

## 3. Items requiring the maintainer's decision

### 3.1 Wintun prebuilt DLL (embedded by sing-tun)

- License: Wintun Prebuilt Binaries License (WireGuard LLC), proprietary. The
  text is **not shipped** in sing-tun or in `golang.zx2c4.com/wintun`; it was
  read from the upstream wintun repository. Redistribution is permitted only
  when the DLL ships together with software that uses it solely through the
  `wintun.h` API; no modification, reverse engineering or "extraction";
  notices must stay; no endorsement using WireGuard/Wintun names.
- Our use: unmodified signed DLL embedded via `//go:embed` by sing-tun and
  loaded from memory through its API. This appears to fit the bundling
  condition (and is the same pattern sing-box's own Windows releases use), but
  in-memory loading vs. the "extract" restriction has not been confirmed by
  WireGuard LLC.
- GPL question: a non-GPL binary is embedded inside a GPL-3.0 executable. The
  GPL copyright holders of the embedding code (SagerNet) do this themselves,
  but for full clarity the maintainer could add a **GPLv3 §7 additional
  permission** for this project's own code allowing combination with the
  Wintun prebuilt DLL. Not added — decision needed (and ideally legal review).
- Action before release: paste the verbatim Wintun `LICENSE.txt` from the
  official `wintun-0.14.1.zip` into `THIRD_PARTY_LICENSES.md` (TODO marker
  left in the file).

### 3.2 WinDivert driver is linked although the app may not need it

`sing-box/common/windivert` is pulled in (via `common/tlsspoof` /
`protocol/bridge`) and embeds `WinDivert64.sys` (~kernel driver) into
`aurasplit.exe`. It is LGPL-3.0, so compatible, but it makes the binary larger
and more likely to trigger AV heuristics, and LGPL/GPL source obligations then
cover WinDivert 2.2.2 (upstream source: github.com/basil00/WinDivert tag
v2.2.2). sing-box offers a `with_external_windivert` build tag that removes
the embedded driver. Decision: keep as is (documented), or have the code
agents check whether the WinDivert path is reachable and, if not, add the tag
(requires a Go/build change outside this phase's scope).

### 3.3 Other decisions

- Project copyright in `NOTICE`: Copyright (C) 2026 AURA Split TR contributors.
- Repository: https://github.com/umut720s/aura-split-tr; private vulnerability reporting: see SECURITY.md.
- Disclosure timelines in SECURITY.md (7/14/90 days) and DCO sign-off
  request in CONTRIBUTING.md are proposals.
- Supported OS: README "Sınırlamalar" says Windows 10/11; the release notes
  say Windows 11 x64 only (per the release brief). Align one way.
- Release workflow always marks the draft as `--prerelease`; drop it for
  stable tags.
- Authenticode signing is not configured (documented in release.yml,
  README, SECURITY, release notes).
- Product name spelling: README title uses "AuraSplit TR", NOTICE/TRADEMARKS
  use "AURA Split TR". Pick one.

## 4. Reproducibility

`build.ps1` changes (reproducibility only): fixed `GOAMD64=v1`,
`GOFLAGS=-mod=readonly`, empty `GOEXPERIMENT`, `-ldflags -buildid=`, version
string validation, toolchain check against `go.mod` (`toolchain` line, else
`go` line; `-Strict` makes a mismatch fatal), `SHA256SUMS.txt` written with LF.

Measured (local, go1.26.5, `-Version 0.1.0-beta`): `build.ps1` output and an
independent `go build -a` with the same flags produced the identical SHA-256
`f722fad3ea2dfe702d60dca6ccdd31d644b2db9404aa23a22226eae1cb3c74ee`. This
was a same-machine check only; a cross-machine/CI comparison has not been run.
The hash will change with any source or go.mod change.

Recommendation: add `toolchain go1.26.11` (or whatever the go.mod bump uses)
to pin the toolchain; CI uses `go-version-file: go.mod`.

## 5. CI / release workflows

- `ci.yml` (push to main, PR): windows-latest, `permissions: contents: read`,
  checkout without persisted credentials, setup-go from `go.mod`,
  `go mod verify`, gofmt check, build with tags, vet, tests (default tags and
  release tags), staticcheck v0.8.2, govulncheck v1.10.0.
- `release.yml`: `workflow_dispatch` only, tag input validated, checks out the
  tag, `build.ps1 -Strict`, zip + exe + `SHA256SUMS.txt`, workflow artifact,
  `actions/attest-build-provenance`; optional second job creates a **draft**
  release with `gh release create --draft --verify-tag` (only that job has
  `contents: write`). Never publishes.
- All actions pinned to full commit SHAs resolved with `git ls-remote` on
  2026-11-21: checkout v7.0.1, setup-go v7.1.0, upload-artifact v7.0.2,
  download-artifact v8.0.2, attest-build-provenance v4.2.2.
- Not run on GitHub (no repository exists); YAML parses locally. govulncheck
  will fail CI until the pending dependency/toolchain bump lands.

## 6. Repository hygiene scan

- `dist/aurasplit.exe` and `dist/SHA256SUMS.txt` exist locally — now ignored
  by `.gitignore` (`dist/`, `*.exe`). No commits exist yet, so nothing to
  purge from history.
- No `.conf`, `profile.json`, `tunnel-state.json`, logs, keys or tokens found.
- No local user name or working-directory path found in tracked text files or
  in `dist/aurasplit.exe`. The binary contains `C:\Users\Jason A. Donenfeld`
  (upstream Wintun PDB path, already documented) and the redaction placeholder
  `C:\Users\<user>`.
- Test fixtures use synthetic paths (`C:\Users\Some Name`, `C:\Users\u`,
  `C:\Users\bob`) — fine.
- `docs/audits/govulncheck_baseline_2026-11-21.txt`: PowerShell-captured
  output (UTF-8 BOM, CRLF, includes PowerShell error-record noise). No
  personal paths. Consider regenerating it cleanly (plain `govulncheck` output)
  before publishing.

## 7. Still to do after the go.mod bump

- Re-run the module listing and regenerate `THIRD_PARTY_LICENSES.md` (module
  versions will change; the generator used was a one-off script, the command
  is in the file header and in docs/BUILD.md).
- Re-check that no newly added module has a different license.
- Fill `<!-- FAILCLOSED_STATUS -->` in the release notes.
