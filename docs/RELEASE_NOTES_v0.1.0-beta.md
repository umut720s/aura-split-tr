# AURA Split TR v0.1.0-beta — release notes (DRAFT)

> **Draft.** Not published. Fill in the TODO markers and re-check every
> statement against the tagged source before publishing.

Planned first public beta. **Platform: Windows 11 x64 only** (tested target; Windows 10
may work but is not supported in this beta).

## Canlı test özeti / Live validation

Canlı testler **tek Windows 11 x64 PC'de, IPv4-only Ethernet, Kaspersky Plus
açık ve imzasız beta** ile yapıldı. TCP soket gözlemi paket yakalama değildir;
UDP/DNS ve açılış penceresi doğrulanmadı. Run 3 sonrası dosya seçici,
`VPN_CONNECTING` başlangıç toleransı ve ağ-değişimi probe düzeltmesi uygulandı,
**henüz canlı test edilmedi**. Beta üretime hazır değildir; herkese açık sürüm
kararı bakımcıya aittir.

All live tests used **one Windows 11 x64 PC, IPv4-only Ethernet, Kaspersky Plus
active, unsigned beta**. Details and chronology:
[live runs 1–3](testing/phase3_live_results_2026-11-22.md).
**Not production-ready**; public release is the maintainer's decision.

| Category | Result / observation method |
|---|---|
| **Observed — Discord** | Proton, WARP and generic WireGuard (a Proton `.conf` used for the generic option): established Discord TCP sockets sampled with `Get-NetTCPConnection` had TUN local address `172.19.0.1`. Voice join succeeded (user-observed); UDP path inferred, not packet-captured. |
| **Observed — fail-closed** | Per-second socket sampling during `stop` (25 s), `taskkill` crash (~4–5 s until SCM restart) and ~40 s physical network outage: 0 Discord TCP sockets outside the TUN. Socket-level observation, not packet capture; UDP and DNS not captured. |
| **Observed — reboot** | Service enabled: service/tunnel up ~12 s after boot; Discord TCP via TUN after user opened it. No boot-window leak capture. |
| **Observed — lifecycle/config** | `disable`/`start`, MSI install/upgrade/uninstall passed. After uninstall: 0 AURA provider filters/sublayer in `netsh wfp show filters/state`; IP addresses, DNS servers and routes identical to pre-install capture; `%ProgramData%\AuraSplitTR` (private key) removed. Invalid config rejected without changing the running profile, WFP policy or Discord TUN routing. |
| **Not yet tested** | Packet-capture leaks (DNS/IPv6/UDP, boot window, browser/ECH); forced-failure MSI uninstall/upgrade rollback; repair/error paths; CPU measurement; native IPv6 hosts; other AV products; more than one machine. |
| **Implemented, not live-tested** | Post-run-3 file picker, `VPN_CONNECTING` start-up grace and network-change probe. Run 3 status missed the ~40 s outage. |

Live-test bugs fixed:

- IPv6-less host WireGuard bind: connection path corrected and re-verified live.
- Browser IPv6 outage: host-aware TUN/DNS configuration corrected and re-verified live.
- WARP host-name endpoint handshake: IP resolution corrected and re-verified live.
- AV hold on self-install: moved to MSI; no AV alert/start-up hold observed in MSI runs on the same PC.

## Features (implemented; live validation limited to the scope above)

- Routes only Discord traffic through a WireGuard tunnel (embedded sing-box
  v1.14.4, gVisor TUN stack):
  - Discord desktop app (`Discord.exe`, PTB, Canary), `Update.exe` and Discord
    installers, by process;
  - listed Discord domains from any process, including browsers.
- Everything else (games, other sites and apps) uses the direct connection.
- Providers: Cloudflare WARP (automatic registration; only the public key is
  sent), Proton VPN WireGuard `.conf` (Free/Plus), any standard WireGuard `.conf`.
- **Installed with a standard Windows Installer package**
  `AuraSplitTR-0.1.0-beta-x64.msi` (per-machine, x64, built with WiX 5.0.2):
  Windows Installer copies `aurasplit.exe` to `%ProgramFiles%\AuraSplitTR`,
  registers the `AuraSplitTR` service (LocalSystem, manual start until
  configured, depends on BFE, restart on failure) and adds the Start Menu entry
  "AURA Split TR - Yapılandır". Uninstall via Settings > Apps removes the WFP
  policy first (`recover --msi`), then the service, the files and
  `%ProgramData%\AuraSplitTR` (profile with the private key). Upgrades keep the
  profile; downgrades are refused. `aurasplit.exe` no longer copies itself or
  creates a service. **MSI install/upgrade/uninstall passed live** in the scope
  above; repair and forced-failure rollback paths remain **NOT TESTED** live.
- Runs as a Windows service (`AuraSplitTR`), starts automatically at boot once
  configured, no window or tray icon.
- Turkish configuration wizard (`setup`, Start Menu shortcut; runs only from
  the installed copy, checks that the service really reaches RUNNING and
  explains a service stuck in START_PENDING); commands `status`, `start`,
  `stop`, `restart`, `disable`, `recover`, `run [--debug]`, `version`.
  `uninstall` now only explains how to uninstall through Windows.
- Upgrading from a pre-release self-installing build: run that build's
  `aurasplit.exe uninstall` first, then install the MSI.
- If the tunnel cannot start, Discord traffic and Discord DNS are blocked
  (not sent direct) while the service retries.
- `status` reports service state and tunnel state separately.
- Key material stored in an ACL-protected `%ProgramData%\AuraSplitTR\profile.json`
  (SYSTEM + Administrators only); secrets are never logged.
- Size-capped logs (2 MB + 2 backups, level `warn`, user names redacted).
- Folder trust checks and quarantine instead of deletion for untrusted content.
- No telemetry.

## Known limitations

- **Fail-closed is limited; live evidence is TCP socket sampling only.** Persistent
  Windows Filtering Platform filters (exercised on a real machine as above)
  block the **discovered** Discord
  desktop executables (`%LOCALAPPDATA%\Discord*\Update.exe` and every
  installed `app-*\Discord*.exe`, all user profiles) outside the tunnel, also
  at boot before the service starts, while it is stopped or crashed, and while
  the tunnel is down. Fail-closed applies only to that discovered inventory.
  Remaining windows:
  - a new Discord version is added about 1 s after its directory/executable
    appears (directory watcher; 60 s rescan as backstop; a failed watch is
    retried with a 1 s to 60 s backoff). If it connects within that window
    **while the tunnel is down**, it can go direct;
  - a version staged while the service is stopped is not covered until the
    service starts and rescans (`Update.exe` is blocked while stopped, so the
    updater cannot download one then; a manually copied or just-downloaded
    version can still fall in this window);
  - Discord in a browser, Discord copies outside `%LOCALAPPDATA%\Discord*`
    and installers are **not** covered by the WFP filters (they are
    tunnelled by process/domain only while the service runs);
  - while the service is stopped, Discord name lookups made by the Windows
    DNS Client (Dnscache) can reach the ISP resolver in clear text (the
    connections themselves are blocked);
  - the policy is bounded (256 executables, 32 per profile, existing plus
    new); beyond that new executables are not added and `status` reports
    incomplete coverage; filters that WFP reports as disabled are not counted
    as protection.
  Stop/crash/physical-outage TCP observations passed; the remaining windows
  above, UDP/DNS/IPv6 and boot-window packet-capture checks are not validated.
  See [SECURITY.md](../SECURITY.md).
- DNS protection covers the listed Discord domains only.
- "Tunnel started" means the configuration was applied; the WireGuard
  handshake is not verified.
- May conflict with other VPN/TUN clients (Proton VPN app, WARP app, etc.).
- Discord must be fully restarted after setup or provider changes.
- Requires administrator rights.
- **v0.1.0-beta binaries (exe and MSI) are NOT Authenticode-signed.** Windows
  SmartScreen and antivirus products may warn. Verify each file's SHA-256 against
  `SHA256SUMS.txt` and its GitHub build provenance attestation (see below).
  Authenticode signing is planned for a later release.
- **Antivirus false positives are possible.** The binary is an unsigned Go
  executable that runs as a service, adds persistent WFP filters, creates a TUN
  adapter (embedded Wintun DLL loaded from memory). In a live test on a Kaspersky-protected PC the former
  self-installing setup was flagged by a behaviour detection and the new
  service process was held in START_PENDING; MSI installation was subsequently
  re-tested on that PC with no observed AV alert/start-up hold. Other AV products
  remain untested; signing is still planned. Report false positives
  to the AV vendor; never disable your AV or add exclusions.
- The embedded upstream Wintun DLL contains its author's PDB build path.
- Not a privacy/anonymity tool: only Discord traffic is tunnelled; the VPN
  provider can see Discord connection metadata.

## Verification

Official files are built by the manual release workflow from tag
`v0.1.0-beta`:

- `AuraSplitTR-0.1.0-beta-x64.msi` (the installer; MSI ProductVersion 0.1.0)
- `aurasplit-0.1.0-beta-windows-amd64.zip` (exe + LICENSE, NOTICE,
  THIRD_PARTY_LICENSES.md, TRADEMARKS.md, README.md, SECURITY.md)
- `aurasplit.exe` (for verification and for `recover` if the installed copy
  is lost; it refuses `setup` outside the MSI installation)
- `SHA256SUMS.txt`

```powershell
(Get-FileHash .\AuraSplitTR-0.1.0-beta-x64.msi -Algorithm SHA256).Hash.ToLower()
Get-Content .\SHA256SUMS.txt
gh attestation verify AuraSplitTR-0.1.0-beta-x64.msi -R umut720s/aura-split-tr
gh attestation verify aurasplit.exe -R umut720s/aura-split-tr
```

For each downloaded file, compare its SHA-256 with the matching entry in
`SHA256SUMS.txt` and run `gh attestation verify <file> -R umut720s/aura-split-tr`
(replace `<file>` with its path). Do not run a file if either verification fails.

TODO(maintainer): paste the SHA-256 values from the workflow run here.

Reproduce the build: see docs/BUILD.md (same Go toolchain as `go.mod`). The
exe is byte-reproducible; the MSI is not (new GUIDs/timestamps per build) —
compare the exe inside it.

## License

GPL-3.0-or-later. Third-party components and their licenses:
THIRD_PARTY_LICENSES.md. Not affiliated with Discord, Proton, Cloudflare,
WireGuard or sing-box (TRADEMARKS.md).

## Reporting problems

Bugs: GitHub issues (redact user names, IPs, never attach `.conf` or
`profile.json`). Security issues: privately, see SECURITY.md.
