# Leak evidence: P0-B / SEC-013, SEC-014

These tools classify **one reviewed scenario window**, not a release-wide security
guarantee. Use an isolated Windows test environment. Capture requires Administrator
and exclusive use of pktmon; it removes existing pktmon filters. It never modifies
the service, routing, WFP or VPN configuration or performs scenario disruptions.

## Capture privately

Choose an access-restricted folder **outside the repository**. A new private run
folder gets an ACL allowing the invoking administrator and SYSTEM. No profiles,
private keys, process command lines or environment inventories are read. Full packet
payloads can contain application secrets; use synthetic accounts/data and avoid
PowerShell transcription. Never pass keys or whole configurations to these tools.

Inspect `Get-NetAdapter` and `pktmon list --all`. Verify the AURA TUN's component ID
independently from physical NICs; `-TunComponentId` is an operator-supplied mapping,
not automatic proof. Physical capture starts without an initial TUN. Activate protection only after the capture-active message. Supply the verified TUN component later with `-TunComponentFile <private-json>` containing `{"component_id":42}`, or a previously verified `-TunComponentId`. Snapshots attach TUN without restarting the all-component recorder. Unsupported Wintun
visibility needs a validated alternative recorder; this tool stays INCONCLUSIVE.
Supply the actual **runtime resolved peer literal IP and UDP port**, independently
verified against engine/provider telemetry. A profile hostname's DNS result may
differ. Optional private `-PeerFile` contains only `{"ip":"literal","port":51820}`;
these allowlisted fields are reread each sample. Update on runtime peer changes.

```powershell
.\tools\leaktest\capture.ps1 -Scenario L1 -Seconds 240 `
    -OutDir E:\PrivateEvidence -TunComponentFile E:\PrivateEvidence\tun-component.json `
    -PeerIP <runtime-peer-IP> -PeerPort <runtime-peer-port>
```

Use the new `L1_<random>` folder for controls. One global recorder captures all
components, including newly active NICs. Every mapped physical NIC and the TUN
are converted **separately**, for every segment. All active physical NICs count,
including secondary Ethernet/Wi-Fi/mobile; ambiguous MAC mapping is incomplete.

Exact native commands, also recorded with UTC invocation times in `commands.jsonl`:

```text
pktmon list --all
pktmon filter remove
pktmon start --capture --comp all --type all --pkt-size 0 --flags 0x033 --file-name <run>\capture.etl --file-size 1024 --log-mode multi-file
pktmon counters --json
pktmon stop
# Every segment, every mapped component C:
pktmon etl2txt <segment.etl> --out <segment.etl.txt> --timestamp --metadata --verbose
pktmon etl2txt <segment.etl> --stats
pktmon etl2pcap <segment.etl> --component-id C --out <segment>-ifI-cC.pcapng
pktmon etl2pcap <segment.etl> --component-id C --drop-only --out <segment>-ifI-cC-drops.pcapng
```

`etl2pcap` produces **pcapng**. Conversion loses component/stack/drop context:
retain ETLs, verbose edge text, statistics, drop-only files and mappings together.
See Microsoft's [conversion contract](https://learn.microsoft.com/windows-server/networking/technologies/pktmon/pktmon-pcapng-support)
and [capture options](https://learn.microsoft.com/windows-server/administration/windows-commands/pktmon-start).

`run.json` lists interface index/GUID/component, addresses and all segments.
`snapshots.jsonl` records UTC adapters/routes, peer endpoints, PID/exe/start time,
TCP tuples and UDP local endpoints/owners every second by default, preserving
endpoint changes. `process-events.jsonl` records observed starts/stops: stop is a
sampling bound, not exact OS exit time; a process present at the end has no invented
stop. Short-lived sockets/processes may be missed. Denied exe/start-time access,
PID reuse or ambiguous wildcard UDP ownership cannot yield trusted attribution.

Packet reports preserve timestamps, pcapng interface/direction flags and mapped NIC
identity. Where native direction flags are absent, direction is derived from that
NIC's addresses and its basis reported. Raw verbose text preserves Tx/Rx/edge data.
Review final physical egress edges (or correlate an external recorder), particularly
with offloads, relays, AV, virtual switches and TUN recreation. Sampling cannot
rule out sub-sample identity changes. Never reuse a TUN component by alias alone.

## Two positive controls in EVERY scenario

Use separate non-Discord test executables and a maintainer-owned remote UDP
receiver. Run both controls sequentially in the healthy period after the activation marker
**within the same capture**, and again after recovery. They need not succeed during a VPN cut.

On a clock-synchronized remote host (allow only intended test traffic):

```text
python -I -B receiver.py --bind <receiver-IP> --port 9000 --expected-tunnel-source <verified-VPN-exit-IP> --seconds 900 --out <new-private-receipts.json>
```

Independently verify the VPN exit IP; it must differ from the direct public source.
The receiver records nonce/source/time without keys. On Windows run **unenrolled**
`powershell.exe` for direct, and a **distinct existing executable already configured
to use WG** for tunnel (for example `pwsh.exe` in the existing profile's
`extra_process_names` test setting, only in the isolated environment):

```powershell
powershell.exe -NoProfile -File .\tools\leaktest\control.ps1 -Mode direct `
    -RunDir <private-run-folder> -LocalIP <physical-local-IP> `
    -RemoteIP <owned-receiver-IP> -RemotePort 9000
pwsh.exe -NoProfile -File .\tools\leaktest\control.ps1 -Mode tunnel `
    -RunDir <private-run-folder> -LocalIP <TUN-local-IP> `
    -RemoteIP <owned-receiver-IP> -RemotePort 9000
```

Binding a TUN address **does not guarantee tunnelling**. Tools do not edit profiles
or enroll executables. Keep the direct executable unenrolled; do not enroll shared
production shells. Without a configured independent tunnel process, INCONCLUSIVE.

The sender holds UDP open and sends a random nonce for 8 seconds; `controls.jsonl`
records PID/start-time, tuple, nonce and UTC interval. Direct requires that nonce
with the recorded non-Discord owner on a physical NIC. Tunnel requires it on TUN,
no plaintext nonce flow on any physical NIC, WireGuard type-4 UDP transport to the
then-current peer during its interval, and remote nonce telemetry from the verified
VPN exit. Handshake/keepalive alone is insufficient. Inspect receiver records and
merge `tunnel_receipts` into private review JSON. This is correlation evidence,
not WG decryption; review timestamps, edges and concurrent flows too.

## Analyze, then review

```powershell
python -I -B tools/leaktest/analyze.py <private-run-folder>\run.json
# Inspect PRIVATE report/ETLs/stats/counters and receiver/client telemetry.
# Create private review.json; use NEW outputs (no evidence overwrites):
python -I -B tools/leaktest/analyze.py <private-run-folder>\run.json `
    --review <private-review.json> --json <new-private-report.json> `
    --export <new-redacted-export.json>
```

First analysis intentionally returns INCONCLUSIVE. Review fields are explicit
operator assertions backed by retained evidence; they cannot override machine gates:

```json
{
  "loss_checked": true, "capture_loss": false,
  "coverage_checked": true, "scenario_stimulus_observed": true,
  "encrypted_metadata_checked": true, "outer_correlation_checked": true,
  "flow_labels": {"packet-record-id": "unrelated"},
  "tunnel_receipts": {"control-nonce": {
    "received_via_tunnel": true, "evidence": "receiver-records-sha256:..."
  }}
}
```

Check EVERY segment's ETW buffer/event loss, all NIC/TUN mappings/edges throughout
the window, clocks, actual scenario/class/protocol stimuli, encrypted DNS/ECH/QUIC
caller telemetry and receiver correlation. Unknown loss is not zero. Packet drops
and recorder loss differ; either makes this tool INCONCLUSIVE, even intentional
policy drops. Label stable packet-record IDs from unchanged inputs `discord` or
`unrelated` only with retained caller/endpoint evidence. Browser or engine ownership
alone cannot establish unrelated encrypted traffic; relay flows need original
caller telemetry. Unknown shared-CDN traffic must not be labelled benign.

- **PASS:** both controls, all machine gates and explicit evidence reviews passed;
  all physical outbound flows attributed/qualified and no protected escape in
  this scenario window. Does not transfer to other classes/protocols/variants.
- **FAIL:** complete reviewed evidence contains an attributed protected physical
  flow or an attributed flow carrying a related name/destination.
- **INCONCLUSIVE:** empty/missing interface capture, incomplete run/inventory,
  unknown loss/drop evidence, drops/truncation/fragments, parser gaps, unknown
  direction/owner, opaque unreviewed traffic, absent controls or scenario telemetry.
  These gates take precedence over FAIL; confirmed offending records remain in
  `leaks` for investigation.

No Discord domain/SNI seen is never sufficient for PASS. Inventory is read directly
from `internal/engine/config.go`: suffix `DiscordDomains` plus exact `DiscordHosts`.
The upload host does not widen to `storage.googleapis.com` or `googleapis.com`.
Keep that source available offline. QUIC/ECH/encrypted DNS are not decrypted.
Unknown flows to related destinations stay INCONCLUSIVE.

Exit **0 means only analysis ran**, regardless of result. Exit 1 means invalid
inputs or read/write failure. Inspect `result`, never infer security from exit code.

## L1..L14 windows

Separate runs per variant; both controls and private UTC stimulus notes each time.
Follow all class/protocol requirements in `docs/audits/network_leak_matrix.md`.
Faults are performed externally by the maintainer, never by these scripts.

| Scenario | Seconds | Required actions/evidence |
|---|---:|---|
| L1 enable/baseline | 240 | All classes; pre-existing and new TCP/WebSocket/download/voice across enable. |
| L2 service stop | 240 | Baseline, stop, all-class/DNS reconnect, restore; unrelated direct continues. |
| L3 NIC handover | 300 | Both Ethernet/Wi-Fi, same-NIC DHCP/gateway change, first packets. |
| L4 browser | 240 | Login/upload/download/CDN and unrelated tabs; HTTP3/WebRTC/proxy variants. |
| L5 IPv6 | 240 | Real dual-stack/IPv4-only WG, unrelated IPv6-only target; zero traffic is not proof. |
| L6 VPN-only cut | 900 | External peer-UDP-only drop; direct stays up; >=3 probe failures, rebuild/recovery. |
| L7 crash | 240 | Exact SCM PID crash, active TCP/UDP, restart/reconnect and recovery controls. |
| L8 update | 900 | Real update/installer, first new exe/network, each helper; absent stimulus inconclusive. |
| L9 reboot | 120 pre + 240 post | External/validated boot recorder mandatory; post-logon is not boot coverage. |
| L10 sleep/resume | 600 | External recorder for sleep gap/first resume packets, NIC/peer changes. |
| L11 QUIC/UDP | 240 | Voice/share/helpers/HTTP3/WebRTC, all UDP ports/callers, fault variants separately. |
| L12 DNS | 180 | Cold caches, A/AAAA UDP/TCP53, exact upload host, unrelated query; running/stopped. |
| L13 encrypted DNS | 240 each | Native/browser DoH/DoT/DoQ/ECH; actual query-to-flow telemetry. |
| L14 TUN removal | 600 | Isolated VM removal/recreation; physical stays up, new GUID/index/component/first flow. |

This local recorder is not boot-capable and cannot certify sleep continuity or
sub-sample identity changes. Those windows need external evidence; missing mapping
or continuity remains INCONCLUSIVE. Recreated TUN needs a newly verified component.
L9/L10 always include `external_continuity_not_analyzed`: this classifier does not
ingest an external boot/resume recorder. Assess those full windows separately;
an operator review flag cannot turn the local recording into continuous evidence.

## Privacy and fixtures

Raw captures/sidecars, receiver logs, reviews and detailed reports stay private
outside Git. Separate export allowlists only canonical scenario/result, fixed
reason codes and counts: no IPs (peer/remote/NAT included), usernames, hostnames,
paths, PIDs, payloads, nonces or arbitrary review text. Console output uses the same
allowlist. Inspect before sharing. Export is a summary, not replayable evidence;
never paste private report sections into it.

Fixtures use system temp; no admin, network or capture:

```powershell
python -I -B -m pytest tools/leaktest/test_analyze.py
# If pytest is absent:
python -I -B tools/leaktest/test_analyze.py
```

Fixture success validates tooling only. **All real captures remain NOT TESTED.**

## Executable contract and L1 activation window

`internal/manifest` is the sole executable specification. Regenerate the path-free
`executable_manifest.json` with `go run ./internal/manifest/cmd/export` (UTF-8,
no BOM); `aurasplit.exe manifest --json` exports identical bytes. Go parity tests
reject a stale generated file. The recorder embeds this contract in `run.json`;
the analyzer requires an identical contract and uses its regex for protected
flows and unrelated control eligibility. No basename or directory-prefix fallback.
Only the four supported install roots, known helper paths and installers in those
roots/SquirrelTemp qualify. Downloads and arbitrary Discord* roots do not.

For L1 keep existing Discord flows running, start the recorder with no TUN,
then activate protection after the physical-capture message. Independently verify
the new TUN component and publish its ID in the private mapping file.
All-component recording is already active, preserving the initial enable interval.
Keep capture running through retirement/restart and both controls. Missing TUN
mapping, empty TUN packets or missing required TUN control evidence is INCONCLUSIVE;
never replace the initial interval with a later healthy-only capture.


## Aktivasyon sınırı ve temel kayıt

Kayıt, korumadan önce başlar. Politika uygulandı ve tünel açık bilgisini güncel
servis durumundan doğrulayın; açık TUN bileşenini eşleyin. Ardından yakalayıcı
penceresinde **A** tuşuna basın. `capture.ps1` örneklemeyi durdurmadan UTC zamanı,
`capture_operator_confirmation`, `policy_applied: true`, `tunnel_up: true`
alanlarını `run.json.activation` içine yazar. Bu, operatörün politika doğrulamasına
dayanır; otomatik heartbeat/politika readback kanıtı değildir. İşareti aktivasyonun
hemen ardından, senaryo uyaranları ve iki pozitif kontrolden önce verin.
Yönlendirilmiş stdin ile işaret girilemez; kayıt INCONCLUSIVE kalır.

Analiz işaretin kaynağını, iki onayı ve kayıt zaman aralığını denetler. Eksik veya
geçersiz işaret `verified_activation_boundary_missing` ile INCONCLUSIVE olur.
İşaret öncesi akışlar özel raporda `phase: baseline` ve `baseline` kayıt kimlikleri
olarak korunur; sızıntı listesine katılmaz. İşaret anı dahil sonraki fiziksel çıkışlar
sızıntı değerlendirmesine girer. Pozitif kontroller de bu aralıkta olmalıdır.
Kalite/attribution kapıları tüm kayıt için sürer; temel kayıt hataları silinmez.
Sonuç yalnızca işaret-son aralığını kapsar; önceki trafiğin güvenli olduğu iddiası yoktur.

Varsayılan Discord basename/Downloads installer yönlendirme fallback'leri engine'de
sürer; bunlar analyzer'ın doğrulanmış executable manifestini genişletmez.
Manifest dışı şifreli akışlarda caller telemetry gereklidir. Canlı L1 ve klavye/
pktmon/TUN işaret akışı **NOT TESTED**; sentetik sınır testleri ağ kabulü değildir.
