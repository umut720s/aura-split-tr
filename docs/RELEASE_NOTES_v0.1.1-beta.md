# v0.1.1-beta (experimental)

**Deneysel, üretime hazır değildir / Experimental, not production-ready.** Exe/MSI Authenticode imzasızdır; bağımsız paket düzeyi doğrulaması yoktur. Riski size ait olmak üzere kullanın / Use at your own risk.

## v0.1.0-beta sonrası değişiklikler / Changes since v0.1.0-beta

The published v0.1.0-beta tag remains unchanged as history. This summary derives from git log --oneline v0.1.0-beta..HEAD and the linked records. The older release-note body is retained as history, not as evidence that these changes shipped in that tag.

- **Per-class readiness/status (P0 wave 1, 7199e1d):** desktop, updater, helpers, installers, browser and DNS are reported separately. SERVICE_RUNNING, TUNNEL_INITIALIZED, VPN_CONNECTIVITY_VERIFIED and PROTECTION_READY are distinct. Readiness requires four-layer WFP readback, complete permit coverage and the old-flow gate; failed permit closures are retained and retried.
- **Single executable manifest:** WFP discovery, engine routing, status, process-close eligibility and leak-test classification share one manifest. Known Discord/PTB/Canary/Development roots, root updater, app-version helpers and known root/SquirrelTemp installers are covered within discovery/capacity bounds. Unknown/custom paths have no persistent-block assurance.
- **Helper/installer WFP enrollment:** known helpers and installers join persistent executable blocking and dynamic tunnel permits. The enrollment-before-connect race remains open.
- **Old-flow gate with consent-based Discord close:** pre-enrollment processes keep readiness pending; PID/creation-time and enrollment generations track them. TCP tuple resets were removed. Closing exact-manifest processes requires explicit consent (default No), with identity rechecked through the same handle. Fully quitting/restarting Discord remains necessary when old connections persist.
- **Leak-test tooling:** the existing toolkit gained separate physical/TUN capture, process attribution, activation boundaries, positive controls and manifest-driven classification. Missing or ambiguous evidence stays INCONCLUSIVE. Tooling is not a completed packet-level acceptance test.
- **R3 fixes (edb457b):** identified system processes no longer hold the old-flow gate; unresolved manifest-named candidates still do, and matched session-0 processes retain creation-time gating. Non-interactive console prompts exit with code 3; setup waits for Enter on exit. Turkish status encoding and unreadable discovery-path reporting were corrected. Windows adapter/route diagnostics were added.
- **Multi-NIC egress health/failover (aaec3fd):** bound TCP and DNS checks assess the selected default-route NIC every 30 seconds and on probe/interface events. TCP-confirmed reachability determines health; DNS health is tracked separately. Three failed samples can trigger a rebuild pinned to another healthy NIC; three successful samples permit return to automatic selection, with bounded switching. Direct traffic, WireGuard transport and local DNS follow the selection; IPv6 capability follows the pinned NIC. Status reports egress/failover state. **Not tested live.**
- **MSI packaging/maintenance:** a small embedded-only cleanup helper reduces MSI size (recorded approximately 51 MB to 14 MB); explicit CAB compression and upgrade/uninstall/reinstall observations were recorded. This does not validate forced-failure rollback/recovery paths.
- **Documentation/CI:** isolation audit and remediation records, readiness assertions, CI test-failure annotations and experimental-release limitations were updated.

WARP registration and the earlier IPv4-only-host/IPv6 transport fixes predate v0.1.0-beta; they are not new fixes in this release. The post-tag IPv6 change makes capability selection follow the pinned egress NIC; native IPv6 operation remains unverified.

**Türkçe özet:** sınıf bazlı hazırlık, ortak executable manifesti, helper/installer WFP kaydı, onaylı Discord kapatma kapısı, sızıntı testi araçları, R3 düzeltmeleri ve çoklu adaptör sağlık/failover eklendi. Bunlar paket düzeyinde izolasyon kabulü değildir; üretime hazır değildir. Çoklu adaptör failover'ı canlıda doğrulanmadı.

Sources: [P0 progress](audits/security_remediation_plan.md#p0-progress), [isolation audit](audits/network_isolation_audit.md), [live results](testing/phase3_live_results_2026-11-22.md), [multi-NIC analysis](audits/r3_multinic_analysis.md), [leak-test tooling](../tools/leaktest/README.md). Publishing this experimental release does not close the security acceptance gate.

## Bilinen sınırlar

- **Tarayıcı Discord ve DNS best-effort'tur; fail-closed değildir (P0-F/P0-G açık).** Hizmet dururken tarayıcı bağlantıları ve açık metin DNS sorguları doğrudan çıkabilir; çalışan hizmet de tüm alan adlarını/şifreli DNS'i kapsamaz.
- **Engine süreç kimliğini kaybederse bir Discord akışı doğrudan yönlendirilebilir (P0-D açık).** Tünelin bağlı olması izolasyon kanıtı değildir.
- **Yeni bir Discord sürümü enrollment tamamlanmadan bağlanabilir:** kısa bir yarış penceresi vardır. Yardımcılar ve kurucular yalnızca manifestteki bilinen yollar ve kapasite sınırları içinde kapsanır; özel/Downloads/diğer Temp yolları için kalıcı engelleme güvencesi yoktur.
- **Koruma açılmadan önce kurulmuş bağlantılar kalabilir.** Etkinleştirdikten veya sağlayıcı değiştirdikten sonra Discord'u sistem tepsisinden tamamen kapatıp yeniden açın; yalnız pencereyi kapatmak yeterli değildir.
- **Çoklu ağ adaptörü:** sağlık durumuna göre çıkış failover'ı eklendi, **canlı test edilmedi**. İki adaptör açıkken İnternet/DNS kesilirse `aurasplit.exe stop` veya `aurasplit.exe disable` çalıştırın. `stop` kayıtlı programların engellerini tutar; `disable` engelleri kaldırır ve Discord doğrudan bağlanabilir.
- **Test kapsamı:** tek Windows 11 x64 bilgisayar; test edilen sağlayıcılar WARP ve Proton. Genel WireGuard seçeneği yalnız Proton `.conf` ile denendi; diğer genel WireGuard sağlayıcıları canlı test edilmedi. Windows 10, yerel IPv6 ve diğer makineler/antivirüsler doğrulanmadı.
- **Exe/MSI Authenticode imzasızdır; antivirüs/SmartScreen uyarabilir.** Antivirüsü asla kapatmayın veya istisna eklemeyin. SHA-256 ve `gh attestation verify` ile doğrulayın.
- **Kapsamlı paket yakalamalı sızıntı testleri tamamlanmadı; bağımsız paket doğrulaması yoktur.** `tools/leaktest` mevcuttur. Eski run 5 sınırlı yakalamalar içerir ve tarayıcı/DNS kaçışını kaydeder; genel bir “sızıntı yok” sonucu değildir.
- **Başka bir VPN istemcisinin tünelini aynı anda çalıştırmayın** (Proton/WARP uygulaması dahil).

Ayrıntılar: [ağ izolasyonu denetimi](audits/network_isolation_audit.md), [iyileştirme planı — P0 progress](audits/security_remediation_plan.md#p0-progress), [R3/R4 canlı kayıtları](testing/phase3_live_results_2026-11-22.md), [çoklu adaptör analizi](audits/r3_multinic_analysis.md). Deneysel yayın kararı bu açıkları veya planın güvenlik kabul kapısını kapatmaz.

### Known limitations

- **Browser Discord and DNS are best-effort, not fail-closed (P0-F/P0-G open).** Browser connections and plaintext DNS can go direct while the service is stopped; running it does not cover every domain/encrypted-DNS path.
- **Process-identity loss in the engine can route a Discord flow direct (P0-D open).** A connected tunnel does not prove isolation.
- **A brand-new Discord version can connect before enrollment:** a short race remains. Helpers/installers are covered only within known manifest paths and capacity bounds; custom, Downloads and other Temp paths have no persistent-block assurance.
- **Connections opened before protection can remain direct.** Fully quit Discord from the tray and restart it after enabling protection or changing providers.
- **Multi-NIC:** health-aware egress failover was added but **has NOT been tested live**. If Internet/DNS breaks with two adapters, run `aurasplit.exe stop` or `aurasplit.exe disable`. `stop` retains enrolled-program blocks; `disable` removes them and lets Discord connect directly.
- **Tested scope:** one Windows 11 x64 PC, WARP and Proton. The generic WireGuard option was exercised only with a Proton `.conf`; other generic WireGuard providers have not been tested live. Windows 10, native IPv6 and other PCs/antivirus products are unverified.
- **Exe/MSI are unsigned; antivirus/SmartScreen may warn. Never disable antivirus or add exclusions.** Verify SHA-256 and `gh attestation verify`.
- **No comprehensive packet-capture leak test suite has been completed; no independent packet verification.** `tools/leaktest` exists. Historical run 5 contains limited captures, including browser/DNS escapes; it does not establish leak-free operation.
- **Do not run another VPN client's tunnel at the same time**, including the Proton/WARP app.

See the [isolation audit](audits/network_isolation_audit.md), [remediation plan / P0 progress](audits/security_remediation_plan.md#p0-progress), [R3/R4 live results](testing/phase3_live_results_2026-11-22.md) and [multi-NIC analysis](audits/r3_multinic_analysis.md). Publishing an experimental beta does not close these findings or satisfy the plan's security acceptance gate.

## Kurulum ve doğrulama / Install and verify

[Releases](https://github.com/umut720s/aura-split-tr/releases) üzerinden MSI ve aynı sürümün `SHA256SUMS.txt` dosyasını indirin. Download the MSI and checksum file from the same release. In the download folder, use PowerShell:

```powershell
(Get-FileHash .\AuraSplitTR-0.1.1-beta-x64.msi -Algorithm SHA256).Hash.ToLower()
Get-Content .\SHA256SUMS.txt
gh attestation verify .\AuraSplitTR-0.1.1-beta-x64.msi --repo umut720s/aura-split-tr
```

Hash'i MSI satırıyla karşılaştırın; iki doğrulamadan biri başarısızsa çalıştırmayın. Compare the hash with the matching MSI entry; do not run it if either check fails. Verify any separately downloaded exe/zip the same way. Checksums verify integrity; attestation verifies build provenance, not application safety. Neither provides Authenticode signing. **Antivirüsü kapatmayın / Never disable antivirus or add exclusions.** [Verification details](BUILD.md#verifying-a-downloaded-release).

Doğrulanmış MSI'yi çalıştırın / Run the verified MSI:

```powershell
msiexec /i .\AuraSplitTR-0.1.1-beta-x64.msi
```

Başlat menüsünden **“AURA Split TR - Yapılandır”** açıp sağlayıcı seçin. Hizmet yapılandırılana kadar başlamaz ve trafik engellemez. Diğer VPN tünellerini kapatın; `.conf` kopyaları özel anahtar içerir, paylaşmayın ve kurulumdan sonra silin. `status` kontrolünden sonra Discord'u tepsiden tamamen kapatıp yeniden açın.

Open **“AURA Split TR - Yapılandır”** from Start and select a provider. The service does not start/block traffic until configured. Disconnect other VPN tunnels, keep configs private and delete downloaded copies after setup. Check `status`, fully quit Discord from the tray and restart it. See [README](../README.md#english-summary) for provider setup.

## v0.1.0-beta üzerinden yükseltme / Upgrade from v0.1.0-beta

Doğrulanmış v0.1.1-beta MSI dosyasını mevcut v0.1.0-beta kurulumu üzerine çalıştırın; önce kaldırmanız gerekmez. Mevcut profil korunur. Run the verified AuraSplitTR-0.1.1-beta-x64.msi over v0.1.0-beta without uninstalling first; the existing profile is preserved.

The release workflow takes v0.1.1-beta as tag input and passes 0.1.1-beta to build.ps1. The MSI product version strips the suffix to 0.1.1, higher than v0.1.0-beta's 0.1.0; the fixed UpgradeCode and MajorUpgrade enable replacement of the old installation. This is the configured upgrade path, not a new live validation result. After upgrading, check status, fully quit Discord from the tray and restart it. Historical upgrade observations do not establish failed-upgrade/rollback safety for this release.

## Kullanım ve kurtarma / Commands and recovery

Yönetici PowerShell / Administrator PowerShell. These are alternatives; do not run them all in sequence:

```powershell
& "C:\Program Files\AuraSplitTR\aurasplit.exe" status
& "C:\Program Files\AuraSplitTR\aurasplit.exe" stop
& "C:\Program Files\AuraSplitTR\aurasplit.exe" disable
& "C:\Program Files\AuraSplitTR\aurasplit.exe" recover
```

| Command | Etki / Effect |
|---|---|
| `status` | Hizmet/tünel/probe/kapsam / Inspect service, tunnel, probe and coverage; no packet-isolation proof. |
| `stop` | Hizmet durur, engeller kalır / Stop service, keep persistent executable blocks and automatic startup setting. |
| `disable` | Onayla devre dışı bırak / Confirm to disable startup, stop service and remove blocks; Discord can go direct. |
| `recover` | Acil engel kaldırma / Attempt emergency WFP block removal without confirmation; disable/stop service if present. Works with a broken profile/missing service; successful removal allows direct traffic. |
| `start` | Yeniden etkinleştir / Restore rules, automatic startup and service; fully restart Discord afterwards. |

İki adaptörle İnternet kesilirse önce `stop` veya `disable` kullanın. If Internet breaks with two adapters, use `stop` or `disable`; the new failover has not been validated live.

## Kaldırma / Uninstall

**Windows Ayarlar → Uygulamalar → AURA Split TR → Kaldır / Settings → Apps → AURA Split TR → Uninstall.** Normal removal deletes the service, WFP rules, installed files and private-key data folder. Unexpected/untrusted contents or quarantine folders may remain for manual inspection; downloaded `.conf` files are not removed.

Alternatively, launch the matching verified MSI's uninstall from administrator PowerShell (normal uninstall removes the profile/private-key data):

```powershell
msiexec /x .\AuraSplitTR-0.1.1-beta-x64.msi
```

Kaldırma bozulursa aynı sürümün MSI'sini doğrulayıp onarın/yeniden kurun, tam yoldan yönetici olarak `recover` çalıştırın, sonra Windows'tan kaldırmayı tekrar deneyin. If removal fails and blocks remain, verify and repair/reinstall the same MSI version, run full-path `recover` as administrator, then retry uninstall. Forced-failure rollback/repair/recovery error paths have not been tested live.

[Private vulnerability reporting](../SECURITY.md) · [License](../LICENSE) · [Third-party licenses](../THIRD_PARTY_LICENSES.md). Do not attach configs, private keys, profiles or unredacted logs to reports.
