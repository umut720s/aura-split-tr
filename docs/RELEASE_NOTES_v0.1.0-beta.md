# v0.1.0-beta (experimental)

**Deneysel, üretime hazır değildir / Experimental, not production-ready.** Exe/MSI Authenticode imzasızdır; bağımsız paket düzeyi doğrulaması yoktur. Riski size ait olmak üzere kullanın / Use at your own risk.

## Özellikler / Features

- Masaüstü Discord, güncelleyici ve bilinen yardımcılar için WireGuard yönlendirmesi; diğer uygulamalar doğrudan bağlanır. Tarayıcı/alan adı ve DNS yönlendirmesi best-effort'tur.
- Cloudflare WARP kaydı, Proton VPN `.conf` ve tek eşli standart WireGuard yapılandırması desteği.
- MSI kurulum/kaldırma, arka plan Windows hizmeti, Türkçe dosya seçicili yapılandırıcı; ayrı hizmet/tünel/bağlantı/kapsam durumu.
- Bilinen program yolları için sınırlandırılmış kalıcı WFP engelleri, yeniden bağlanma ve eski süreç kapısı. Çoklu adaptör sağlık failover'ı eklendi; canlıda doğrulanmadı.

Routes desktop Discord, its updater and known helpers through WireGuard; other apps stay direct. Includes WARP registration, Proton/standard single-peer WireGuard configs, MSI installation, a background service, Turkish setup wizard and separate connection/coverage status. Persistent executable blocks and reconnection have the limits below; new health-aware egress failover is not live-tested.

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
(Get-FileHash .\AuraSplitTR-0.1.0-beta-x64.msi -Algorithm SHA256).Hash.ToLower()
Get-Content .\SHA256SUMS.txt
gh attestation verify .\AuraSplitTR-0.1.0-beta-x64.msi --repo umut720s/aura-split-tr
```

Hash'i MSI satırıyla karşılaştırın; iki doğrulamadan biri başarısızsa çalıştırmayın. Compare the hash with the matching MSI entry; do not run it if either check fails. Verify any separately downloaded exe/zip the same way. Checksums verify integrity; attestation verifies build provenance, not application safety. Neither provides Authenticode signing. **Antivirüsü kapatmayın / Never disable antivirus or add exclusions.** [Verification details](BUILD.md#verifying-a-downloaded-release).

Doğrulanmış MSI'yi çalıştırın / Run the verified MSI:

```powershell
msiexec /i .\AuraSplitTR-0.1.0-beta-x64.msi
```

Başlat menüsünden **“AURA Split TR - Yapılandır”** açıp sağlayıcı seçin. Hizmet yapılandırılana kadar başlamaz ve trafik engellemez. Diğer VPN tünellerini kapatın; `.conf` kopyaları özel anahtar içerir, paylaşmayın ve kurulumdan sonra silin. `status` kontrolünden sonra Discord'u tepsiden tamamen kapatıp yeniden açın.

Open **“AURA Split TR - Yapılandır”** from Start and select a provider. The service does not start/block traffic until configured. Disconnect other VPN tunnels, keep configs private and delete downloaded copies after setup. Check `status`, fully quit Discord from the tray and restart it. See [README](../README.md#english-summary) for provider setup.

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

Kaldırma bozulursa aynı sürümün MSI'sini doğrulayıp onarın/yeniden kurun, tam yoldan yönetici olarak `recover` çalıştırın, sonra Windows'tan kaldırmayı tekrar deneyin. If removal fails and blocks remain, verify and repair/reinstall the same MSI version, run full-path `recover` as administrator, then retry uninstall. Forced-failure rollback/repair/recovery error paths have not been tested live.

[Private vulnerability reporting](../SECURITY.md) · [License](../LICENSE) · [Third-party licenses](../THIRD_PARTY_LICENSES.md). Do not attach configs, private keys, profiles or unredacted logs to reports.
