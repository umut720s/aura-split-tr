<img src="assets/aura-logo.png" alt="AURA Split TR" width="360">

# AURA Split TR

> **Deneysel beta — v0.1.1-beta.** Masaüstü Discord'u, güncelleyicisini ve bilinen yardımcılarını Proton VPN, Cloudflare WARP veya standart bir WireGuard yapılandırması üzerinden yönlendirir; diğer uygulamalar doğrudan bağlantıyı kullanır. **Deneyseldir, exe/MSI imzasızdır ve bağımsız paket düzeyi doğrulaması yoktur. Riski size ait olmak üzere kullanın; üretime hazır değildir.** Kapsam sınırları aşağıdadır.

Windows hizmeti olarak arka planda çalışır. **Yalnızca Windows 11 x64 üzerinde test edildi.** [English summary](#english-summary) · [Sürüm notları](docs/RELEASE_NOTES_v0.1.1-beta.md)

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

Ayrıntılar: [ağ izolasyonu denetimi](docs/audits/network_isolation_audit.md), [iyileştirme planı — P0 progress](docs/audits/security_remediation_plan.md#p0-progress), [R3/R4 canlı kayıtları](docs/testing/phase3_live_results_2026-11-22.md), [çoklu adaptör analizi](docs/audits/r3_multinic_analysis.md). Deneysel yayın kararı bu açıkları veya planın güvenlik kabul kapısını kapatmaz.

## İndirme ve kurulum

1. [GitHub Releases](https://github.com/umut720s/aura-split-tr/releases) üzerinden `AuraSplitTR-0.1.1-beta-x64.msi` ve aynı sürümün `SHA256SUMS.txt` dosyasını indirin.
2. İndirme klasöründe PowerShell açın:

   ```powershell
   (Get-FileHash .\AuraSplitTR-0.1.1-beta-x64.msi -Algorithm SHA256).Hash.ToLower()
   Get-Content .\SHA256SUMS.txt
   gh attestation verify .\AuraSplitTR-0.1.1-beta-x64.msi --repo umut720s/aura-split-tr
   ```

   Hash'i dosyanın ilgili satırıyla karşılaştırın; doğrulamalardan biri başarısızsa çalıştırmayın. Hash bütünlüğü, attestation derleme kaynağını denetler; bunlar güvenlik testi veya Authenticode imzası değildir. Ayrıntılar: [indirme doğrulaması](docs/BUILD.md#verifying-a-downloaded-release).
3. Doğrulanan MSI'yi çalıştırıp UAC iznini onaylayın. SmartScreen uyarısını ancak kaynağı ve iki doğrulamayı kontrol ettikten sonra değerlendirin; antivirüs algılamasında durup üreticiye yanlış pozitif bildirimi yapın. **Antivirüsü kapatmayın veya istisna eklemeyin.**
4. Başlat menüsünden **“AURA Split TR - Yapılandır”** açın. Yapılandırma öncesi hizmet başlamaz ve AURA trafik engellemez.
5. Sağlayıcı seçin:
   - **Cloudflare WARP:** ayrı uygulama veya dosya gerekmez. Koşulları okuyup kabul edin; bölge/IP kayıt sınırları kaydı reddedebilir.
   - **Proton VPN:** hesabınızdan Windows için WireGuard `.conf` indirin, Proton uygulamasının tünelini kapatın ve dosya seçiciyle açın. [Proton rehberi](https://protonvpn.com/support/wireguard-configurations).
   - **Diğer WireGuard:** tek `[Peer]` içeren standart `.conf` seçin. `PostUp`/`PostDown` betikleri çalıştırılmaz; sağlayıcı uyumluluğu canlıda doğrulanmadı.
6. `status` ile kontrol edin; ilk bağlantı 1–2 dakika sürebilir. Discord'u tepsiden tamamen kapatıp yeniden açın. `.conf` özel anahtar içerir: paylaşmayın; indirdiğiniz kopyayı ve Geri Dönüşüm Kutusu kopyasını silin.

v0.1.1-beta MSI, v0.1.0-beta üzerine kurulabilir; önce kaldırmak gerekmez ve mevcut profil korunur. Dosya seçici açılmazsa **Yol olarak kopyala** ile yolu yapıştırın.

## Kullanım ve kurtarma

**PowerShell'i yönetici olarak** açın. Bunlar alternatif işlemlerdir; hepsini sırayla çalıştırmayın.

| Komut | Etki |
|---|---|
| `status` | Hizmet, tünel, VPN bağlantı kontrolü ve sınıf bazlı kapsamı gösterir. |
| `stop` | Hizmeti durdurur; kalıcı program engelleri kalır, otomatik başlatma ayarı değişmez. |
| `start` | Kuralları uygular, otomatik başlatmayı açar ve hizmeti başlatır. |
| `disable` | Onay ister; otomatik başlatmayı kapatır, hizmeti durdurur ve engelleri kaldırır. Discord doğrudan bağlanabilir. |
| `recover` | Acil kurtarma: varsa hizmeti devre dışı bırakıp durdurur ve WFP engellerini kaldırmayı dener; profil bozuk/hizmet yokken de kullanılabilir. Onay sormaz; doğrudan bağlantıya dönüş içindir. |
| `setup` | Kurulu kopyadan yapılandırıcıyı açar. |

```powershell
& "C:\Program Files\AuraSplitTR\aurasplit.exe" status
# İhtiyacınıza göre yalnız birini seçin:
& "C:\Program Files\AuraSplitTR\aurasplit.exe" stop
& "C:\Program Files\AuraSplitTR\aurasplit.exe" disable
& "C:\Program Files\AuraSplitTR\aurasplit.exe" recover
```

`SERVICE_RUNNING`, `TUNNEL_INITIALIZED`, `VPN_CONNECTIVITY_VERIFIED` ve `PROTECTION_READY` ayrı durumlardır; hiçbiri paket düzeyinde sızıntısızlık kanıtı değildir. Kapsam eksikse `status` nedenini gösterir. Eski süreç kapısı bekliyorsa Discord'u tamamen kapatın ve durumu yeniden kontrol edin; çözülemeyen süreç kimlikleri de kapıyı bekletebilir.

Bağlantı kurulmazsa İnterneti kontrol edin, sonra başka sunucu/sağlayıcı deneyin. Çoklu adaptörde kesinti için yukarıdaki `stop`/`disable` yolunu kullanın. VPN'e dönmek için `start` çalıştırın ve Discord'u yeniden başlatın.

## Kaldırma

**Ayarlar → Uygulamalar → AURA Split TR → Kaldır**. Normal kaldırma hizmeti, WFP kurallarını, program dosyalarını ve özel anahtarlı `%ProgramData%\AuraSplitTR` klasörünü temizler. Beklenmeyen/güvenilmeyen içerik ve karantina klasörleri elle inceleme için kalabilir; indirilen `.conf` dosyasını MSI silmez.

Bozuk kaldırma sonrası engel kaldıysa aynı sürümün MSI'sini yeniden indirip doğrulayın, onarın/yeniden kurun, yönetici PowerShell'de tam yol ile `recover` çalıştırın ve Windows'tan kaldırmayı tekrar deneyin. Zorlanmış hata/geri alma ve kurtarma hata yolları canlıda doğrulanmadı.

## Gizlilik, kaynaklar ve lisans

Telemetri yoktur. WARP kaydı Cloudflare'e açık anahtar ve kayıt bilgileri gönderir. Bağlantı kontrolü tünelden Cloudflare trace adresine gider; fiziksel adaptör sağlığı için DNS/TCP kontrolleri de yapılır. VPN sunucu adının ilk çözümlemesi tünel dışında olabilir. VPN sağlayıcısı bağlantı meta verilerini görebilir; bu bir anonimlik aracı değildir.

Profil `%ProgramData%\AuraSplitTR\profile.json` içinde Administrators/SYSTEM erişimiyle, günlükler aynı klasörde yerelde tutulur. Hata günlükleri alan adı/IP içerebilir; paylaşmadan önce kişisel bilgileri ve gizli değerleri temizleyin. `.conf`, profil veya özel anahtar paylaşmayın.

[Hata bildirimi](https://github.com/umut720s/aura-split-tr/issues) · [Özel güvenlik bildirimi](SECURITY.md) · [Mimari](ARCHITECTURE.md) · [Derleme](docs/BUILD.md) · [Katkı](CONTRIBUTING.md)

**GPL-3.0-or-later · Copyright (C) 2026 AURA Split TR contributors**, olduğu gibi ve garantisiz sunulur. Yerel yasalara ve sağlayıcı koşullarına uyun. Discord, Proton, Cloudflare veya WireGuard ile bağlantılı/onaylı değildir. sing-box/sing-tun, wireguard-go, Wintun, wireguard-windows, wgcf/warp-plus, WiX ve go-winres projelerine teşekkürler. [LICENSE](LICENSE) · [NOTICE](NOTICE) · [Üçüncü taraf lisansları](THIRD_PARTY_LICENSES.md) · [Markalar](TRADEMARKS.md)

---

## English summary

> **Experimental beta — v0.1.1-beta.** Routes desktop Discord, its updater and known helpers through Proton VPN, Cloudflare WARP or a standard WireGuard configuration; other apps use the direct connection. **Experimental, unsigned exe/MSI, and not independently packet-verified. Use at your own risk; not production-ready.** Coverage is limited as described below.

Runs as a background Windows service. **Only Windows 11 x64 has been tested.** [Release notes](docs/RELEASE_NOTES_v0.1.1-beta.md)

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

See the [isolation audit](docs/audits/network_isolation_audit.md), [remediation plan / P0 progress](docs/audits/security_remediation_plan.md#p0-progress), [R3/R4 live results](docs/testing/phase3_live_results_2026-11-22.md) and [multi-NIC analysis](docs/audits/r3_multinic_analysis.md). Publishing an experimental beta does not close these findings or satisfy the plan's security acceptance gate.

### Install and verify

Download the MSI and matching `SHA256SUMS.txt` from [Releases](https://github.com/umut720s/aura-split-tr/releases). In the download folder:

```powershell
(Get-FileHash .\AuraSplitTR-0.1.1-beta-x64.msi -Algorithm SHA256).Hash.ToLower()
Get-Content .\SHA256SUMS.txt
gh attestation verify .\AuraSplitTR-0.1.1-beta-x64.msi --repo umut720s/aura-split-tr
```

Compare the hash with the matching entry. Do not run the file if either check fails. Hashes check integrity; attestation checks build provenance. Neither is an Authenticode signature or a security test. Verify any separately downloaded exe/zip the same way. [Verification details](docs/BUILD.md#verifying-a-downloaded-release).

Install the verified MSI, approve UAC, then open **“AURA Split TR - Yapılandır”** from Start. Nothing is blocked until configured. Select WARP (accept its terms; registration can be refused), Proton or a single-peer WireGuard `.conf`. Disconnect other VPN tunnels first. `PostUp`/`PostDown` scripts are not executed. Check `status`, allow 1–2 minutes for connection, then fully restart Discord. Delete downloaded config copies after setup; they contain private keys. The v0.1.1-beta MSI upgrades over v0.1.0-beta without uninstalling first and preserves the profile.

### Commands, recovery and uninstall

Run administrator PowerShell; commands below are alternatives:

```powershell
& "C:\Program Files\AuraSplitTR\aurasplit.exe" status
& "C:\Program Files\AuraSplitTR\aurasplit.exe" stop
& "C:\Program Files\AuraSplitTR\aurasplit.exe" disable
& "C:\Program Files\AuraSplitTR\aurasplit.exe" recover
```

`status` reports service/tunnel/probe/coverage separately, without proving packet isolation. `stop` retains persistent blocks and automatic startup. `disable` asks for confirmation, disables startup, stops and removes blocks. `recover` attempts emergency block removal without confirmation, even with a broken profile/missing service; it disables/stops an existing service. Discord can go direct after block removal. Use `start` to restore automatic startup and the tunnel; fully restart Discord afterwards.

Uninstall via **Settings → Apps → AURA Split TR → Uninstall**. Normal removal cleans service, rules, files and the private-key data folder. Unexpected/untrusted content or quarantine folders may remain for manual inspection. Downloaded configs are not removed. If removal fails and Discord stays blocked, verify and repair/reinstall the same MSI version, run full-path `recover`, then uninstall again. Forced failure/rollback and recovery error paths have not been tested live.

No telemetry. WARP registration and connectivity/physical-egress health checks make network requests; endpoint bootstrap DNS may go outside the tunnel. The VPN provider sees connection metadata. Local logs may contain hosts/IPs: redact before sharing, and never share configs, profiles or keys. This is not an anonymity tool.

GPL-3.0-or-later · Copyright (C) 2026 AURA Split TR contributors. As-is without warranty. "WireGuard" and the "WireGuard" logo are registered trademarks of Jason A. Donenfeld. Not affiliated with Discord, Proton, Cloudflare or WireGuard. [License](LICENSE) · [Third-party credits/licenses](THIRD_PARTY_LICENSES.md) · [Trademarks](TRADEMARKS.md) · [Private vulnerability reporting](SECURITY.md) · [Build](docs/BUILD.md)
