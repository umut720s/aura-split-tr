<!-- TASLAK: Bakımcı metni ve sürüm bilgilerini gözden geçirmeli, ardından Technopat Sosyal'de kendisi elle paylaşmalıdır. Bu dosya yayımlanmış bir duyuru değildir. -->

# AURA Split TR — Windows'ta yalnızca Discord için WireGuard VPN (açık kaynak, imzasız beta)

Merhaba Sosyal,

AURA Split TR'nin beta sürümünü paylaşmak istiyorum. Windows'ta yalnızca Discord uygulamasını, güncelleyicisini, kurucusunu ve listelenen Discord alan adlarını WireGuard VPN tünelinden geçiriyor. Hizmet çalışırken tarayıcıdaki Discord da buna dahil. Oyunlar, diğer siteler ve uygulamalar normal internet bağlantınızı kullanıyor.

Program arka planda Windows hizmeti olarak çalışıyor; her açılışta VPN penceresi açmak gerekmiyor. **Windows 10/11 x64 için; mevcut beta Authenticode imzalı değil.**

## Neler sunuyor?

- **Fail-closed:** hizmet durduğunda, çöktüğünde veya ağ kesildiğinde bulunan Discord uygulaması ve güncelleyicisi doğrudan bağlanamasın diye kalıcı WFP kuralları kullanıyor. Tarayıcı ve DNS için sınırları aşağıda.
- **Sağlayıcı seçimi:** ücretsiz Cloudflare WARP, Proton VPN Free/Plus veya tek `[Peer]` içeren standart WireGuard `.conf` dosyası.
- **MSI kurulumu/kaldırma:** normal kaldırmada hizmet, filtreler, dosyalar ve özel anahtarlı veri klasörü temizleniyor.
- **Sistem DNS ayarlarını değiştirmiyor.** Çalışırken listelenen Discord adlarını tünelden çözüyor.
- Dosya seçicili yapılandırıcı, otomatik yeniden bağlanma ve bağlantı/koruma durumunu gösteren `status` komutu var.

## İndirme

Proje ve ayrıntılı rehber: https://github.com/umut720s/aura-split-tr

**MSI ve SHA256SUMS.txt:** https://github.com/umut720s/aura-split-tr/releases

Yalnızca bu sayfadan, aynı sürümün Assets bölümünden indirin. PowerShell'de MSI adını indirdiğiniz sürüme göre değiştirip hash'i hesaplayın ve `SHA256SUMS.txt` içindeki MSI satırıyla karşılaştırın:

```powershell
(Get-FileHash .\AuraSplitTR-0.1.0-beta-x64.msi -Algorithm SHA256).Hash.ToLower()
Get-Content .\SHA256SUMS.txt
```

GitHub CLI kullanıyorsanız isteğe bağlı derleme kaynağı doğrulaması:

```powershell
gh attestation verify .\AuraSplitTR-0.1.0-beta-x64.msi --repo umut720s/aura-split-tr
```

Doğrulama başarısızsa çalıştırmayın. Hash tek başına kaynağı kanıtlamaz; indirme adresini de kontrol edin.

## Kısa kurulum

1. MSI'yi doğrulayıp kurun ve UAC iznini onaylayın. Yapılandırılana kadar hizmet başlamaz, hiçbir trafik engellenmez.
2. Başlat menüsünden **AURA Split TR - Yapılandır** kısayolunu açın.
3. Sağlayıcıyı seçin:
   - **WARP:** dosya indirmeden sihirbazda Cloudflare koşullarını okuyup kabul edin. Bazı bölge/IP'lerde Cloudflare kaydı “abuse” sınırıyla reddedebilir; başka sağlayıcı kullanın.
   - **Proton:** https://account.protonvpn.com → **Downloads → WireGuard configuration**. Windows; NetShield Off veya Block malware only; Moderate NAT ve NAT-PMP Off. VPN Accelerator açık kalabilir. Türkiye dışında yakın sunucu seçip `.conf` indirin, AURA'nın dosya seçicisinde açın. Free hesapta ücretsiz sunucuları seçin. Proton VPN uygulaması bağlıysa bağlantısını kapatın.
   - **Diğer WireGuard:** tek `[Peer]` içeren standart `.conf` seçin.
4. Yapılandırma tamamlanınca Discord'u tepsiden tamamen kapatıp yeniden açın. İlk bağlantıda 1–2 dakika beklemek gerekebilir. Dosya seçici açılmazsa kopyalanmış dosya yolunu yapıştırabilirsiniz.
5. **`.conf` özel anahtar içerir: kurulumdan sonra silin, Geri Dönüşüm Kutusu'nu da temizleyin; asla paylaşmayın.** Kullanılan anahtar `%ProgramData%\AuraSplitTR\profile.json` içinde yalnızca Administrators/SYSTEM erişimiyle tutulur.

Yönetici PowerShell'de durum kontrolü:

```powershell
& "C:\Program Files\AuraSplitTR\aurasplit.exe" status
```

`stop` hizmeti durdurur ama bulunan Discord programlarını engelli bırakır. VPN'e dönmek için `start`, doğrudan bağlantı için `disable` kullanılır. Bozuk kurulum/kaldırma için `recover` vardır; ayrıntılar README'de. Normal kaldırma **Ayarlar → Uygulamalar → AURA Split TR → Kaldır** üzerinden yapılır.

## Testler ve bilinen sınırlar

Canlı denemeler **yalnızca bir Windows 11 x64 PC'de**, IPv4-only Ethernet ve Kaspersky Plus açıkken yapıldı. Wintun paketi önceden kurulu olan bu bilgisayarda Proton Plus, WARP ve genel WireGuard seçeneği denendi; genel seçenekte de Proton dosyası kullanıldı. Proton Free ve başka bir genel sağlayıcı bu testlere dahil değil.

- Durma, çökme ve fiziksel ağ kesintisinde soket örneklemesi TUN dışında Discord TCP bağlantısı göstermedi. Ağ dönüşünde yeniden bağlantı ve durum göstergesi gözlendi.
- Son paket yakalamasında hizmet çalışırken fiziksel ağda Discord DNS/TLS SNI/HTTP Host adı görülmedi. Bu, tek PC'deki sınırlı yakalamanın sonucu; her sızıntının dışlandığı iddiası değil.
- **Hizmet durmuşken Discord uygulaması engelli kaldı, ancak Discord adları açık metin DNS'te görüldü; tarayıcıdaki Discord sekmeleri doğrudan bağlanabildi.** Tarayıcı ve Windows DNS İstemcisi kalıcı uygulama engelinin kapsamında değil.
- Yeni Discord sürümünün keşfinde ~1 sn pencere olabilir; hizmet durmuşken hazırlanmış sürümler sonraki taramaya kadar kapsanmayabilir. Başka konuma kopyalanan uygulamalar ve kurucular WFP engelinin dışında. Kural bütçesi ve süreç tespiti de kapsamı sınırlayabilir.
- Açılış penceresi paket yakalaması, QUIC SNI/ECH/şifreli DNS kapsamı, yerel IPv6 ağları, diğer PC/antivirüsler, ekran paylaşımı ve zorlanmış MSI geri alma/onarım/kurtarma hata yolları henüz test edilmedi. IPv6 olmayan ağlar destekleniyor; diğer VPN istemcileriyle çakışma olabilir. Bu bir üretime hazır olma iddiası değil.

Depodaki ayrıntılı test kaydı: `docs/testing/phase3_live_results_2026-11-22.md` (run 1–5).

## Antivirüs, SmartScreen ve gizlilik

Beta imzasız olduğu için SmartScreen uyarısı çıkabilir; hizmet ve ağ filtresi kullanan araçlar sezgisel antivirüs algılamalarına takılabilir. Eski kendi kendini kuran geliştirme sürümünde Kaspersky davranış algılaması görüldü. MSI aynı test PC'sinde uyarı vermedi; bu tüm bilgisayarlar için garanti değil.

**Antivirüsünüzü kapatmayın veya istisna eklemeyin.** Yanlış pozitif olduğunu düşünüyorsanız üreticiye inceleme için bildirin. SmartScreen'de **Ek bilgi → Yine de çalıştır** yolunu ancak dosyanın yukarıdaki Releases sayfasından geldiğini ve SHA-256 eşleşmesini doğruladıktan sonra kullanın. İsterseniz VirusTotal'da hash araması yapın; sonuç tek başına güvenlik garantisi değil. SignPath Foundation üzerinden imzalama planlanıyor; mevcut beta imzalı değil.

Telemetri yok; günlükler yerelde warn düzeyinde tutuluyor, kullanıcı yolları temizleniyor. Hatalar alan adı/IP içerebilir. WARP kaydı yalnızca kullanıcı seçip koşulları kabul ettiğinde yapılıyor. Ayrıca tüm sağlayıcılarda başlangıçta, normalde 5 dakikada bir ve ağ değişiminde **tünelden https://www.cloudflare.com/cdn-cgi/trace adresine otomatik bağlantı denetimi** gönderiliyor; başarısızlıkta yeniden denenebiliyor. Yalnızca `warp=`/`ip=` alanları okunuyor, IP saklanmıyor/günlüğe yazılmıyor. Discord DNS'i hizmet çalışırken tünelden çözülüyor; VPN sunucu adı varsa ilk çözümlemesi tünel dışında. Bu araç bütün cihazı anonimleştiren VPN değil.

## Geri bildirim ve lisans

Hata/uyumluluk geri bildirimleri: https://github.com/umut720s/aura-split-tr/issues

Sürüm, Windows sürümü, sağlayıcı türü ve sorunu tekrar oluşturma adımları yardımcı olur. `.conf`, `profile.json`, özel anahtar, IP veya kişisel bilgi paylaşmayın. Güvenlik açıkları için herkese açık issue yerine **SECURITY.md** içindeki özel bildirim yolunu kullanın.

**GPL-3.0-or-later — Copyright (C) 2026 AURA Split TR contributors.** sing-box/sing-tun, WireGuard ve diğer bileşenlerin atıfları depoda. Yazılım olduğu gibi, garanti olmadan sunuluyor; yerel yasalara ve Discord/VPN koşullarına uymak kullanıcıya ait. Proje Discord, Cloudflare, Proton veya WireGuard ile bağlantılı değil.
