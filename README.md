<img src="assets/aura-logo.png" alt="AURA Split TR" width="360">

# AURA Split TR

## AURA Split TR nedir?

AURA Split TR, Windows'ta yalnızca **Discord trafiğini WireGuard VPN tünelinden** geçiren, arka planda Windows hizmeti olarak çalışan açık kaynaklı bir araçtır (GPL-3.0-or-later). Discord uygulaması, güncelleyicisi, kurucusu ve listelenen Discord alan adları — hizmet çalışırken tarayıcıdaki Discord dahil — VPN'i kullanır; oyunlar, diğer siteler ve diğer uygulamalar normal bağlantınızdan çıkar. Ücretsiz **Cloudflare WARP**, **Proton VPN Free/Plus** veya standart bir **WireGuard yapılandırması** seçebilirsiniz. Yapılandırmadan sonra hizmet Windows ile başlar; açık pencere veya tepsi simgesi gerekmez.

**Windows 10/11 x64 · Authenticode imzasız beta.** Canlı testler yalnızca bir Windows 11 bilgisayarda yapıldı; sonuçlar tüm ağlar için garanti değildir. [English summary](#english-summary) aşağıdadır.

## Öne çıkanlar

- **Discord uygulaması için fail-closed koruma:** hizmet durduğunda, çöktüğünde veya ağ kesildiğinde bulunan Discord uygulaması ve güncelleyicisi tünel dışında engelli kalır. Tek bilgisayarda durma/çökme/ağ kesintisi soket örneklemesiyle; hizmetin durması ayrıca paket yakalamayla gözlendi. Tarayıcı ve DNS sınırları [Test durumu](#test-durumu) bölümündedir.
- **Sistem DNS ayarlarını değiştirmez.** Hizmet çalışırken listelenen Discord adlarını tünel üzerinden çözer.
- **Standart MSI kurulumu/kaldırma:** normal kaldırmada hizmet, WFP kuralları, dosyalar ve özel anahtarlı veri klasörü temizlenir.
- **Dosya seçicili yapılandırıcı:** Proton veya başka sağlayıcının `.conf` dosyasını seçin; WARP için dosya indirmek gerekmez.
- **Otomatik yeniden bağlanma:** başarısız bağlantıları yeniden dener; kısa fiziksel ağ kesintisinden dönüş canlıda gözlendi.
- **`status` komutu:** hizmeti, tüneli, bağlantı denemesini ve koruma kapsamını ayrı gösterir.

## İndirme ve Kurulum

1. [GitHub Releases](https://github.com/umut720s/aura-split-tr/releases) sayfasındaki en yeni sürümün **Assets** bölümünden `AuraSplitTR-<sürüm>-x64.msi` ve **aynı sürüme ait** `SHA256SUMS.txt` dosyalarını indirin.
2. İndirdiğiniz klasörde PowerShell açın. Örnekteki MSI adını indirdiğiniz sürüme göre değiştirin:

   ```powershell
   (Get-FileHash .\AuraSplitTR-0.1.0-beta-x64.msi -Algorithm SHA256).Hash.ToLower()
   Get-Content .\SHA256SUMS.txt
   ```

   Hesaplanan SHA-256 değerini `SHA256SUMS.txt` içindeki **MSI satırıyla** karşılaştırın. Farklıysa çalıştırmayın. Hash eşleşmesi bütünlüğü denetler; kaynağı tek başına kanıtlamaz.
3. İsteğe bağlı olarak [GitHub CLI](https://cli.github.com/) ile derleme kaynağını da doğrulayın:

   ```powershell
   gh attestation verify .\AuraSplitTR-0.1.0-beta-x64.msi --repo umut720s/aura-split-tr
   ```

   Bu doğrulama başarısızsa devam etmeyin. Ayrıntılar: [indirme doğrulaması](docs/BUILD.md#verifying-a-downloaded-release).
4. MSI'ye çift tıklayın. SmartScreen **“Windows kişisel bilgisayarınızı korudu”** uyarısını gösterirse, **yalnızca hash eşleşmesini ve dosyanın yukarıdaki Releases sayfasından geldiğini doğruladıktan sonra** **“Ek bilgi” → “Yine de çalıştır”** yolunu kullanın. Antivirüs algılaması varsa [ilgili bölüme](#antivirüs-ve-smartscreen) bakın; antivirüsü kapatmayın.
5. Yönetici izni (UAC) istemini onaylayıp kurulumu tamamlayın. Program `C:\Program Files\AuraSplitTR` altına kurulur. **VPN yapılandırılana kadar hizmet başlamaz ve hiçbir trafik engellenmez.**

Güncellemek için yeni MSI'yi çalıştırın; mevcut profil korunur. Başka VPN istemcileri çakışabilir; bu aracı kullanırken onların VPN bağlantısını kapatın.

## VPN yapılandırma

**Başlat menüsü → “AURA Split TR - Yapılandır”** kısayolunu açın, UAC iznini onaylayın ve bir sağlayıcı seçin. Sağlayıcı değiştirmek için aynı sihirbazı yeniden açabilirsiniz.

### 1. Cloudflare WARP — ücretsiz

1. Sihirbazda **Cloudflare WARP** seçin. WARP uygulaması veya yapılandırma dosyası indirmeniz gerekmez.
2. Cloudflare kullanım koşullarını okuyup kabul edin. Sihirbaz anahtar üretir ve Cloudflare'e kayıt isteği gönderir.
3. Yapılandırmanın tamamlanmasını bekleyin; ilk bağlantı yaklaşık 1–2 dakika sürebilir.

Cloudflare bazı bölgelerde veya IP adreslerinde kaydı **“abuse” sınırları** nedeniyle reddedebilir. Bu durumda Proton veya başka bir WireGuard sağlayıcısı kullanın; WARP kaydının kabul edileceği garanti değildir.

### 2. Proton VPN — Free veya Plus

1. [account.protonvpn.com](https://account.protonvpn.com) adresinden hesabınıza giriş yapın.
2. **Downloads → WireGuard configuration** bölümünü açın ve yapılandırmaya ad verin.
3. Platformu **Windows** seçin. AURA için şu ayarları kullanın (planınızda görünmeyen seçenekleri atlayın):

   | Ayar | Seçim |
   |---|---|
   | NetShield | **Off** veya **Block malware only** |
   | Moderate NAT | **Off** |
   | NAT-PMP / Port forwarding | **Off** |
   | VPN Accelerator | Açık kalabilir |

4. **Türkiye dışında, size yakın bir sunucu** seçin (Free hesapta ücretsiz sunuculardan). Yapılandırmayı oluşturup `.conf` dosyasını indirin. Proton VPN uygulaması bağlıysa bağlantısını kapatın.
5. AURA yapılandırıcısında **Proton VPN** seçip dosya seçicide `.conf` dosyasını açın.

Arayüz adımları: [Proton'un resmî WireGuard rehberi](https://protonvpn.com/support/wireguard-configurations). Yukarıdaki seçenekler AURA kurulumu için önerilen seçimlerdir.

### 3. Diğer WireGuard sağlayıcıları

1. Tam olarak **bir `[Peer]`** içeren standart WireGuard `.conf` dosyası alın.
2. Sihirbazda **Diğer WireGuard** seçip dosyayı açın. `PostUp` / `PostDown` betikleri çalıştırılmaz.

### Yapılandırmayı tamamlayın

1. Sihirbaz profili kaydeder, koruma kurallarını uygular ve hizmeti otomatik başlatmaya alıp çalıştırır. `status` ile bağlantıyı kontrol edin.
2. Discord'u **sistem tepsisinden tamamen kapatın** (sağ tık → Discord'dan Çık), ardından yeniden açın. Yalnızca pencereyi kapatmak yeterli değildir.
3. **`.conf` özel anahtarınızı içerir.** Kurulumdan sonra indirdiğiniz dosyayı ve Geri Dönüşüm Kutusu'ndaki kopyasını silin; asla paylaşmayın, issue'ya veya ekran görüntüsüne koymayın. Uygulamanın kullandığı kopya `%ProgramData%\AuraSplitTR\profile.json` içinde, yalnızca Administrators/SYSTEM erişimiyle kalır.

## Kullanım

Günlük kullanımda pencere açmanız gerekmez. Komutlar için **PowerShell'i yönetici olarak** açın. Aşağıdaki işlemler alternatiflerdir; hepsini sırayla çalıştırmayın.

| Komut | Ne yapar? | Ne zaman? |
|---|---|---|
| `status` | Hizmet, tünel, VPN denemesi ve koruma kapsamını gösterir. | Kurulum sonrası ve sorun giderirken. |
| `stop` | Hizmeti durdurur; kalıcı kurallar kalır. Bulunan Discord programları **engelli** kalır; açılış ayarı değişmez. | Tüneli geçici durdururken uygulamanın doğrudan bağlanmasını istemiyorsanız. |
| `start` | Kuralları uygular, hizmeti etkinleştirip başlatır; otomatik başlatmayı açar. | `stop`/`disable`/`recover` sonrasında VPN'e dönmek için. |
| `disable` | Onay ister; otomatik başlatmayı kapatır, hizmeti durdurur ve engelleri kaldırır. Discord **doğrudan** bağlanabilir. | AURA'yı devre dışı bırakmak için. |
| `recover` | Hizmet varsa devre dışı bırakıp durdurur; profil bozuk veya hizmet yok olsa da WFP engellerini kaldırır. Onay sormaz. | Bozuk kurulum/kaldırma sonrası doğrudan bağlantıyı geri getirmek için. |
| `setup` | “AURA Split TR - Yapılandır” sihirbazını açar; kurulu kopyadan çalışmalıdır. | Sağlayıcı veya `.conf` değiştirmek için. |

Tam yol ile örnekler:

```powershell
& "C:\Program Files\AuraSplitTR\aurasplit.exe" status
& "C:\Program Files\AuraSplitTR\aurasplit.exe" stop
& "C:\Program Files\AuraSplitTR\aurasplit.exe" start
& "C:\Program Files\AuraSplitTR\aurasplit.exe" disable
& "C:\Program Files\AuraSplitTR\aurasplit.exe" recover
& "C:\Program Files\AuraSplitTR\aurasplit.exe" setup
```

`SERVICE_RUNNING` hizmetin çalıştığını, `TUNNEL_INITIALIZED` yapılandırmanın uygulandığını gösterir. Başarılı bağlantı denemesi **`VPN_CONNECTIVITY_VERIFIED`** olarak görünür. `PROTECTION_ACTIVE` ve **Kapsam: TAM / EKSİK** satırlarını da kontrol edin; hizmetin çalışması tek başına tam koruma anlamına gelmez.

## Sık karşılaşılan sorunlar

| Belirti | Yapılacak |
|---|---|
| `VPN_CONNECTING` / `VPN_DEGRADED` kalıyor | İlk bağlantıda yaklaşık **1–2 dakika** bekleyin. İnterneti kontrol edin; sürerse başka sunucu/sağlayıcı yapılandırın. |
| Discord “Checking for updates” / “Bağlanıyor” ekranında | `status` çalıştırın. Hizmet durmuşsa bulunan Discord programları kasıtlı olarak engellidir: VPN için `start`, doğrudan bağlantı için `disable` kullanın. |
| IP değişiminden sonra “Mesajlar yüklenemedi” | Discord'u tepsiden tamamen kapatıp açın; sürerse başka VPN sunucusu deneyin. |
| Antivirüs hizmeti engelliyor/bekletiyor | Algılama geçmişini inceleyin; **antivirüsü kapatmayın veya istisna eklemeyin**. Yanlış pozitif bildirin; [AV bölümüne](#antivirüs-ve-smartscreen) bakın. |
| WARP kaydı reddediliyor / “abuse” | Cloudflare'in bölge/IP kayıt sınırı olabilir. Proton veya diğer WireGuard seçeneğini kullanın. |
| Ağda IPv6 yok | IPv6 olmayan ağlar desteklenir; IPv4-only Ethernet'te canlıda denendi. IPv6'yı açmanız gerekmez. |
| Dosya seçici açılmıyor | Dosyaya sağ tık → **Yol olarak kopyala**, sonra yapılandırıcıya yapıştırın. Tırnaklar kabul edilir. Yönetici penceresine sürükleyip bırakmak Windows tarafından engellenebilir. |

Günlük: `%ProgramData%\AuraSplitTR\service.log` (yönetici erişimi; eski kayıtlar `.1` ve `.2`). [GitHub Issues](https://github.com/umut720s/aura-split-tr/issues) bildiriminize sürümü, Windows sürümünü, sağlayıcı türünü ve yeniden üretme adımlarını ekleyin; anahtarları, IP'leri ve kişisel bilgileri paylaşmayın.

## Kaldırma

1. **Ayarlar → Uygulamalar → AURA Split TR → Kaldır** yolunu izleyin.
2. Normal kaldırma hizmeti, WFP kurallarını, program dosyalarını, kısayolu ve **`%ProgramData%\AuraSplitTR` klasörünü özel anahtar dahil** kaldırır. Bu temizlik canlıda gözlendi.

**Bozuk kaldırmadan sonra Discord engelli kaldıysa:** aynı sürümün MSI'sini [Releases](https://github.com/umut720s/aura-split-tr/releases) sayfasından yeniden indirip doğrulayın. Kurulu exe'yi geri getirmek için onarım/yeniden kurulum yapın, ardından yönetici PowerShell'de:

```powershell
& "C:\Program Files\AuraSplitTR\aurasplit.exe" recover
```

`recover` kalıcı engelleme kurallarını temizler ve doğrudan bağlantıya döndürür; VPN kurmaz. Sonra Windows üzerinden kaldırmayı yeniden deneyin. Kurulu exe kayıpsa MSI güvenli temizlik için kaldırmayı durdurabilir. Bu hata yolları canlıda henüz sınanmadı.

Güvenlik istisnası: beklenmeyen/güvenilmeyen içerikli veri klasörü ve `AuraSplitTR.quarantine-...` klasörleri elle incelenmek üzere korunabilir. İndirdiğiniz `.conf` dosyasını MSI silmez. Ayrıntılar: [mimari](ARCHITECTURE.md).

## Antivirüs ve SmartScreen

**Bu betanın exe ve MSI dosyaları Authenticode imzalı değildir.** SmartScreen uyarısı çıkabilir. Hizmet kuran ve ağ filtresi kullanan araçlar sezgisel antivirüs algılamalarına takılabilir; bir uyarı tek başına dosyanın güvenli veya zararlı olduğunu kanıtlamaz.

Geliştirmede Kaspersky Plus, **eski kendi kendini kuran exe'de** davranış algılaması (`PDM:Trojan.Win32.Generic`) gösterdi ve hizmetin başlamasını bekletti. MSI'ye geçildikten sonra **aynı test PC'sinde** kurulum/başlatmada uyarı gözlenmedi. Bu, diğer makineler/antivirüs sürümleri için sonuç değildir.

- Yalnızca proje Releases sayfasından indirin; SHA-256'yı ve mümkünse GitHub derleme kaynağını doğrulayın. Kaynak kod ve derleme yönergeleri açıktır.
- İsterseniz hash'i VirusTotal'da aratın. Dosya yüklemek üçüncü tarafla paylaşımdır; anahtar/yapılandırma yüklemeyin. Algılama sayısı tek başına güvenlik garantisi değildir.
- **Antivirüsünüzü asla kapatmayın veya istisna eklemeyin.** Yanlış pozitif olduğunu düşünüyorsanız üreticiye inceleme için bildirin.
- **SignPath Foundation üzerinden kod imzalama planlanıyor.** Mevcut beta imzalı değildir; bu bir onay alınmış olduğu iddiası değildir.

## Nasıl çalışır?

Araç Discord bağlantılarını VPN'e, diğer bağlantıları normal internetinize yönlendirir. Tünel yokken bulunan Discord uygulamasını engelli tutar; sistem DNS ayarlarını değiştirmeniz gerekmez.

Teknik olarak **sing-box TUN**, süreç/alan adı kurallarıyla Discord'u **WireGuard** çıkışına, diğer trafiği `direct` çıkışına gönderir. **WFP**, bulunan her Discord çalıştırılabilir dosyası için kalıcı engelleme ve TUN üzerinde dinamik izin uygular. Hizmet kapanınca dinamik izin kaybolur, kalıcı engeller kalır. Kurucuların/tarayıcının tünellenmesi, hizmet durmuşken onların da WFP ile engellendiği anlamına gelmez.

Alan adı kuralları `discord.com`, `discord.gg`, `discordapp.com`, `discordapp.net`, `discord.media`, `discordcdn.com`, `discordsays.com`, `dis.gd`, `discord.gift`, `discord.dev` ve mimaride belirtilen diğer Discord hedeflerini kapsar. Hizmet çalışırken bu adların DNS'i tünelden çözülür. WireGuard sunucusu alan adıyla belirtilmişse tüneli kurmak için sunucu adı sistem çözücüsüyle tünel dışında çözülür.

**Otomatik ağ isteği:** Proton veya başka sağlayıcı seçseniz de hizmet, tünelin içinden **`https://www.cloudflare.com/cdn-cgi/trace`** adresine başlangıçta, normalde **5 dakikada bir** ve **ağ değişiminde** HTTPS bağlantı denetimi yapar; başarısızlıkta daha sık yeniden deneyebilir. Bu denetimin DNS sorgusu da tünelden gider. Yanıttan yalnızca `warp=` ve `ip=` okunur; IP'nin geçerli adres olduğu kontrol edilir, **saklanmaz veya günlüğe yazılmaz**. Cloudflare isteği VPN çıkış adresinden görür.

Ayrıntılar: [ARCHITECTURE.md](ARCHITECTURE.md).

## Test durumu

Kaynak: [22 Kasım 2026 canlı test kaydı, run 1–5](docs/testing/phase3_live_results_2026-11-22.md). Önceki denemelerin açık maddeleri sonraki sonuçlarla birlikte değerlendirilmiştir.

### Kapsam

**Tek Windows 11 x64 bilgisayar**, IPv4-only Ethernet (fiziksel adaptörde IPv6 bağlı değil), Kaspersky Plus açık, imzasız beta. Başka bir uygulamadan Wintun paketi zaten vardı. Farklı donanım/ağ/antivirüs için garanti değildir; beta üretime hazır kabul edilmemelidir.

### Gözlenenler

| Senaryo | Gözlem / yöntem |
|---|---|
| Sağlayıcılar ve Discord | Proton **Plus**, WARP ve genel WireGuard seçeneğinde Discord TCP soketleri TUN `172.19.0.1` üzerindeydi. Genel seçenekte yine Proton `.conf` kullanıldı; başka sağlayıcı denenmedi. Ses kanalına katılım kullanıcı tarafından doğrulandı. |
| Durma / çökme / ağ kesintisi | Saniyelik TCP örneklemesinde TUN dışında 0 Discord bağlantısı: `stop` 25 sn, çökme sonrası SCM yeniden başlatmasına kadar ~4–5 sn, fiziksel ağ kesintisi ~40 sn. Bu ölçüm tek başına UDP/DNS kanıtı değildir. |
| Durum ve yeniden bağlantı (run 4) | İlk bağlantıda `VPN_CONNECTING` ardından `VPN_CONNECTIVITY_VERIFIED`. Ethernet kesilince `VPN_DISCONNECTED`, geri takıldıktan 6 sn sonra doğrulama; Discord TUN'dan yeniden bağlandı. |
| Windows yeniden başlatma | Hizmet/tünel açılıştan ~12 sn sonra hazırdı; kullanıcı Discord'u açınca TCP soketleri TUN'daydı. Açılış penceresinde paket yakalanmadı. |
| Yaşam döngüsü | MSI kurulum/yükseltme/kaldırma ve `disable`/`start` başarılıydı. Kaldırmada 0 AURA WFP filtresi/alt katmanı kaldı; IP/DNS/rota kayıtları kurulum öncesiyle aynıydı; özel anahtarlı veri klasörü silindi. |
| Yapılandırıcı | Dosya seçici run 4'te kullanıcı tarafından doğrulandı. Geçersiz `.conf`, çalışan profil ve koruma değiştirilmeden reddedildi. |
| **Run 5 — hizmet çalışırken** | 120 sn fiziksel NIC yakalamasında (Discord yeniden açıldı, ~30 sn ses ve tarayıcı denendi) **0 Discord DNS adı, 0 Discord TLS SNI, 0 Discord HTTP Host** görüldü. 155.505 paket; 0 IPv6 paketi. Bu yakalama tüm olası sızıntıları dışlamaz. |
| **Run 5 — hizmet durmuşken** | Uygulama bağlanamadı; tarayıcı sekmesi kapalı tekrarında 0 Discord TLS SNI/HTTP Host, ancak fiziksel ağda **9 açık metin Discord DNS sorgusu** görüldü. Tarayıcı sekmesi açıkken doğrudan Discord TLS bağlantıları görüldü; soket sahipliği bunları tarayıcıya bağladı. |

### Henüz test edilmeyenler ve sınırlar

- Açılış penceresi paket yakalaması, QUIC SNI, ECH ve şifreli DNS ile gizlenen adlar. Yakalama 256 bayt snaplen kullanır; QUIC SNI ayrıştırılmadı. İki UDP/443 akışı sonradan soket sahibiyle Spotify'a bağlandı.
- Yerel IPv6 ağları ve IPv6 yeteneği değişiminde tünelin yeniden kurulması. Yakalamada IPv6 görülmemesi IPv6 sızıntı testinin yerine geçmez.
- Diğer bilgisayarlar/antivirüsler, temiz Wintun ortamı, Proton Free ve Proton dışı genel sağlayıcılar, ekran paylaşımı, CPU ölçümü.
- Zorlanmış MSI yükseltme/kaldırma hatasında geri alma, onarım, eksik exe ve bozuk profil/hizmet yokken `recover` hata yolları.
- Kalıcı engelleme yalnızca keşfedilen Discord uygulaması/güncelleyicisi içindir. Başka konuma kopyalanan Discord, kurucular ve tarayıcı WFP kapsamına girmez. Yeni sürümün keşfinde ~1 sn pencere veya hizmet durmuşken hazırlanmış sürümde bir sonraki taramaya kadar boşluk olabilir. Süreç tespiti başarısızlığı da yönlendirme kapsamını etkileyebilir.
- Kural sınırı toplam 256, kullanıcı profili başına 32 programdır; aşılırsa `status` eksik kapsam gösterir. DNS koruması listelenen Discord adlarıyla sınırlıdır; üçüncü taraf adları yerel DNS kullanabilir. Hizmet dururken uygulama engellense de Windows DNS İstemcisi açık metin sorgu gönderebilir ve tarayıcı doğrudan bağlanabilir.

## Gizlilik

**Telemetri veya analiz gönderimi yoktur.** Bununla birlikte uygulama çalışmak için ağ istekleri yapar:

| İstek | Ne zaman / nereye? |
|---|---|
| WARP kaydı | Yalnızca kullanıcı WARP'ı seçip koşulları kabul edince Cloudflare kayıt API'sine. Açık anahtar ve kayıt bilgileri (koşul kabul zamanı, rastgele cihaz seri değeri, model/dil) gönderilir; özel anahtar gönderilmez, yanıtın erişim token'ı saklanmaz. |
| Bağlantı denetimi | Yukarıdaki Cloudflare trace HTTPS isteği ve DNS çözümlemesi; tünelden, başlangıçta/5 dakikada bir/ağ değişiminde ve yeniden denemelerde. |
| Discord DNS / VPN bağlantısı | Hizmet çalışırken listelenen Discord adları tünel içi DNS sunucusuna, WireGuard trafiği seçtiğiniz sağlayıcıya gider. VPN sunucu adı varsa ilk çözümlemesi tünel dışındadır. |

Günlükler `%ProgramData%\AuraSplitTR` altında yerelde kalır. Varsayılan düzey **`warn`**; normal bağlantılar ve DNS geçmişi yazılmaz, kullanıcı klasörü adları temizlenir. Hata satırları alan adı/IP içerebilir; paylaşmadan önce inceleyin. `run --debug` ayrıntılı bağlantı bilgilerini konsola yazar.

Uygulamanın aktif özel anahtar kopyası yalnızca **`%ProgramData%\AuraSplitTR\profile.json`** içindedir (Administrators/SYSTEM). İndirdiğiniz `.conf` silinene kadar ayrıca anahtar içerir; tutulmuş karantina kopyaları da anahtar içerebilir. Bu araç tam cihaz VPN'i veya anonimlik garantisi değildir.

## Teşekkürler ve atıflar

- [sing-box](https://github.com/SagerNet/sing-box) ve [sing-tun](https://github.com/SagerNet/sing-tun) — SagerNet, GPL-3.0-or-later; TUN/yönlendirme altyapısı.
- [WireGuard / wireguard-go](https://www.wireguard.com/) — WireGuard protokolü ve Go uygulaması (kullanılan wireguard-go türevi MIT). **"WireGuard" and the "WireGuard" logo are registered trademarks of Jason A. Donenfeld.**
- [Wintun](https://www.wintun.net/) — Windows TUN sürücüsü; gömülü DLL koşulları üçüncü taraf lisans dosyasındadır.
- [wireguard-windows](https://git.zx2c4.com/wireguard-windows/) — MIT; WFP yapı/binding tanımları uyarlanmıştır.
- [wgcf](https://github.com/ViRb3/wgcf) ve [warp-plus](https://github.com/bepass-org/warp-plus) — WARP kayıt protokolünü kullanan açık kaynak projelerine teşekkürler. AURA'nın kayıt uygulaması `internal/provider/warp.go` içindedir; bu atıf bu projelerden kod kopyalandığı iddiası değildir.
- [WiX Toolset](https://wixtoolset.org/) ve [go-winres](https://github.com/tc-hib/go-winres) — MSI paketleme ve Windows kaynak araçları.

Tam lisans metinleri ve uyarlama notları: [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

## Lisans

**GPL-3.0-or-later** · Copyright (C) 2026 AURA Split TR contributors.

[LICENSE](LICENSE) · [NOTICE](NOTICE) · [TRADEMARKS.md](TRADEMARKS.md)

## Sorumluluk reddi

GPL kapsamında **olduğu gibi, hiçbir garanti olmadan** sunulur. Yerel yasalara, Discord'un ve VPN sağlayıcınızın kullanım koşullarına uymak sizin sorumluluğunuzdadır. Proje Discord, Cloudflare, Proton veya WireGuard ile bağlantılı değildir; bu kuruluşlarca onaylanmış veya desteklenmiş değildir.

Güvenlik açığı için herkese açık issue yerine [SECURITY.md — özel bildirim](SECURITY.md) yolunu kullanın. [CONTRIBUTING.md](CONTRIBUTING.md) · [Kaynaktan derleme: docs/BUILD.md](docs/BUILD.md)

---

## English summary

**Unsigned Windows 10/11 x64 beta.** AURA Split TR runs as a background service, routing Discord's app, updater, installers and listed domains (browser Discord **while running**) through WireGuard; other traffic uses your normal connection. Supports free WARP, Proton VPN Free/Plus and standard single-peer configs. GPL-3.0-or-later.

### Download and setup

1. Download the latest MSI and matching `SHA256SUMS.txt` from [Releases](https://github.com/umut720s/aura-split-tr/releases). Compare the hash; replace the example version:

   ```powershell
   (Get-FileHash .\AuraSplitTR-0.1.0-beta-x64.msi -Algorithm SHA256).Hash.ToLower()
   Get-Content .\SHA256SUMS.txt
   # Optional provenance check (GitHub CLI):
   gh attestation verify .\AuraSplitTR-0.1.0-beta-x64.msi --repo umut720s/aura-split-tr
   ```

   Do not proceed if verification fails. Only after verifying the hash **and release-page origin**, use SmartScreen **More info → Run anyway** if necessary. A hash alone does not authenticate the source.
2. Install the MSI, approve UAC, then open Start Menu **“AURA Split TR - Yapılandır”**. Nothing is blocked until configured. New MSIs preserve the profile on upgrade.
3. Select a provider:
   - **WARP:** no download/account; read and accept Cloudflare's terms. Region/IP “abuse” limits may refuse registration; use another provider then.
   - **Proton:** [account.protonvpn.com](https://account.protonvpn.com) → **Downloads → WireGuard configuration**. Choose Windows; NetShield Off/Block malware only; Moderate NAT and NAT-PMP Off. VPN Accelerator may stay on. Select a nearby server outside Turkey (Free servers for Free accounts), download `.conf`, then open it in AURA's picker. Disconnect the Proton VPN app. [Official guide](https://protonvpn.com/support/wireguard-configurations).
   - **Other WireGuard:** select a standard `.conf` with one `[Peer]`; `PostUp`/`PostDown` scripts are not executed.
4. Check `status`, fully quit Discord from the tray and reopen it. **Delete the downloaded `.conf` and its Recycle Bin copy after setup: it contains your private key. Never share it.** If the picker fails, paste the copied file path.

### Commands and troubleshooting

Run administrator PowerShell. Example: `& "C:\Program Files\AuraSplitTR\aurasplit.exe" status`. Replace `status` with the required command:

| Command | Effect / when to use |
|---|---|
| `status` | Inspect service, tunnel, VPN probe and coverage. Look for `VPN_CONNECTIVITY_VERIFIED` and complete coverage; service running alone is insufficient. |
| `stop` | Stop temporarily; discovered Discord programs stay **blocked**. Automatic startup remains enabled. |
| `start` | Restore rules, enable automatic startup and start. |
| `disable` | Confirm, disable startup, stop and remove blocks: Discord can connect **directly**. |
| `recover` | Emergency block removal even with a broken profile/missing service; disable/stop if present. No confirmation. |
| `setup` | Reconfigure using the installed copy. |

- For `VPN_CONNECTING`/`VPN_DEGRADED`, wait ~1–2 minutes, check internet, then try another server. For stuck updates/“Connecting”, check `status`; a stopped service intentionally blocks discovered apps. Use `start`, or `disable` for direct access.
- For messages failing after an IP change, fully restart Discord, then try another server. IPv6-less networks are supported; other VPN clients can conflict.
- **Never disable antivirus or add exclusions.** The old self-installing build triggered Kaspersky behaviour detection; MSI raised no alerts on the one test PC. This is not a general guarantee. Verify hash, provenance and source; optionally look up a hash on VirusTotal. Report false positives to the vendor. SignPath Foundation signing is planned, not active.
- Uninstall via **Settings → Apps → AURA Split TR → Uninstall**. Normal removal deletes service, WFP rules, files and `%ProgramData%\AuraSplitTR`, including the key. If broken removal leaves Discord blocked, verify and repair/reinstall the **same MSI version**, run the full-path `recover` command, then uninstall again. Failure paths are not live-tested. Untrusted/unexpected data and quarantine folders may be retained; downloaded `.conf` files are not removed by MSI.

### How it works, privacy and test limits

sing-box TUN applies process/domain rules → WireGuard; other traffic goes direct. Persistent per-executable WFP blocks protect **discovered Discord apps/updaters**; the dynamic TUN permit disappears when the service exits. System DNS settings are unchanged; listed Discord DNS names use the tunnel while running.

**Automatic network request:** for all providers, a tunneled HTTPS probe calls `https://www.cloudflare.com/cdn-cgi/trace` at startup, every 5 minutes and on network changes, with failure retries. Its DNS lookup is tunneled too. Only `warp=`/`ip=` are read; the IP is validated but **never stored/logged**. Cloudflare sees the VPN exit IP. WARP registration happens only when selected and terms accepted, sending the public key and registration metadata, not the private key; the returned token is not retained. A named VPN endpoint is initially resolved outside the tunnel. **No telemetry.**

Logs stay local at warn level with user paths scrubbed; errors may contain hosts/IPs. The active key is in `%ProgramData%\AuraSplitTR\profile.json` (Administrators/SYSTEM); downloaded configs and retained quarantine copies may also contain keys. Redact logs before sharing.

| Category | Evidence / limits |
|---|---|
| Scope | One Windows 11 x64 PC, IPv4-only Ethernet, Kaspersky Plus, unsigned beta, Wintun already present. [Run 1–5 record](docs/testing/phase3_live_results_2026-11-22.md). |
| Observed | Proton Plus, WARP and generic option with a Proton config; Discord TCP via TUN, user-confirmed voice. Stop/crash/network-loss socket sampling: no off-TUN Discord TCP. Run 4 verified network-change status/reconnection and picker. Boot readiness ~12 s; MSI lifecycle/key removal, disable/start, invalid config rejection observed. |
| Run 5 capture | Running: **no Discord DNS/SNI/HTTP Host names on the physical NIC in that 120 s capture**. Stopped: app blocked, but **plaintext Discord DNS visible and browser Discord tabs connected directly**. Not proof against all leaks. |
| Not tested | Boot-window capture, QUIC SNI/ECH/encrypted-DNS coverage, native IPv6/capability changes, other PCs/AVs, clean Wintun, Proton Free/other generic providers, screen sharing, CPU, forced MSI rollback/repair/recovery failure paths. |

Fail-closed excludes installers, browsers and undiscovered copies. New versions have a ~1 s discovery window; versions staged while stopped wait for reconciliation. Process lookup failures, rule limits (256 total/32 per user profile) and unlisted domains limit coverage. Capture truncation/encryption can hide names. This is not a whole-device anonymity tool or a production-readiness claim.

Thanks to **SagerNet sing-box/sing-tun** (GPL-3.0-or-later), **WireGuard/wireguard-go**, **Wintun**, **wireguard-windows** (MIT WFP bindings adapted), **wgcf/warp-plus** using the WARP registration protocol, **WiX Toolset** and **go-winres**. See [credits](#teşekkürler-ve-atıflar) and [third-party licenses](THIRD_PARTY_LICENSES.md). "WireGuard" and the "WireGuard" logo are registered trademarks of Jason A. Donenfeld.

**GPL-3.0-or-later · Copyright (C) 2026 AURA Split TR contributors.** As-is, without warranty. Comply with local law and Discord/VPN provider terms. Not affiliated with or endorsed by Discord, Cloudflare, Proton or WireGuard. [LICENSE](LICENSE) · [NOTICE](NOTICE) · [TRADEMARKS.md](TRADEMARKS.md).

[Private vulnerability reporting](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [Build from source](docs/BUILD.md) · [Bug reports](https://github.com/umut720s/aura-split-tr/issues)
