<img src="assets/aura-logo.png" alt="AURA Split TR" width="360">

# AURA Split TR

Windows için **yalnızca Discord** trafiğini bir VPN (WireGuard) tünelinden geçiren,
arka planda Windows hizmeti olarak çalışan küçük bir araç.

- Discord uygulaması (`Discord.exe`), güncelleyicisi (`Update.exe`) ve kurulum dosyaları → VPN tüneli
- Discord alan adları (discord.com, discord.gg, discordapp.com/.net, discord.media,
  discordcdn.com, discordsays.com, dis.gd, discord.gift, discord.dev …) **her
  programdan, tarayıcılar dahil** → VPN tüneli (tarayıcıdaki Discord da tünellenir)
- Oyunlar, diğer siteler ve geri kalan her şey → normal (doğrudan) bağlantınız
- Pencere yok, tepsi simgesi yok; bilgisayar açılınca kendiliğinden başlar
- Discord PTB / Canary sürümleri de desteklenir
- **Fail-closed (sınırlı, canlı testte TCP soket düzeyinde gözlendi):** kalıcı Windows Filtering
  Platform kuralları, **bulunan** Discord programlarını (masaüstü uygulaması ve
  `Update.exe`) hizmet durduğunda, çöktüğünde, açılışta ve tünel çalışmadığında
  tünel dışında engeller. Kapsam dışı kalanlar ve kalan pencereler (yeni sürüm için
  ~1 sn yarış, hizmet durmuşken hazırlanan sürüm, tarayıcıdaki Discord, hizmet
  durmuşken DNS sorguları): aşağıda [Sınırlamalar](#sınırlamalar).

> English summary is at the bottom.

## Canlı test durumu — 22 Kasım 2026

**Kapsam:** tüm canlı denemeler **tek Windows 11 x64 PC**, IPv4-only Ethernet,
Kaspersky Plus açık ve Authenticode imzasız beta ile yapıldı.
[Canlı test kaydı (run 1–3)](docs/testing/phase3_live_results_2026-11-22.md)
ayrıntıları ve kronolojiyi içerir. Beta **üretime hazır değildir**;
herkese açık sürüm kararı bakımcıya aittir.

| Kategori | Sonuç / yöntem |
|---|---|
| **Gözlendi — Discord** | Proton, WARP ve genel WireGuard seçeneğinde (genel seçenekte de Proton `.conf` kullanıldı) `Get-NetTCPConnection` örneklemesindeki kurulmuş Discord TCP soketlerinin yerel adresi TUN `172.19.0.1` idi. Ses kanalına katılım başarılıydı (kullanıcı gözlemi); UDP yolu çıkarımdır, paket yakalanmadı. |
| **Gözlendi — fail-closed** | `stop` ile 25 sn, `taskkill` sonrası SCM yeniden başlatmasına kadar ~4–5 sn ve ~40 sn fiziksel ağ kesintisinde saniyelik soket örneklemesi: TUN dışında **0 Discord TCP soketi**. Paket yakalama değildir; UDP ve DNS yakalanmadı. |
| **Gözlendi — yeniden başlatma** | Hizmet etkin Windows yeniden başlatmasında hizmet/tünel açılıştan ~12 sn sonra hazırdı; kullanıcı Discord'u açınca TCP soketleri TUN'daydı. Açılış penceresinde sızıntı yakalaması yapılmadı. |
| **Gözlendi — yaşam döngüsü** | `disable`/`start`, MSI kurulum/yükseltme/kaldırma başarılı. Kaldırma sonrası `netsh wfp show filters/state`: 0 AURA sağlayıcı filtresi/alt katmanı; IP adresleri, DNS sunucuları ve rotalar kurulum öncesi kayıtla aynı; `%ProgramData%\AuraSplitTR` (özel anahtar) silindi. |
| **Gözlendi — geçersiz yapılandırma** | Çalışan profil, WFP politikası ve Discord TUN yönlendirmesi değişmeden reddedildi. |
| **Henüz test edilmedi** | Paket yakalamayla DNS/IPv6/UDP, açılış penceresi ve tarayıcı/ECH sızıntıları; zorlanmış kaldırma/yükseltme hatasında MSI geri alma; CPU ölçümü; yerel IPv6 bağlantılı makineler; diğer antivirüsler; birden fazla makine. |
| **Uygulandı, canlı test edilmedi** | Run 3 sonrası yapılandırıcı dosya seçici, `VPN_CONNECTING` başlangıç toleransı ve ağ değişiminde bağlantı denemesi. Run 3'te durum göstergesi ~40 sn kesintiyi yansıtmadı. |

Canlı testlerde bulunan ve düzeltilenler:

- IPv6 olmayan makinede WireGuard bind hatası: bağlantı yolu düzeltildi, canlıda yeniden doğrulandı.
- Tarayıcıda IPv6 nedeniyle bağlantı kaybı: makineye uygun TUN/DNS yapılandırmasıyla düzeltildi, canlıda yeniden doğrulandı.
- WARP sunucu adı uç noktasında el sıkışma hatası: IP çözümlemesiyle düzeltildi, canlıda yeniden doğrulandı.
- Kaspersky'nin kendi kendini kuran exe'yi bekletmesi: MSI'ye geçildi; aynı PC'de MSI denemelerinde AV uyarısı/başlangıç takılması gözlenmedi.

## Desteklenen sağlayıcılar

| Sağlayıcı | Ücret | Gerekli |
|---|---|---|
| **Cloudflare WARP** | Ücretsiz | Hesap gerekmez; Cloudflare kullanım koşullarını kabul etmeniz gerekir |
| **Proton VPN** | Free veya Plus | Proton hesabından indirilen WireGuard `.conf` dosyası |
| **Diğer WireGuard** | Sağlayıcıya bağlı | Herhangi bir standart WireGuard `.conf` dosyası |

## İmzasız beta ve indirme doğrulaması

**v0.1.0-beta dosyaları (exe ve MSI) Authenticode ile imzalı DEĞİLDİR.**
Windows SmartScreen ve antivirüs ürünleri uyarı verebilir. Her dosyanın SHA-256
özetini aynı sürümün `SHA256SUMS.txt` dosyasıyla karşılaştırın ve GitHub derleme
kaynağı doğrulamasını (build provenance attestation) yapın:
`gh attestation verify <file> -R umut720s/aura-split-tr` (`<file>` yerine indirdiğiniz
dosyanın yolunu yazın). Doğrulama başarısızsa dosyayı çalıştırmayın.
**Antivirüsü asla kapatmayın veya istisna eklemeyin.** Yanlış pozitifleri antivirüs
üreticisine bildirin. Authenticode imzalama daha sonraki bir sürüm için planlanıyor.

## Kurulum

1. [GitHub Releases](https://github.com/umut720s/aura-split-tr/releases) sayfasındaki
   aynı sürümün **Assets** bölümünden `AuraSplitTR-<sürüm>-x64.msi` ve
   `SHA256SUMS.txt` dosyalarını indirin. PowerShell'de SHA256 özetini hesaplayın ve
   `SHA256SUMS.txt` içindeki MSI satırıyla aynı olduğunu doğrulayın; farklıysa kurmayın:

   ```powershell
   (Get-FileHash .\AuraSplitTR-0.1.0-beta-x64.msi -Algorithm SHA256).Hash.ToLower()
   Get-Content .\SHA256SUMS.txt
   ```

2. MSI'ye çift tıklayın ve Windows'un yönetici iznini (UAC) onaylayın. Program
   `%ProgramFiles%\AuraSplitTR` altına kurulur. Hizmet yapılandırılana kadar
   başlatılmaz, otomatik başlamaz ve hiçbir trafik engellenmez.
3. VPN yapılandırmanızı hazırlayın:
   - **Cloudflare WARP (ücretsiz, hesap gerekmez):** indirilecek yapılandırma yoktur.
     Yapılandırıcı otomatik kayıt yapar; sihirbazda Cloudflare kullanım koşullarını
     **okuyup kabul etmeniz** gerekir.
   - **Proton VPN (Free veya Plus):** [Proton hesabınıza](https://account.protonvpn.com)
     giriş yapın → **Downloads** → **WireGuard configuration**. Platformu **Windows**,
     **NetShield** ayarını **Off** veya **Block malware only**, **Moderate NAT** ayarını
     **Off**, **NAT-PMP / port forwarding** ayarını **Off** seçin. **VPN Accelerator**
     açık kalabilir. Türkiye dışında size yakın bir sunucu seçin (Free planda yalnızca
     ücretsiz sunucular). Yapılandırmayı oluşturup `.conf` dosyasını indirin.
     **Bu dosya ÖZEL ANAHTARINIZI içerir.** Proton VPN uygulamasının bağlantısını kapatın.
   - **Diğer WireGuard sağlayıcıları:** tam olarak bir `[Peer]` içeren standart bir
     WireGuard `.conf` kullanın. `PostUp` / `PostDown` betikleri yok sayılır.
4. **Başlat menüsü → "AURA Split TR - Yapılandır"** kısayolunu açın, UAC iznini
   onaylayın ve sağlayıcıyı seçin. Proton/diğer sağlayıcılar için `.conf` dosyasını
   açılan dosya seçicide seçin. Alternatif olarak "Yol olarak kopyala" ile yolunu kopyalayıp yapıştırın; tırnaklar sorun değildir.
   Sihirbaz profili kaydeder, kuralları uygular, hizmeti otomatik başlatmaya alır ve başlatır.
5. Sihirbaz hizmetin **çalıştığını** söyledikten sonra Discord'u sistem tepsisinden
   **tamamen kapatın** (sağ tık → Discord'dan Çık) ve yeniden açın.
6. `.conf` dosyasını sonrasında silin (Geri Dönüşüm Kutusu dahil) veya özel bir yerde
   saklayın. **ASLA Git deposuna, issue'ya, paylaştığınız ekran görüntüsüne ya da günlüğe
   koymayın.** Uygulamanın özel anahtar kopyası yalnızca
   `%ProgramData%\AuraSplitTR\profile.json` içinde, yalnızca yöneticiler ve SYSTEM
   erişimiyle saklanır. İndirdiğiniz `.conf` dosyası silinene kadar ayrı bir kopyadır.

Sağlayıcıyı değiştirmek için yapılandırıcıyı yeniden çalıştırın. `setup` yalnızca
MSI ile kurulan kopyadan çalışır.

### Sorun giderme

Aşağıdaki komutları **yönetici PowerShell** penceresinde çalıştırın (`&` gereklidir).

| Sorun / işlem | Yapılacak |
|---|---|
| Durumu kontrol et | `& "C:\Program Files\AuraSplitTR\aurasplit.exe" status` |
| Günlük konumu | `%ProgramData%\AuraSplitTR\service.log` (yöneticiler; eski kayıtlar `.1` ve `.2`) |
| Hizmet başlatılıyor durumunda kalıyor | Antivirüs imzasız beta dosyasını bekletiyor olabilir; algılama geçmişini kontrol edin. **Antivirüsü kapatmayın veya istisna eklemeyin.** Yanlış alarmı antivirüs üreticisine ve projeye bildirin. İmzalı sürümler planlanıyor. |
| Discord engelli | `& "C:\Program Files\AuraSplitTR\aurasplit.exe" disable` veya `& "C:\Program Files\AuraSplitTR\aurasplit.exe" recover` ile kuralları kaldırın ve doğrudan bağlantıya dönün. |
| Kaldırma | Windows **Ayarlar → Uygulamalar → Yüklü uygulamalar → AURA Split TR → Kaldır** |

> **Eski kendi kendini kuran sürümden geçiş:** MSI'den önce eski programın
> `aurasplit.exe uninstall` komutuyla kaldırın, ardından MSI'yi kurup yapılandırın.

### Güncelleme ve onarım

Yeni sürümün `.msi` dosyasını çalıştırmanız yeterlidir: eski sürüm otomatik kaldırılır
(profil ve kurallar korunur), yeni sürüm kurulur. Eski sürüm yeni kurulumun işleminin
içinde kaldırılır; yeni kurulum yarıda başarısız olursa Windows Installer eski sürümü geri
getirir. Windows Installer hizmeti yeniden kaydederken durdurur; kurulum başarıyla
tamamlandıktan sonra hizmet, **yalnızca** profil varsa ve kalıcı Discord kuralları
yüklüyse (yani `disable`/`recover` ile kapatılmadıysa) otomatik başlatmaya alınıp yeniden
başlatılır. Aynı
durum MSI onarımı (Programlar ve Özellikler > Onar) için de geçerlidir. Daha eski bir
sürüm, yenisinin üzerine kurulamaz.

## Komutlar

Yönetici komut isteminde (veya gerektiğinde araç izin ister):

```text
aurasplit.exe setup       Yapılandırma sihirbazı (varsayılan; Başlat menüsü: "AURA Split TR - Yapılandır")
aurasplit.exe status      Hizmet ve tünel durumu
aurasplit.exe start       Başlat (açılışta otomatik başlatmayı da açar)
aurasplit.exe stop        Durdur — bulunan Discord programları ENGELLİ kalır (fail-closed)
aurasplit.exe restart     Yeniden başlat
aurasplit.exe disable     Devre dışı bırak: hizmeti durdurur, açılışta başlatmaz ve
                          Discord engelleme kurallarını kaldırır → Discord VPN'siz,
                          DOĞRUDAN bağlanır (onay ister)
aurasplit.exe recover     Kurtarma: engelleme kurallarını her durumda kaldırır ve hizmeti
                          durdurur (profil bozuk veya hizmet kurulu olmasa da çalışır)
aurasplit.exe uninstall   Windows üzerinden (MSI) nasıl kaldırılacağını gösterir
aurasplit.exe run         Ön planda çalıştır (hata ayıklama, günlük konsola, Ctrl+C ile çıkış)
aurasplit.exe run --debug Ayrıntılı günlük: her bağlantı ve hedef adresi yazılır
aurasplit.exe version     Sürüm
```

Sağlayıcıyı değiştirmek için "AURA Split TR - Yapılandır" kısayolunu (`setup`) yeniden
çalıştırmanız yeterlidir. `setup` ve diğer yönetici komutları, kullanıcı tarafından
başlatıldıklarında gerekirse UAC ile izin ister; Windows Installer'ın çalıştırdığı
`--msi` biçimleri (`recover --msi`, `start --msi`, `uninstall --msi`) hiçbir şey sormaz.

### stop, disable ve recover farkı

| Komut | Hizmet | Açılışta | Discord |
|---|---|---|---|
| `stop` | durur | yine başlar | **engelli** (bulunan programlar; tünel yok, kurallar duruyor) |
| `disable` | önce devre dışı, sonra durur | başlamaz (Disabled) | **doğrudan** (kurallar kaldırılır) |
| `recover` | önce devre dışı, sonra durur | başlamaz (Disabled) | **doğrudan** (acil durum; onay sormaz) |
| `start` | yeniden etkinleştirilir, başlar | başlar | tünelden (kurallar yeniden uygulanır) |

`disable`/`recover` hizmeti durdurmadan **önce** devre dışı bırakır; böylece Windows'un
sıradaki bir otomatik kurtarma yeniden başlatması kuralları geri getiremez. `restart`
devre dışı bir hizmeti başlatmaz; bunun için `start` (veya `setup`) kullanın.

Discord'u hiç açamıyorsanız (ör. profil bozuldu, VPN sağlayıcısı çalışmıyor) önce
`aurasplit.exe status` ile nedenini görün; doğrudan bağlantıya hemen dönmek için
`aurasplit.exe recover` çalıştırın. Program dosyası kaybolduysa MSI'yi onarın ya da
aynı sürümün `aurasplit.exe` dosyasını indirip herhangi bir klasörden
`aurasplit.exe recover` çalıştırın (kurallar sabit bir sağlayıcı kimliğiyle bulunur;
`recover` kurulu kopya gerektirmez).

## Çalıştığını doğrulama

- `"%ProgramFiles%\AuraSplitTR\aurasplit.exe" status` (yönetici olarak) her durumu ayrı
  satırda gösterir; birden fazlası aynı anda EVET olabilir:
  - `SERVICE_RUNNING` — Windows hizmet yöneticisine göre hizmet çalışıyor.
  - `TUNNEL_INITIALIZED` — tünel yapılandırması uygulandı (sunucunun yanıt verdiği
    henüz denetlenmedi).
  - `VPN bağlantısı` — tünelin içinden yapılan denemenin sonucu:
    `VPN_CONNECTING` (ilk 90 sn içinde bağlanıyor), `VPN_CONNECTIVITY_VERIFIED` (çalışıyor), `VPN_DEGRADED` (1–2 deneme başarısız ya da
    WARP `warp=off`), `VPN_DISCONNECTED` (fiziksel bağlantı yok veya art arda 3+ deneme başarısız).
  - `PROTECTION_ACTIVE` — kalıcı Discord engelleme kuralları yüklü; ayrıca tünel izninin
    açık olup olmadığı (eksikse `açık, EKSİK (2/3 program)`). Altındaki `Kapsam` satırı
    `TAM` (son tarama hatasız, her program çözüldü) ya da `EKSİK` (neden ile; bu durumda
    hiçbir kural silinmez ve birkaç saniyede bir yeniden denenir) gösterir.
  - `Discord şu anda` — bunların özeti: TÜNELDEN, ENGELLİ veya DOĞRUDAN.
  `bilinmiyor` görürseniz durum kaydı çalışan hizmete ait değildir veya 90 saniyedir
  yenilenmemiştir. Doğrulama hiçbir zaman yalnızca sürecin çalışmasına bakılarak yapılmaz.
- `services.msc` içinde **AuraSplitTR** hizmeti *Çalışıyor* ve *Otomatik* olmalı
  (yalnızca MSI kurulup henüz yapılandırılmadıysa *El ile* ve durmuş olması normaldir).
- Günlük dosyası: `%ProgramData%\AuraSplitTR\service.log` (en fazla 2 MB; eski kayıtlar
  `service.log.1` ve `service.log.2`; yalnızca yöneticiler okuyabilir). Varsayılan günlük
  düzeyi `warn`: normal bağlantılar ve DNS sorguları yazılmaz. Kullanıcı klasörü yolları
  `C:\Users\<user>` olarak yazılır. Dosya döndürülemezse sınır aşılmaz, yeni satırlar
  atlanır ve `status` bunu uyarı olarak gösterir.
- `%ProgramData%` altında `AuraSplitTR.quarantine-...` klasörü görürseniz, araç
  güvenilmeyen içerik bulmuş ve silmek yerine oraya taşımıştır (yönetici olmayanların
  okuyabildiği bir profil de güvenilmez sayılır). Profil oraya taşındıysa "Yapılandır"
  (`setup`) ile yeniden yapılandırın. Karantina klasörleri MSI kaldırmasıyla silinmez;
  başka kullanıcıların oluşturduğu benzer adları (bağlantı/junction olabilir)
  `Remove-Item -Recurse` ile silmeyin. (`%ProgramFiles%\AuraSplitTR` klasörü artık
  Windows Installer'a aittir; araç oraya yazmaz, `setup` yalnızca izinlerini denetler.)
- Bağlantıların hangi çıkışa gittiğini görmek için hizmeti durdurup
  `aurasplit.exe run --debug` çalıştırın; ayrıntılı günlük yalnızca o pencereye yazılır.
  `run`, hizmet çalışırken başlamayı reddeder ve engelleme kurallarını hizmetle aynı
  şekilde uygular (Discord tünelden çalışır; `run` kapanınca yeniden engellenir).

## Kaldırma

**Ayarlar > Uygulamalar > Yüklü uygulamalar > AURA Split TR > Kaldır** (veya Denetim
Masası > Programlar ve Özellikler). Komut satırından: `msiexec /x AuraSplitTR-<sürüm>-x64.msi`.

Windows Installer sırasıyla:

1. Kurulu `aurasplit.exe` dosyasının yerinde olduğunu denetler. Dosya yoksa (ör.
   virüsten koruma programı karantinaya aldıysa) kaldırma **Türkçe bir hata iletisiyle
   durur**: bu dosya olmadan Discord engelleme kuralları kaldırılamaz ve Discord engelli
   kalırdı. Dosyayı karantinadan geri yükleyin ya da aynı sürümün MSI paketini yeniden
   indirip kurun (veya onarın), sonra kaldırmayı tekrar deneyin. Yalnızca Discord engelini
   hemen kaldırmak için aynı sürümün `aurasplit.exe` dosyasıyla yönetici olarak
   `aurasplit.exe recover` çalıştırın, sonra kaldırın. Kurulu exe geri yüklenmeden
   kaldırma sürdürülemez; dosya denetimi atlanamaz.
2. `aurasplit.exe recover --msi` çalıştırır (Discord engelleme kuralları kaldırılır,
   hizmet devre dışı bırakılıp durdurulur; pencere açılmaz, soru sorulmaz). **Bu adım
   başarısız olursa kaldırma geri alınır**: program ve hizmet yerinde kalır, Discord'un
   engelli kalıp kurtarma aracının silinmesi önlenir. Bilgisayarı yeniden başlatıp tekrar
   deneyin ya da `aurasplit.exe recover` çalıştırın. Kurtarmadan önce hizmetin başlangıç
   türü ve çalışma bayrağı güvenli kaydedilir; geri alma bunları geri yükler ve profil
   varsa WFP politikasını yeniden uygular.
3. Hizmeti siler.
4. Program dosyaları kaldırıldıktan sonra, başarılı işlemin commit aşamasında MSI'ye
   gömülü aynı sürüm araç `uninstall --msi` ile `%ProgramData%\AuraSplitTR` içindeki **yalnızca
   AURA Split TR dosyalarını** (profil = VPN özel anahtarı, durum dosyası, günlükler)
   siler, klasör boş kalırsa klasörü de siler. Klasör güvenilir değilse (ör. başka bir
   kullanıcı oluşturmuş) ya da içinde beklenmeyen bir şey varsa **hiçbir şey silinmez**;
   klasör elle incelemeniz için bırakılır (kaldırma yine
   başarılı biter). Bırakılan klasörde özel anahtar olabilir: içeriğini kontrol edip
   yönetici olarak silin.
5. Commit temizliği başarısızsa veri klasörü elle inceleme için kalır. Native EXE commit
   eyleminin stdout ayrıntıları MSI günlüğüne aktarılmaz; günlükte eylemin dönüş kodu bulunur.

IPv6 yalnızca sing-tun tarafından seçilen IPv4 varsayılan çıkış arabiriminde tercih
edilen kullanılabilir global IPv6 adresi ve `::/0` rotası birlikte varsa açılır.
Başka adaptörün IPv6 bağlantısı yeterli değildir.

`RollbackDisabled` set edilmiş yükseltme, onarım ve tam kaldırma işlem başlamadan
Türkçe hatayla reddedilir. Profil ve kurtarma kaydı commit aşamasına kadar korunur.

Yükseltme sırasında (yeni MSI eskisinin yerine kurulurken) 1, 2 ve 4. adımlar çalışmaz;
profil ve kurallar korunur. Eski sürüm yeni sürümün kurulum işleminin içinde kaldırılır:
yeni sürümün kurulumu başarısız olursa eski sürüm geri gelir. Hizmet, kurulum başarıyla
tamamlandıktan sonra yeniden başlatılır. Ardından Discord'u yeniden açın.

`aurasplit.exe uninstall` artık hiçbir şey silmez; yalnızca bu yolu gösterir.

## Sınırlamalar

- Beta için canlı test kapsamı **Windows 11 x64**; Windows 10 test edilmedi.
- Kurulum ve hizmet **yönetici izni** gerektirir (TUN sanal ağ arayüzü için).
- MSI kurulum/yükseltme/kaldırma yukarıdaki kapsamda canlı denendi; zorlanmış hata
  ile geri alma, onarım ve eksik exe gibi hata yolları **henüz canlı test edilmedi**.
- ~40 sn fiziksel ağ kesintisi ve dönüşü canlı denendi (TCP soket gözlemi).
  Sonraki ağ-değişimi probe düzeltmesi ve yerel IPv6 değişiminde tüneli yeniden kurma
  **henüz canlı test edilmedi**.
- Başka VPN istemcileriyle (ör. Proton VPN uygulaması, WARP uygulaması, diğer TUN tabanlı
  araçlar) **çakışabilir**. Bu aracı kullanırken Proton VPN uygulamasının kendi bağlantısını
  kapatın.
- Oyunlar ve diğer uygulamalar TUN arayüzü üzerinden **doğrudan** çıkar; trafikleri VPN'e
  gitmez, ancak çok nadir durumlarda gecikme veya uyumluluk farkı görülebilir.
- Ayar değişikliklerinden veya kurulumdan sonra **Discord yeniden başlatılmalıdır**.
- Bu bir gizlilik/anonimlik aracı değildir; yalnızca Discord trafiği tünellenir.
- Kalıcı engelleme yalnızca **bulunan Discord programları** içindir
  (`%LOCALAPPDATA%\Discord*\Update.exe` ve diskteki **tüm** `app-*\Discord*.exe`
  sürümleri, tüm kullanıcı profillerinde). Discord klasörleri değişiklik bildirimiyle
  izlenir (yeni sürüm ~1 sn içinde eklenir; açılamayan veya düşen bir izleme 1 sn'den
  60 sn'ye artan aralıklarla yeniden kurulur) ve dakikada bir yeniden taranır. Kalan
  yarış: yeni bir sürüm bu ~1 sn dolmadan **ve** tünel/hizmet çalışmazken bağlanırsa,
  ya da hizmet durmuşken hazırlanmış bir sürüm hizmet yeniden başlayana kadar
  kapsanmaz (hizmet dururken `Update.exe` engelli olduğundan güncelleme indirilemez).
  Diskte hâlâ var olan bir programın kuralı hiçbir zaman silinmez. Başka bir yere
  kurulmuş Discord, kurulum dosyaları ve tarayıcıdaki Discord bu kurallarla engellenmez;
  hizmet çalışırken tünele yönlendirilirler. Hizmet çalışmıyorken Discord'un DNS
  sorguları (Windows DNS İstemcisi üzerinden) ISS'nize gidebilir; bağlantıların kendisi
  engellenir. Ayrıntı: [SECURITY.md](SECURITY.md).
- Kural bütçesi: kalıcı politika en fazla 256 program (profil başına 32) kapsar;
  mevcut + yeni toplamı aşarsa yeni programlar eklenmez, `status` "Kapsam: EKSİK"
  gösterir ve var olan kurallar yer açmak için **silinmez**. WFP'nin devre dışı
  (disabled) gösterdiği bir kural koruma sayılmaz; aynı işlemde silinip yeniden eklenir.
- Kalıcı WFP kuralları gerçek makinede yukarıdaki TCP soket yöntemiyle denendi.
  Bu sonuç UDP/DNS/IPv6 veya açılış penceresi için paket düzeyinde sızıntı kanıtı değildir;
  sorun olursa `aurasplit.exe recover`.
- DNS güvencesi yalnızca listelenen Discord alan adları içindir; Discord'un başka
  alan adlarına (ör. üçüncü taraf CDN'ler) yaptığı sorgular yerel DNS'i kullanabilir.

## Gizlilik

- Telemetri yok, analiz yok, hiçbir veri toplanmaz veya gönderilmez.
- Anahtarlar yalnızca bu bilgisayarda, yalnızca `SYSTEM` ve `Administrators` erişimine
  açık bir dosyada (ACL) saklanır. Özel anahtar loglanmaz ve ekrana basılmaz.
- Cloudflare WARP kaydında yalnızca açık anahtar Cloudflare'e gönderilir.
- Günlük varsayılan olarak `warn` düzeyindedir ve gezinme geçmişi (normal bağlantılar,
  DNS sorguları) içermez. Yalnızca başarısız bir DNS sorgusu veya bağlantı hatası bir
  alan adı/IP içerebilir. Her bağlantıyı yazan ayrıntılı günlük yalnızca
  `run --debug` ile, ön planda ve yalnızca konsola yazılır.
- Hata bildirirken günlükteki kullanıcı adlarını (ör. `C:\Users\<ad>\...`) ve
  paylaşmak istemediğiniz adresleri gizleyin.
- Ayrıntılar: [SECURITY.md](SECURITY.md)

## Hukuki not

Bu aracı kullanırken bulunduğunuz yerin yasalarına ve kullandığınız VPN sağlayıcısının
kullanım koşullarına uymak sizin sorumluluğunuzdadır.

Bu proje Discord, Cloudflare veya Proton ile **bağlantılı değildir**, bu şirketler
tarafından onaylanmamış veya desteklenmemektedir. Discord, Cloudflare, WARP, Proton ve
Proton VPN adları ilgili sahiplerinin ticari markalarıdır. WireGuard, Jason A. Donenfeld'in
tescilli ticari markasıdır.

## Kaynaktan derleme

`aurasplit.exe` için gereken tek araç [Go](https://go.dev/dl/) (`go.mod` içindeki
sürüm; tekrar üretilebilir derleme için aynı sürüm kullanılmalıdır).

```powershell
git clone https://github.com/umut720s/aura-split-tr.git
cd aura-split-tr
powershell -ExecutionPolicy Bypass -File .\build.ps1 -Version 0.1.0-beta -Strict
```

MSI paketi için ayrıca WiX Toolset **5.0.2** (.NET global aracı) ve
`WixToolset.Util.wixext` 5.0.2 gerekir (`-NoMsi` ile yalnızca exe derlenir):

```powershell
dotnet tool install --global wix --version 5.0.2
wix extension add -g WixToolset.Util.wixext/5.0.2
```

Çıktı: `dist\aurasplit.exe`, `dist\AuraSplitTR-<sürüm>-x64.msi` ve `dist\SHA256SUMS.txt`.
MSI sürümü `major.minor.build` biçimindedir (`0.1.0-beta` → `0.1.0`). Derleme `-trimpath
-buildvcs=false -ldflags "-s -w -buildid="` ve `CGO_ENABLED=0` ile yapılır, sing-box
için `with_gvisor,with_wireguard,with_external_windivert` etiketlerini kullanır. Aynı kaynak, aynı Go sürümü
ve aynı `-Version` değeri bayt bayt aynı `aurasplit.exe` dosyasını üretir (MSI'nin
kendisi her derlemede farklıdır; içindeki `aurasplit.exe` karşılaştırılmalıdır).
Ayrıntılar ve doğrulama adımları: [docs/BUILD.md](docs/BUILD.md).

### Sürümler (release)

- Resmî sürümler yalnızca elle başlatılan GitHub Actions iş akışı
  (`.github/workflows/release.yml`) ile etiketli kaynaktan derlenir. İş akışı
  `AuraSplitTR-<sürüm>-x64.msi`, `aurasplit-<sürüm>-windows-amd64.zip`, `aurasplit.exe`
  ve `SHA256SUMS.txt` üretir, üçü için GitHub derleme kaynağı (provenance) kanıtı
  oluşturur ve en fazla **taslak** (draft) bir sürüm açar; yayımlama her zaman elle yapılır.
- İndirdiğiniz dosyayı doğrulayın:
  ```powershell
  (Get-FileHash .\AuraSplitTR-0.1.0-beta-x64.msi -Algorithm SHA256).Hash.ToLower()   # SHA256SUMS.txt ile karşılaştırın
  gh attestation verify AuraSplitTR-0.1.0-beta-x64.msi --repo umut720s/aura-split-tr
  ```
- `aurasplit.exe` ve `.msi` şu anda **Authenticode ile imzalı değildir**: SmartScreen
  uyarı verebilir ve bazı antivirüs ürünleri dosyayı sezgisel olarak (yanlış alarm)
  işaretleyebilir. Yalnızca resmî depodan indirin ve özeti doğrulayın. İş akışında
  imzalama adımı hazırdır ama yapılandırılmadıkça **atlanır** (sahte imza üretilmez).
- Not: gömülü üst akış (upstream) **wintun** DLL'i, onu derleyenin derleme yolunu içeren
  bir PDB yolu barındırır. Bu bizim derlememizden değil, üst akıştan gelir.
- Resmî ve üçüncü taraf derlemeler, çatallar (fork) için ad değiştirme kuralı:
  [TRADEMARKS.md](TRADEMARKS.md).

## Lisans

[GPL-3.0-or-later](LICENSE) — tam metin `LICENSE` dosyasında, proje başlığı ve üst
akış atıfları [NOTICE](NOTICE) dosyasında. Proje, GPL-3.0-or-later lisanslı
[sing-box](https://github.com/SagerNet/sing-box) kütüphanesini ve diğer açık kaynak
modülleri içerir; tam liste ve lisans metinleri:
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md). Binary ayrıca ayrı lisanslı
Wintun DLL'i (Wintun Prebuilt Binaries License) gömer; WinDivert sürücüsü bu
derlemede gömülü değildir (`with_external_windivert`). Katkı: [CONTRIBUTING.md](CONTRIBUTING.md).
Bu proje sing-box projesiyle bağlantılı değildir ve onun tarafından onaylanmamıştır.

---

## English

**AURA Split TR** is a Windows service routing only Discord applications and domains
(including browsers) through WireGuard; other traffic goes direct. The beta's live-tested
target is Windows 11 x64; Windows 10 is untested.
Fail-closed covers only discovered desktop executables; **live TCP socket sampling
observed no off-TUN Discord TCP sockets** in the scenarios below. New versions have
discovery gaps; browser traffic and DNS while stopped are not covered. `stop` keeps discovered Discord apps blocked;
`disable`/`recover` removes those blocks. See [limitations](#sınırlamalar) and
[SECURITY.md](SECURITY.md) for scope and remaining risks. Other VPN clients may conflict.

Live status (22 November 2026): **one Windows 11 x64 PC, IPv4-only Ethernet,
Kaspersky Plus active, unsigned beta**. Details: [live runs 1–3](docs/testing/phase3_live_results_2026-11-22.md).
**Not production-ready**; public release is the maintainer's decision.

| Category | Result / method |
|---|---|
| **Observed — Discord** | Proton, WARP and generic WireGuard (a Proton `.conf` used for the generic option): established Discord TCP sockets sampled with `Get-NetTCPConnection` had TUN local address `172.19.0.1`. Voice joined successfully (user-observed); UDP tunnel path inferred, not packet-captured. |
| **Observed — fail-closed** | Per-second socket sampling during `stop` (25 s), forced crash (`taskkill`, ~4–5 s until SCM restart), and ~40 s physical network outage: **0 Discord TCP sockets outside the TUN**. Socket-level observation, not packet capture; UDP and DNS were not captured. |
| **Observed — reboot** | Service enabled: service/tunnel up ~12 s after boot; Discord TCP via TUN after the user opened it. No boot-window leak capture. |
| **Observed — lifecycle/config** | `disable`/`start`, MSI install/upgrade/uninstall passed. After uninstall: 0 AURA provider filters/sublayer in `netsh wfp show filters/state`; IP addresses, DNS servers and routes identical to pre-install capture; `%ProgramData%\AuraSplitTR` (private key) removed. Invalid config rejected without changing the running profile, WFP policy or Discord TUN routing. |
| **Not yet tested** | Packet-capture leaks (DNS/IPv6/UDP, boot window, browser/ECH); forced-failure MSI uninstall/upgrade rollback; CPU measurement; native IPv6 hosts; other AV products; more than one machine. |
| **Implemented, not live-tested** | Post-run-3 configurator file picker, `VPN_CONNECTING` start-up grace and network-change probe. Run 3's status missed the ~40 s outage. |

Live-test fixes:

- WireGuard bind on an IPv6-less host: connection path fixed and re-verified live.
- Browser IPv6 outage: host-aware TUN/DNS configuration fixed and re-verified live.
- WARP host-name endpoint handshake: IP resolution fixed and re-verified live.
- AV hold on self-install: moved to MSI; no AV alert/start-up hold observed in MSI runs on the same PC.

Install and configure:

1. Download the MSI and `SHA256SUMS.txt` from the same release's **Assets** on
   [GitHub Releases](https://github.com/umut720s/aura-split-tr/releases).
   Run `(Get-FileHash .\AuraSplitTR-0.1.0-beta-x64.msi -Algorithm SHA256).Hash.ToLower()`
   in PowerShell and compare it with the MSI line in `SHA256SUMS.txt`; do not install if different.
2. Run the MSI and accept UAC. Nothing is blocked until configuration; the service stays stopped/manual.
3. Prepare your provider:
   - **WARP:** free, no account or config download; registration is automatic.
     Read and accept Cloudflare's terms in the wizard.
   - **Proton Free/Plus:** sign in at [account.protonvpn.com](https://account.protonvpn.com)
     → **Downloads → WireGuard configuration**. Choose **Windows**, **NetShield Off**
     (or **Block malware only**), **Moderate NAT Off**, **NAT-PMP / port forwarding Off**.
     VPN Accelerator may stay on. Pick a nearby server outside Turkey (Free: free servers only),
     create and download the `.conf`. **It contains your PRIVATE KEY.** Disconnect the Proton VPN app.
   - **Other WireGuard:** standard `.conf` with exactly one `[Peer]`; `PostUp`/`PostDown` scripts are ignored.
4. Open **Start Menu → "AURA Split TR - Yapılandır"**, accept UAC and choose the provider.
   For Proton/other, select the `.conf` in the file picker. Alternatively, use "Copy as path" and paste the path; quotes are fine.
5. After the wizard says the service is running, fully quit Discord from the tray and reopen it.
6. Delete the `.conf` afterwards (including the Recycle Bin), or keep it private. **NEVER put it in a
   git repository, issue, shared screenshot or log.** The app stores the private key only in
   `%ProgramData%\AuraSplitTR\profile.json` (admins/SYSTEM only); the downloaded `.conf` remains
   a separate copy until deleted. Run the configurator again to change providers.

Troubleshooting (commands in an admin PowerShell):

| Task / problem | Action |
|---|---|
| Status | `& "C:\Program Files\AuraSplitTR\aurasplit.exe" status` |
| Logs | `%ProgramData%\AuraSplitTR\service.log` (admins; rotated `.1` / `.2`) |
| Service stuck starting | Check antivirus history. Do not disable AV or add exclusions; report false positives to the vendor and project. Signed builds are planned. |
| Discord blocked | `& "C:\Program Files\AuraSplitTR\aurasplit.exe" disable` or `& "C:\Program Files\AuraSplitTR\aurasplit.exe" recover` restores direct access. |
| Uninstall | Windows Settings → Apps → Installed apps → AURA Split TR → Uninstall |

Coming from the old self-installing build: run its `aurasplit.exe uninstall` first.

Upgrade/repair with the MSI; rollback is the designed failure behaviour, but forced
uninstall/upgrade failures, repair and missing-EXE error paths have not been live-tested.
Install, upgrade and uninstall passed live. A configured service restarts only if its
persistent policy is still enabled. If the EXE is missing, restore it or repair with the
same-version MSI before uninstalling; failed recovery rolls uninstall back. Uninstall
removes the profile/key and logs only from a trusted data folder; unexpected contents
are left for private manual inspection. Details: [removal](#kaldırma).

No telemetry. Logs default to `warn`; failed lookups/connections may include hostnames.
Redact personal data before sharing logs.

**v0.1.0-beta binaries (exe and MSI) are NOT Authenticode-signed.** Windows
SmartScreen and antivirus products may warn. Verify each file's SHA-256 against
`SHA256SUMS.txt` from the same release and verify the GitHub build provenance
attestation with `gh attestation verify <file> -R umut720s/aura-split-tr`
(replace `<file>` with the downloaded file's path). Do not run a file if verification
fails. **Never disable antivirus or add exclusions.** Report false positives to the
AV vendor. Authenticode signing is planned for a later release.

Build/checksum/provenance details: [docs/BUILD.md](docs/BUILD.md).
GPL-3.0-or-later: [LICENSE](LICENSE), [NOTICE](NOTICE), [third-party licenses](THIRD_PARTY_LICENSES.md).
Provider terms and local law remain your responsibility. Not affiliated with Discord,
Cloudflare or Proton; names belong to their owners. Fork naming: [TRADEMARKS.md](TRADEMARKS.md).
