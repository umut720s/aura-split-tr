# AURA Split TR — Mimari

Windows için yalnızca Discord trafiğini (uygulama + güncelleyici) bir WireGuard
VPN tünelinden geçiren, arka planda Windows hizmeti olarak çalışan araç.

## P0 hazır olma sözleşmesi

`SERVICE_RUNNING`, `TUNNEL_INITIALIZED`, VPN probe ve `PROTECTION_READY` bağımsızdır.
Hazır olmak için başarılı Apply, manifest ve tutulan kapsamın dört ALE katmanında
commit sonrası readback, eksiksiz discovery/enrollment, tüm manifesti kapsayan tek
dinamik izin ve eski akış kapısı gerekir. LUID bulunamaması başarısızdır. İlk Apply
hatası mevcut blokları kaldırmaz; pending + 10 sn retry ve açık neden raporlanır.
Her uzlaştırmada değişmeyen manifest için de readback yapılır. Readback mevcut
deterministik anahtar, katman, action, persistent/disabled ve kayıtlı yolu denetler;
tüm native koşul/weight/AppID içerik drift denetimi P1-C olarak açıktır.

`internal/oldflow`, politika readback sonrasında her manifest yolu için başlangıç
zamanı eşiği tutar. Eşikten önce başlamış tam manifest süreçleri kapanana kadar
kapı bekler. TCP tablosu değişikliği veya otomatik süreç kapatma yoktur. Kimliği ya
da başlangıcı okunamayan olası Discord süreçleri, çocukları ve daha önce ilgili
gözlenen kimlikler çözülene veya envanterden kaybolana kadar bekleme nedenidir.
İlgi geçmişi `(PID, oluşturulma zamanı)` ile tutulur; doğrulanmış yeni süreç eski
PID'nin ilgisini devralmaz. Görüntüsü okunamayan, eşikten önce başlayan (veya
başlangıcı okunamayan) ve ebeveyn zinciri bilinmeyen yabancı süreçler de bekletir;
durum engelleyen PID/adı gösterir. Bu belirsizlik her snapshot'ta yeniden değerlendirilir.
Discord'u tamamen kapatıp yeniden başlatmak ilgili süreçleri emekliye ayırır.
İlgisiz erişilemeyen bir orphan da bekletebilir; bu durumda belirtilen sürecin
kimliği çözülmeli veya süreç kapanmalıdır. Oluşturulma zamanı hiç okunamıyorsa
iki snapshot arasındaki gizli çıkış/PID yeniden kullanımı ayırt edilemez.
Bu kapı bilinmeyen okunabilir özel EXE'leri, launch yarışını veya örnekleme
arasındaki ebeveyn değişimini bütünüyle çözmez; paket izolasyonu kanıtı değildir.
Eşik her kesintisiz doğrulanmış enrollment nesline aittir. Yolun emekliye
ayrılması/prune veya discovery/Apply/readback kaybı eşikleri iptal eder; Apply
onarımından önce de eski kapsam okunur. Recover/servis yeniden başlatma yeni kapı
kurar. Yeniden kaydedilen yol yeni eşik alır. Poll arası kaybolup geri yüklenen,
hiç gözlenmeyen politika değişimi bu örneklemeyle tespit edilemez.
Etkileşimli setup/start yalnızca açık `[y/N]` onayından sonra tam manifest yolunu
aynı process handle üzerinden tekrar okuyup TerminateProcess uygular; klasör
üyeliği ve ebeveyn ilişkisi kapatma yetkisi vermez. Her servis oturumu yeni kapı
kurar. Bu yol eşliği yayıncı/imza veya paket sahipliği doğrulaması değildir.
Süreç örneklemesi launch bariyeri veya paket izolasyonu kanıtı değildir.

Executable sözleşmesinin tek kaynağı `internal/manifest` paketidir. Dört destekli
kök, bilinen göreli yardımcı yollar ve destekli konumlardaki kurucular discovery,
engine regex ve durum sınıflarında kullanılır. `manifest --json` ve üretilen
`tools/leaktest/executable_manifest.json` aynı JSON'dur; eşlik testi drift'i reddeder.

Desktop, updater, helpers, installers, routing fallbacks, browser Discord ve DNS
ayrı raporlanır. `protected` yalnızca hazır manifest yollarını ifade eder; browser ve
DNS best-effort / not-covered kalır. Genel izolasyon release kapısı kapalıdır.
Kanonik olmayan eski kalıcı bloklar korunabilir; tünel permitleri yalnızca
engine'in kanonik manifest regex'ine uyan yolları kapsar. Daraltılan eski permit
yeni izin açılamasa da kapatılır; kapatma hatası hazır duruma geçişi engeller.

## Akış

0. **Kurulum (Windows Installer):** kullanıcı `AuraSplitTR-<sürüm>-x64.msi` paketini kurar
   (`installer/AuraSplitTR.wxs`, WiX 5, per-machine, x64). Windows Installer
   `%ProgramFiles%\AuraSplitTR` klasörünü `InstallSDDL` tanımlayıcısıyla oluşturur
   (`MsiLockPermissionsEx`), `aurasplit.exe` ve lisans dosyalarını kopyalar, `AuraSplitTR`
   hizmetini kaydeder (LocalSystem, kendi süreci, **El ile** başlatma, `BFE` bağımlılığı,
   komut satırı `"<INSTALLFOLDER>aurasplit.exe" service`, hata eylemleri: 5 sn sonra yeniden
   başlat ×3, sayaç 1 günde sıfırlanır), olay günlüğü kaynağını yazar ve Başlat menüsüne
   "AURA Split TR - Yapılandır" (`aurasplit.exe setup`) kısayolunu ekler. Hizmeti
   **başlatmaz**: yapılandırılmamış bir hizmet açılışta Discord'u engellememelidir.
   `aurasplit.exe` kendini kopyalamaz ve hizmet oluşturmaz/silmez.
1. Kullanıcı Başlat menüsünden "Yapılandır" (`setup`) çalıştırır; `setup` önce, yönetici
   izni istemeden, kurulu kopyadan çalıştığını **dosya kimliğiyle** doğrular (değilse MSI'yi
   kurmasını söyleyip çıkar), sonra UAC ile yükselir. Sihirbaz sağlayıcı seçtirir:
   - **Cloudflare WARP (ücretsiz)** — cihazda anahtar çifti üretilir, Cloudflare
     WARP kayıt API'sine yalnızca açık anahtar gönderilir.
   - **Proton VPN (Free veya Plus)** — kullanıcı Proton hesabından indirdiği
     WireGuard `.conf` dosyasını verir.
   - **Diğer WireGuard** — herhangi bir standart `.conf`.
2. Profil `%ProgramData%\AuraSplitTR\profile.json` dosyasına yazılır
   (ACL: yalnızca SYSTEM + Administrators; özel anahtar içerir).
3. Discord engelleme kuralları (WFP) uygulanır, hizmet **otomatik** başlatmaya alınır
   (`SetAutoStart(true)`; ayrıca "çökme dışı hatalarda da kurtarma" bayrağı
   `EnableNonCrashRecovery` ile yazılır — WiX 5 util bunu ayarlayamaz) ve başlatılır.
   `setup` hizmetin 30 sn içinde `RUNNING` olduğunu denetler; `START_PENDING`'de kalırsa
   (`service.ErrStartPending`: süreç oluşturuldu ama hizmet dağıtıcısına ulaşmadı — ör.
   antivirüs yeni süreci bekletiyor) bunu ve nasıl kontrol edileceğini açıkça yazar ve
   sıfırdan farklı kodla çıkar. Hizmetin penceresi yoktur.
4. Hizmet, gömülü **sing-box** kütüphanesiyle bir TUN arayüzü açar.
   Yönlendirme kuralları:
   - Tek executable manifestinin ürettiği tam yol regex'iyle eşleşen süreçler
     → `wg` (WireGuard) çıkışı. Varsayılan dört Discord EXE adı ve
     `Discord\w*Setup*.exe` kurucu regex'i (Downloads dahil) ayrıca yönlendirme
     fallback'idir: tünel kipinde `wg`, block kipinde `reject`. Manifest dışında
     `routed-not-fail-closed` olarak raporlanır; doğrulanmış koruma sayılmaz.
     Kullanıcının `ExtraProcessNames` kuralları ayrıca → `wg`.
   - Discord alan adlarının tümü (`discord.com`, `discord.gg`, `discordapp.com/.net`,
     `discord.media`, `discordcdn.com`, `discordsays.com`, `dis.gd`, `discord.gift`,
     `discord.dev`, ... ve tam ad `discord-attachments-uploads-prd.storage.googleapis.com`)
     **her süreçten** (tarayıcılar dahil) → `wg`. `TunnelBrowserDiscord` profil alanı
     uyumluluk için durur ama artık etkisizdir.
   - Diğer her şey → `direct`. Yerel ağ (RFC1918, link-local, multicast) TUN dışında.
   - Listelenen Discord alan adlarının ve Discord süreçlerinin DNS sorguları tünel
     üzerinden (tünel içi UDP DNS: profil DNS'i ya da 1.1.1.1) çözülür; diğerleri
     yerel DNS. `dns.reverse_mapping` açıktır.
5. Tünel başlatılamazsa (ör. açılışta ağ yok) hizmet aynı TUN ile **engelleme
   yapılandırmasını** (Discord kuralları `reject`) çalıştırır ve tüneli artan
   aralıklarla (10 sn → 60 sn) yeniden dener. Her denemede, engelleme hâlâ
   çalışırken önce WireGuard sunucu adı çözülür (çözülemiyorsa engelleme sürer,
   hiçbir şey kapatılmaz) ve yeni tünel örneği oluşturulur (`box.New`: aygıt açmaz).
   Ancak bundan sonra engelleme kapatılıp hazırlanan tünel başlatılır. İki TUN aynı
   anda çalıştırılamaz (aynı arayüz adı, yollar ve strict-route filtreleri); bu
   aralıkta ve engelleme de başlatılamadığında (TUN açılamıyorsa) bulunan Discord
   programları kalıcı WFP kurallarıyla engelli kalır (aşağıda "Kalıcı fail-closed").
   Hizmet 10 sn sonra yeniden dener.
   - **Uç nokta adı (`engine/config.go` `resolveNetEnv`):** tünel yapılandırması
     kurulmadan hemen önce WireGuard sunucu adı sistem çözücüsüyle (tünel dışında)
     çözülür (IPv4 tercih edilir; ana makinede IPv6 yoksa yalnızca IPv4) ve yapılandırmaya
     **yalnızca IP** yazılır (Hata 3: adla sing-box bağlanmamış dinleme soketi yoluna
     geçiyor, el sıkışma olmuyordu). Ad çözülemezse yapılandırma **kurulmaz**
     (`ErrEndpointUnresolved`): bu bir hazırlama hatasıdır, engelleme yapılandırması
     Discord'u engelli tutar ve yukarıdaki yeniden deneme sürer. Yalnızca `Check`
     (`setup` doğrulaması; başlatılmaz) çözülemeyen adı yapılandırmada bırakır.
   - **Yeniden kurma (`engine.go` `serve`):** çalışan tünel, bağlantı denetimi
     `VPN_DISCONNECTED` (art arda ≥ 3 başarısız deneme) bildirdiğinde **veya** ana makinenin
     IPv6 yeteneği (60 sn'de bir denetlenir) yapılandırmanın kurulduğu değerden farklı
     olduğunda yeniden kurulur: yeni yapılandırma, ad yeniden çözülür. En fazla **2 dk'da
     bir deneme** (`minRebuildInterval`). Yeni örnek eski tünel çalışırken hazırlanır;
     hazırlama başarısızsa (ör. ad çözülemiyor) eski tünel kalır ve sonraki denemede
     yeniden denenir. Başarılıysa: deneme ve IPv6 izleyicisi durur → Discord tünel izni
     kapatılır → eski tünel kapatılır (kapanma zaman aşımı terminaldir) → durum
     `starting` ("rebuilding the tunnel") → yeni tünel başlatılır → yeni izin. Aradaki
     boşlukta kalıcı WFP politikası Discord'u engeller; başlatma başarısızsa engelleme
     yapılandırmasına geçilir. Sahte örneklerle birim testli; gerçek ağ değişikliğiyle
     **NOT TESTED**.
   - **Ana makine IPv6 yeteneği (`engine/hostipv6*.go`):** arayüz adreslerini taramak
     yerine IP yardımcı tabloları okunur (`GetUnicastIpAddressTable`,
     `GetIpForwardTable2`, `GetIfEntry2Ex`, `GetIpInterfaceEntry`; salt okuma).
     Önce sabitlenmiş sing-tun Windows izleyicisi gibi IPv4 `0.0.0.0/0` rotaları
     arasından açık, bağlı, sanal TUN/loopback olmayan arabirim seçilir: rota metriği
     + IPv4 arabirim metriği en küçük olan kazanır, eşitlikte ilk kayıt korunur.
     Yetenek yalnızca **bu seçili çıkış** arayüzü
     hem *up*, geri döngü değil, AURA TUN'u değil, hem tercih edilen (DAD *preferred*) global
     tek noktaya yayın IPv6 adresine (ULA `fc00::/7`, link-local, Teredo `2001::/32`, 6to4
     `2002::/16` hariç) **hem de** `::/0` varsayılan IPv6 yoluna sahipse doğrudur. Bir sanal
     bağdaştırıcıdaki adres + başka arayüzdeki yol yetmez; başka açık adaptörde adres
     ve varsayılan IPv6 yolu birlikte bulunsa bile yetmez. Tablolar okunamazsa yetenek
     "yok" sayılır (TUN'a IPv6 verilmez, AAAA yanıtları boş). Windows dışı derlemede saplama
     her zaman `false` döner. Karar mantığı sahte tablolarla birim testlidir.
6. Hizmet tünel durumunu `%ProgramData%\AuraSplitTR\tunnel-state.json` dosyasına
   (ayrı bir yazıcı goroutine'i ile, motoru diske bekletmeden; değişiklikler birleştirilir)
   yazar: `starting` (hizmet başlarken), `tunnel-started`, `blocking`, `error`,
   `stopped`; ayrıca süreç kimliği (PID), süreç başlangıç zamanı ve çalışırken her
   30 sn yenilenen bir `heartbeat` zamanı. `status` kaydı yalnızca SCM hizmeti
   *çalışıyor* gösteriyorsa, PID SCM'nin bildirdiği PID ile (QueryServiceStatusEx)
   ve süreç başlangıç zamanıyla eşleşiyorsa ve heartbeat 90 sn'den yeniyse gösterir;
   aksi halde "bilinmiyor" der. Durum yazılamazsa günlüğe uyarı düşülür.
   `tunnel-started` "tünel başlatıldı" demektir (yapılandırma uygulandı), "doğrulandı"
   değil: sing-box v1.14.4 WireGuard el sıkışma zamanını dışa açmaz. Bağlantı ayrıca
   tünelin içinden denenir (aşağıda "Bağlantı denetimi").

## Kalıcı fail-closed (WFP, `internal/wfp`)

**Durum: uygulandı, birim testli (sahte arka uç + WFP çağırmayan yapı/marshalling testleri +
gerçek `FindFirstChangeNotification` testi geçici klasörde); gerçek WFP çağrıları TEST EDİLMEDİ.**

| Nesne | Anahtar / değer |
|---|---|
| Sağlayıcı (kalıcı, `serviceName` boş) | `4699124e-3633-487f-90c5-77e86738322c` ("AURA Split TR") |
| Alt katman (kalıcı) | `58005a25-e04f-4367-9093-bbaeca5dd4f3`, ağırlık `0xF000` (sing-tun'un `0xFFFF` dinamik alt katmanının altında; eşit olamaz) |
| Katmanlar | `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6`, `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6` |
| Kalıcı filtre, ağırlık 15 | PERMIT: `ALE_APP_ID == <program>` ve `FWPM_CONDITION_FLAGS` ⊇ `FWP_CONDITION_FLAG_IS_LOOPBACK` |
| Kalıcı filtre, ağırlık 1 | BLOCK: `ALE_APP_ID == <program>` |
| Dinamik filtre, ağırlık 10 | PERMIT: `ALE_APP_ID == <program>` ve `FWPM_CONDITION_IP_LOCAL_INTERFACE == <TUN LUID>`; `FWPM_SESSION_FLAG_DYNAMIC` oturumunda, yalnızca normal tünel başladıktan sonra |

- Aynı alt katmanda en yüksek ağırlıklı eşleşen filtre karar verir: loopback izni >
  tünel izni > engel. sing-tun'un TUN izni (11) "yumuşak" izin olduğu için alt
  katmanımızdaki engel TUN dışında yine geçerlidir.
- `ALE_APP_ID` `FWP_MATCH_EQUAL` ile eşlenir. `FWP_MATCH_PREFIX`'in bu koşul (bayt
  dizisi) için desteklendiği belgelenmemiştir; bu yüzden her program tam yolla listelenir.
- Kalıcı filtre anahtarları `SHA-256("aurasplit-wfp-v1|" + tür + "|" + katman + "|" + appID)`
  türetilmiş GUID'lerdir; her kalıcı filtre program yolunu `providerData` (UTF-8) olarak
  taşır. Uzlaştırma = sağlayıcıya göre listelenen filtrelerle küme farkı; listeleme
  (devre dışı filtreler dahil, `FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED`; BFE bayrağı
  reddederse bayraksız tekrar) ve fark **aynı okuma-yazma işleminin (transaction) içinde**
  yapılır. Değişiklik yoksa işlem iptal edilir (abort). Dinamik filtrelere anahtarı BFE verir.
  `FWPM_FILTER_FLAG_DISABLED` (`0x20`) `FilterRecord.Disabled` olarak korunur: devre dışı
  filtre "var" sayılmaz; anahtarı istenen bir filtreyse aynı işlemde silinip yeniden
  eklenir (anahtarı olan filtreyi eklemek etkisizdir), tutulan (istenmeyen ama programı
  var olan) devre dışı filtre kayıtlı yolundan yeniden oluşturulur (yol çözülemezse
  "çözülmemiş"). Devre dışı filtreler `Covered`/`Installed` sayısına girmez.
- **Politika bütçesi:** mevcut + önerilen kalıcı politika en fazla `MaxPolicyApps` = 1024
  program, profil başına (`\AppData\Local\` öncesi yol) `MaxPolicyAppsPerProfile` = 128.
  Önce kalan her mevcut engel sayılır (bütçeyi aşsa bile; yer açmak için hiçbir şey
  silinmez), sonra yeni programlar bütçe izin verdikçe eklenir; kalanlar
  `ApplyResult.OverBudget` / `IncompleteError.OverBudget` ile bildirilir, geçiş eksik
  sayılır. Dinamik izin (`PermitOnTunnel`) aynı bütçeyi uygular. Bulma da profil başına
  128 yolda durur (`ErrCapReached`, diğer profiller etkilenmez).
- **Silme kuralı (`Apply(yollar, kip)`):** `AddOnly` hiçbir filtre silmez. `Authoritative`
  yalnızca (a) tarama hatasız bittiyse (sınır aşımı yok, her klasör okunabildi) ve (b) her
  yolun uygulama kimliği okunabildiyse siler; (c) kaydedilmiş yolu diskte hâlâ var olan
  (ya da varlığı denetlenemeyen) bir filtre **asla** silinmez. Kimliği okunamayan ama var
  olan yol "çözülmemiş" sayılır: geçiş `AddOnly`'ye düşer, `*IncompleteError` döner,
  mevcut filtreleri korunur. Dosya artık yoksa "eksik" değil "gitmiş" sayılır. Sonuç
  (`ApplyResult.Covered`) istenen ve çözülen yollar ile tutulan her filtrenin kayıtlı
  yoludur; bu, önceki süreçten WFP'de kalan kurallar dahil **başlangıç kümesidir
  (baseline)**: yeni bir `Guard`'ın ilk uzlaştırması eksik taramayla bunları küçültemez ve
  tünel izni bunları da kapsar.
- Program bulma: `HKLM\...\ProfileList` (yalnızca `S-1-5-21-*` ve `S-1-12-1-*`; okunamayan
  kullanıcı girdisi hata sayılır), her profilde
  `AppData\Local\{Discord,DiscordPTB,DiscordCanary,DiscordDevelopment}\Update.exe` ve
  dört destekli kurulum kökündeki ve SquirrelTemp içindeki `Discord*Setup*.exe`, her
  `app-*` içindeki bilinen istemci/yardımcı EXE'ler ve manifestte belirtilen
  discord_utils/DiscordSystemHelper, discord_voice/audio_effects_helper ve
  gpu_encoder_helper göreli yolları. Yol bileşenleri reparse point olamaz. Sınırlar: 64 profil,
  16 exe/klasör, modül seviyesi başına 64 giriş, kök listelemelerinde 4096 giriş,
  profil başına 128, toplam 1024 yol; sınır/okuma hatası `ErrCapReached`/incomplete
  üretir. Derin veya özel konumlar, Temp child launch kapsamı dışarıdadır.
- Uzlaştırma tetikleri: hizmet başında; her Discord kurulum klasörü (alt ağaç) ve her
  profilin `AppData\Local` klasörü (yalnızca doğrudan alt klasörler: yeni kurulum)
  `FindFirstChangeNotification` ile izlenir, değişiklikten 300 ms sonra uzlaştırılır
  (izleme hedefleri değişiklikten 1 sn sonra ve 60 sn'de bir yeniden okunur); 60 sn'lik
  periyodik tarama yedektir. Açılamayan, yeniden kurulamayan (`FindNextChangeNotification`)
  ya da beklemesi başarısız olan her hedef hemen bir kanal üzerinden bildirilir ve günlüğe
  yazılır; izleyici, hedef listesi değişmese de izlemeleri 1 sn'den 60 sn'ye ikiye katlanan
  aralıklarla yeniden kurar (son yeniden kurulumdan 60 sn sonra gelen hata sayacı sıfırlar)
  ve ardından bir uzlaştırma tetikler; işletim sistemi izleyicisi kendiliğinden biterse
  (tüm bekleme grupları bitti) bu da hata sayılır. Koruma eksikken (tarama hatası, çözülmemiş program, izin
  eksik/başarısız veya eski akış kapısı bekliyor) 10 sn'de bir. Değişmeyen envanterde de
  Apply/readback tekrarlanır; çözülmemiş programlar ve başarısız izinler yeniden denenir.
- **Kalan güncelleme yarışı (mimari sınır):** kurallar tam yola bağlıdır; gelecekteki bir
  sürüm ilk bağlantısından önce garanti olarak kapsanamaz. (1) Yeni `app-*` sürümü
  izleyicinin uzlaştırması bitmeden (~1 sn) çalışır **ve** aynı anda tünel/hizmet
  çalışmıyorsa doğrudan çıkabilir (hizmet çalışırken sing-box süreç yolu kuralıyla onu
  tünele yönlendirir). (2) Hizmet durmuşken hazırlanmış bir sürüm hizmet yeniden başlayıp
  tarayana kadar kapsanmaz; hizmet dururken `Update.exe` engelli olduğundan güncelleyici bu
  sırada indirme yapamaz, ancak el ile kopyalanan ya da durdurmadan hemen önce inen bir
  sürüm bu pencereye girer. Fail-closed yalnızca bulunan envanteri kapsar; `status` bunu
  "Kapsam" satırında gösterir.
- Tünel izni engel envanterinden ayrı izlenir (`permitDirty`): küme büyürken önce yeni
  dinamik izin oturumu (yeni ∪ eski kapsam) açılır, sonra kalıcı küme uygulanır, ardından
  izin engellenen kümeye (`Covered`) göre yeniden eşitlenir. Eski bir oturum yalnızca
  diğer açık oturumlar onun izin verdiği ve hâlâ kümede olan her yolu kapsıyorsa kapatılır:
  eksik bir yenisi (ör. A'nın uygulama kimliği geçici olarak okunamadı) eski oturumu
  kapatmaz, ikisi birlikte kalır. En fazla `MaxPermitSessions` = 2 oturum; hiçbir eskiyi
  emekliye ayıramayan yeni bir oturum bu sınırı aşacaksa yeni oturum kapatılır (yeni
  programlar engelli kalır). Tek ve tam bir oturum dışındaki her durum "izin eksik"tir ve
  yeniden denenir. İzin açılamazsa eski izin kalır, durum
  "izin eksik" olur ve yol değişmese de yeniden denenir; `status` izni yalnızca kapsadığı
  programlar için "açık" gösterir (`PermitApps`/`PermitComplete`).
- Eşzamanlılık: süreç içinde her yazma işlemi (`Apply`, `PermitOnTunnel`, `RemoveAll`)
  bir paket kilidiyle sıralanır. Süreçler arası (hizmet ↔ CLI) sıralamayı BFE'nin
  okuma-yazma işlemleri sağlar (oturumlar arası özel; bekleme sınırı 10 sn) ve politikayı
  kaldıran komutlar (`disable`, `recover`, MSI kaldırmasındaki `recover --msi`) önce hizmeti devre dışı bırakıp
  durdurur. CLI komutlarının kendi aralarında (ör. iki eşzamanlı `setup`) ayrıca kilidi
  yoktur; her biri tek işlemde atomiktir.
- WFP bağlamaları türlüdür: her işaretçi `LazyProc.Call` (`//go:uintptrescapes`) ifadesinin
  içinde `uintptr`'a çevrilir; prosedürler bir kez (`sync.Once`) bulunur. BFE'nin yapı
  alanları üzerinden okuduğu Go belleği (FWP_VALUE0 birlikleri, bloblar, koşul dizileri,
  görünen adlar, `providerData`) çağrı süresince `runtime.Pinner` ile sabitlenir ve
  ardından bırakılır. Yapı kurucuları WFP çağırmadan birim testlidir.
- Sıra (hizmet): veri klasörü → günlük → kalıcı politika (`Apply`) → motor →
  tünel başladı → TUN LUID (`ConvertInterfaceAliasToLuid("AuraSplitTR")`) → dinamik izin →
  `tunnel-started`. Kapanış: deneme durdurulur → izin kapatılır → sing-box kapatılır
  (en fazla 10 sn) → politika döngüsü durur → son durum yazılır → durum yazıcısı
  beklenir → günlük kapatılır. İstenen bir durdurmada SCM bekleme süresi (18 sn) aşılırsa
  hizmet zaman aşımını olay günlüğüne yazar ama çıkış kodu **0** bildirir: sıfırdan farklı
  kod SCM hata eylemlerini (5 sn sonra yeniden başlatma) tetiklerdi, ör. `disable`
  politikayı kaldırdıktan sonra. (Ayrıca `disable`/`recover` durdurmadan önce
  başlangıç türünü Disabled yapar; devre dışı hizmeti SCM, kurtarma eylemiyle de
  başlatamaz.) Fail-closed bu temizliğe bağlı değildir: kalıcı filtreler kalır, dinamik
  izin süreçle ölür.
- Kapanma zaman aşımı terminaldir: bir sing-box örneği 10 sn içinde kapanmazsa
  (`engine.ErrCloseTimeout`) aynı süreçte yeni örnek başlatılmaz (eski örnek TUN'u, yolları
  ve strict-route filtrelerini hâlâ tutuyor olabilir; hazırlanmış örnek yalnızca kapatılır).
  `Run` `StateError` bildirip döner, `serviceRun` bunu `service.ErrFatal` ile sarar, gözetici
  yeniden denemez, hizmet sıfırdan farklı kodla durur ve SCM kurtarma eylemi temiz bir
  süreçte yeniden başlatır; arada kalıcı engeller Discord'u fail-closed tutar.
- Engelleme modunda (tünel başlatılamadı) ve yeniden deneme aralığında izin yoktur.
  İzin açılamazsa tünel kapatılır ve başlatma hatası gibi engelleme moduna geçilir.
- Hizmet `BFE` hizmetine bağımlıdır (MSI yazar; `setup` `service.Verify` ile komut satırını,
  LocalSystem hesabını, kendi-süreç türünü ve bağımlılığı geri okuyarak doğrular).
- Profil geçersizse hizmet çalışmaya devam eder (Discord kalıcı kurallarla engelli),
  durum `error` ve ayrıntı yazar, 60 sn sonra yeniden dener.
- `run` (ön plan) hizmet çalışıyorsa başlamaz ve aynı politika/izin akışını kullanır.

## Komutlar ve Discord'un durumu

| Komut | Hizmet | Başlangıç türü | WFP politikası | Discord |
|---|---|---|---|---|
| MSI kurulumu | kaydedilir, **başlatılmaz** | El ile | dokunulmaz | değişmez |
| `setup` | (yeniden) başlar, `RUNNING` denetlenir | otomatik | uygulanır (hizmet başlamadan önce; tarama eksikse yalnızca ekleme) | tünelden |
| MSI yükseltme / onarım | yeniden kaydedilir (El ile, durur); işlem başarıyla tamamlandıktan sonra (commit) `start --msi` yalnızca profil **ve** kalıcı politika varsa başlatır | otomatik (başlatıldıysa) | korunur | tünelden / engelli / doğrudan (öncekiyle aynı) |
| MSI yükseltme başarısız (geri alma) | eski sürümün dosyaları ve hizmet kaydı geri gelir (eski ürünün kaldırılması aynı işlemin içinde) | eski kayıt geri yüklenir (beklenen; **NOT TESTED**) | korunur | önceki gibi (hizmet yeniden çalışmazsa engelli; `aurasplit.exe start`) |
| `start` | başlar | otomatik (Disabled'dan geri alır) | hizmet uygular | tünelden |
| `stop` | durur | değişmez | kalır | **engelli** |
| `disable` (onaylı) | önce Disabled, sonra durur | **devre dışı** | kaldırılır | doğrudan |
| `recover` | önce Disabled (en iyi çaba), sonra durdurulur (en iyi çaba) | **devre dışı** | sağlayıcı anahtarıyla her durumda kaldırılır | doğrudan |
| MSI kaldırma | `recover --msi` (StopServices'ten önce), sonra MSI durdurur ve siler; ardından `uninstall --msi` veri klasörünü temizler | silinir | exe silinmeden **önce** kaldırılır; **hata → kaldırma geri alınır**, exe ve hizmet kalır | doğrudan |
| MSI kaldırma, `aurasplit.exe` yok (karantina) | dokunulmaz | değişmez | dokunulmaz | **kaldırma Türkçe hatayla durur** (`AuraExeMissing`); exe'yi geri yükleyin / aynı sürümü yeniden kurun ya da aynı sürümle `recover` |
| `uninstall` (kullanıcı) | değişmez | değişmez | değişmez | değişmez (yalnızca MSI ile kaldırmayı anlatır) |

`RemoveAll` sırası: sağlayıcının tüm filtreleri (4 katman, kalıcı ve dinamik, devre dışı
olanlar dahil; listeleme işlemin içinde) → alt katman → sağlayıcı; tek işlem, tekrarlanabilir.

## Durumlar (`status`)

Her durum ayrı satırdadır; birbirinden bağımsızdır ve aynı anda EVET olabilir.

| Durum | Anlamı | Kaynak |
|---|---|---|
| `SERVICE_RUNNING` | SCM hizmeti *çalışıyor* gösteriyor | `QueryServiceStatusEx` |
| `TUNNEL_INITIALIZED` | normal tünel yapılandırması başlatıldı (`tunnel-started`) | durum dosyası (PID + başlangıç zamanı + 90 sn heartbeat ile doğrulanmış) |
| `VPN_CONNECTING` | ilk 90 sn içinde, ilk başarıya kadar bağlanıyor; hatalar normal eşiğe sayılmaz | durum dosyası |
| `VPN_CONNECTIVITY_VERIFIED` | son deneme tünelin içinden başarılı | durum dosyası |
| `VPN_DEGRADED` | art arda 1–2 deneme başarısız, ya da WARP `warp=off` döndü | durum dosyası |
| `VPN_DISCONNECTED` | fiziksel bağlantı yok veya art arda ≥ 3 deneme başarısız | durum dosyası |
| `PERSISTENT_POLICY` | politika varlığı/sayısı; hazır olma kanıtı değildir | WFP `Installed`, olmazsa hizmetin bildirimi |
| `PROTECTION_READY` | manifest Apply/readback + pending yok + tam tünel izni + eski akış kapısı | güncel hizmet durum dosyası |
| `OLD_FLOW_GATE` | politika sonrası korunan süreç kalmadığı gözlendi | oldflow, durum dosyası |

VPN_* durumları yalnızca `TUNNEL_INITIALIZED` iken anlamlıdır; tünel durumu değişince
sıfırlanır. "Doğrulandı" asla süreç varlığından çıkarılmaz.

## Bağlantı denetimi (`internal/engine/probe.go`)

- Yalnızca `wg` uç noktası üzerinden (`box.Endpoint().Get("wg").DialContext`) TCP;
  `GET https://www.cloudflare.com/cdn-cgi/trace`, sistem kök sertifikaları, yönlendirme
  izlenmez, keep-alive yok. Ad çözümünü denetimin kendisi yapar: tek bir UDP DNS sorgusu
  (A, yoksa AAAA; rastgele kimlik; yanıt QR=1, opcode 0, RCODE 0, tam bir IN sorusu
  ad/tür eşleşmeli; yalnızca sahibi sorulan ad ya da ondan başlayan en fazla 8 halkalı
  IN CNAME zinciri olan IN A/AAAA kayıtları kabul edilir) `wg` uç
  noktası üzerinden profilin tünel içi DNS sunucusuna (yapılandırmadaki `remote`
  sunucusuyla aynı: profil DNS'i ya da 1.1.1.1) gider, ardından dönen IP'ye `wg`
  üzerinden bağlanılır. Uç noktaya ad verilseydi sing-box adı, son sunucusu yerel çözücü
  olan DNS yönlendiricisiyle çözerdi. TLS sunucu adı (SNI) ve sertifika doğrulaması URL'deki
  addan yapılır. Bir DNS kuralı eklemek yerine bu yol seçildi: kural her süreçten gelen
  `www.cloudflare.com` sorgularını da tünele yönlendirirdi. **NOT TESTED** gerçek tünelle
  (birim testi sahte DNS/TLS sunucusuyla).
- Zaman aşımı 10 sn, gövde sınırı 4 KiB; yalnızca `warp=` ve `ip=` okunur, `ip`
  yalnızca geçerli adres mi diye denetlenir, saklanmaz/günlüğe yazılmaz. Hata ayrıntısı
  adres içermeyen kısa bir nedendir (`timeout`, `tls error`, `http status N`, ...).
- WARP profilinde başarı için `warp=on` veya `warp=plus` gerekir.
- Zamanlama: tünel başladıktan 10 sn sonra ilk deneme; ilk 90 sn içinde ilk başarıya kadar hatalarda 10 sn arayla tekrar; başarıdan sonra 5 dk; hatadan
  sonra 30 sn'den başlayıp ikiye katlanarak en fazla 5 dk.
- IPv4 fiziksel varsayılan arayüz ve bağlantı durumu 10 sn arayla, ağ trafiği olmadan okunur. Değişiklikte ek deneme yapılır (en sık 10 sn). Fiziksel bağlantı yokken durum hemen `VPN_DISCONNECTED` olur ve tünel yeniden kurulmaz; bağlantı dönünce deneme yapılır.

## Dosya güveni

- `%ProgramData%\AuraSplitTR` ve `%ProgramFiles%\AuraSplitTR` yolları Known Folder
  API'sinden alınır (ortam değişkeninden değil).
- `%ProgramFiles%\AuraSplitTR` Windows Installer'a aittir: MSI onu `InstallSDDL`
  (`O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)`) ile oluşturur, dosyalar
  bu DACL'i miras alır. CLI oraya hiç yazmaz ve klasörü taramaz/karantinaya almaz;
  `setup` yalnızca okur: `IsTrustedAppDir` (gerçek klasör, sahip ve DACL güvenilir) ve
  `IsTrustedFile` (`aurasplit.exe`: gerçek dosya, tek sabit bağlantı, sahip ve DACL
  güvenilir). Uymuyorsa MSI'nin onarılmasını ister. `internal/paths` testi `.wxs` içindeki
  SDDL'in `InstallSDDL` ile aynı olduğunu denetler.
- `EnsureSecureDir` (veri klasörü): klasör yoksa `CreateDirectory` ile
  güvenlik tanımlayıcısıyla atomik oluşturulur (sahip Administrators, korumalı DACL).
  Üst klasör zincirinde reparse point olamaz. Varsa:
  - Önce yalnızca okuma haklarıyla (`READ_CONTROL`) incelenir: bağlantı (reparse
    point) olmamalı; sahip SYSTEM/Administrators/TrustedInstaller olmalı ve DACL'de
    bunlar dışında kimseye yazma/silme/`WRITE_DAC`/`WRITE_OWNER` veren bir ACE
    olmamalı. **Yalnızca-miras (inherit-only) ACE'ler de sayılır.**
  - İnceleme hatası (paylaşım ihlali, erişim reddi) güvenilmezlik kanıtı sayılmaz:
    hata döner, hiçbir şey taşınmaz veya silinmez.
  - Kanıtlanmış güvenilmez klasör **silinmez**: `AuraSplitTR.quarantine-<zaman>-<rastgele>`
    adıyla aynı üst klasöre (veri klasörü için `%ProgramData%`) taşınır, karantina
    klasörünün kendi ACL'i (en iyi çaba, gerekirse restore/take-ownership
    ayrıcalıklarıyla) SYSTEM + Administrators'a indirilir ve yeni klasör oluşturulur.
  - Güvenilir klasörde sahip + DACL yeniden yazılır, ardından her alt öğe tek tek
    incelenir (sahip **ve** DACL). Yalnızca uygulamanın adlarına dokunulur:
    veri klasöründe `profile.json`, `tunnel-state.json`, `service.log`, `service.log.N`
    ve kendi geçici dosyalarımız (`.<ad>.<16 hex>.tmp`). Güvenilir dosyanın ACL'i yerinde sıfırlanır.
    Güvenilmeyen dosyanın ACL'i yerinde **düzeltilmez** (eski tanıtıcılar yaşamaya
    devam ederdi): günlük dosyaları içerik `CREATE_NEW` ile güvenli oluşturulan yeni
    dosyaya kopyalanıp `MoveFileEx` ile değiştirilir; `profile.json` (saldırgan yazmış
    olabilir) ve `tunnel-state.json` yeniden kullanılmaz, karantinaya
    taşınır (profil için `setup` yeniden çalıştırılmalı). Bilinmeyen adlar, alt
    klasörler, bağlantılar ve birden çok sabit bağlantılı dosyalar karantinaya
    (`<klasör>.quarantine-...`) **taşınır**, silinmez. 10 dakikadan eski güvenilir
    geçici dosyalarımız silinir, daha yenileri (süren bir yazma) bırakılır.
- Klasör adında bir bağlantı (junction/symlink) veya dosya varsa (ör. kurulumdan önce
  standart bir kullanıcı oluşturmuşsa) o da `MoveFileEx` ile (bağlantının kendisi)
  karantina adına taşınır ve klasör yeniden oluşturulur. Karantinaya taşınan klasörün ACL'i
  yalnızca yeniden açılan nesne hâlâ aynı dosya kimliğine sahip gerçek bir klasörse
  değiştirilir. `profile.json` için yönetici olmayan birine **okuma** izni veren ACE de
  güvenilmezlik sayılır (anahtar sızmış olabilir): dosya karantinaya alınır, `setup`
  gerekir. `uninstall --msi` yalnızca SYSTEM/Administrators'a ait gerçek karantina
  klasörlerini "bizim" diye listeler; karantina klasörleri hiçbir kaldırmada silinmez.
- Olay günlüğüne yazılan metinden kullanıcı yolları ve satır sonları temizlenir;
  sing-box/wireguard-go günlük satırları yazıcı goroutine'inde gizli anahtarlardan
  (base64 ve hex) arındırılır.
- Günlük: hizmet `service.log` dosyasını kendisi açar (reparse point değil, bağlantı
  sayısı 1, sahip ve DACL güvenilir). sing-box bir boruya (pipe) yazar; okuyucu
  goroutine boruyu sürekli okuyup satırları 1024 girişlik sınırlı bir kuyruğa koyar,
  yazıcı goroutine kuyruğu dosyaya boşaltır. Kuyruk doluysa satır atılır ve sayılır
  ("N log lines dropped"); dosyaya yazma hataları sayılır ama boruyu okumayı
  durdurmaz. Motorun kendi iletileri de aynı engellemesiz yoldan geçer. Kapanışta
  boru yazma uçları kapatılır, okuyucu/yazıcı en fazla 2 sn beklenir, sonra dosya
  kapatılır. Dosya 2 MB'ta döndürülür, 2 yedek (`service.log.1`, `.2`); döndürme
  başarısız olursa sınır aşılmaz: satırlar atılır ve sayılır, döndürme en fazla
  30 sn'de bir yeniden denenir (`Degraded()`; `status` uyarı gösterir). Kullanıcı
  profil yolları (`C:\Users\<ad>`) günlük yazıcısında, bağımlılıkların satırları dahil,
  `C:\Users\<user>` ile değiştirilir. Varsayılan düzey `warn`; `run --debug`
  yalnızca ön planda `info` düzeyidir ve konsola yazar.
- Yapılandırma (`setup`): çalışan exe süreç başında `FILE_SHARE_READ` ile açılır ve
  eşlenen görüntüyle aynı dosya olduğu (dosya kimliği) doğrulanır; tanıtıcı açık kaldıkça
  dosya değiştirilemez. "Kurulu kopyadan çalışıyor" kararı yol metniyle değil,
  `InstalledExePath()` dosyasının var olduğu ve dosya kimliğinin (birim seri no + dosya
  indeksi; bağlantı/çok adlı dosya kabul edilmez) çalışan görüntüyle aynı olduğuyla
  verilir; aksi halde `setup` hiçbir şey değiştirmeden MSI'yi kurmayı anlatır. **Ön denetim**
  (hizmet durdurulmadan ve profile dokunulmadan, hatta sağlayıcı seçilmeden önce): bu
  karar, kurulum klasörü ve exe güveni, `service.Verify` ve veri klasörünün güvenliği.
  Yeni profil `profile.json` yanında güvenli bir geçici dosyaya yazılır; çalışan hizmet
  durdurulur ve **ancak** ondan sonra `profile.json` ile değiştirilir. Değiştirme başarısız
  olursa önceki hizmet eski profille yeniden başlatılır (en iyi çaba).
- Kaldırma tamamen Windows Installer'dadır (`installer/AuraSplitTR.wxs`). Tam kaldırma
  koşulu her yerde `REMOVE~="ALL" AND NOT UPGRADINGPRODUCTCODE` (yükseltmede eski ürünün
  kaldırılmasında hiçbiri çalışmaz):
  1. `AppSearch` `[ProgramFiles64Folder]AuraSplitTR\aurasplit.exe` dosyasını arar
     (`AURAEXEFOUND`). Yoksa (antivirüs karantinası, silinmiş) `AuraExeMissing` (tür 19,
     `InstallInitialize`'dan önce) kaldırmayı Türkçe bir hatayla durdurur: exe olmadan WFP
     politikası kaldırılamaz ve Discord engelli kalırdı. İleti: dosyayı karantinadan geri
     yükleyin ya da aynı sürümü yeniden kurun/onarın, sonra kaldırın; yalnızca engeli hemen
     kaldırmak için aynı sürümün exe'siyle `aurasplit.exe recover`, sonra kaldırın.
     Kurulu exe geri yüklenmeden kaldırma sürdürülemez; denetim atlanamaz.
  2. `AuraRecover` (ertelenmiş, `Impersonate="no"` = LocalSystem, **`Return="check"`**,
     `StopServices`'ten önce, ek koşul `AURAEXEFOUND`): `recover --msi`. Hizmeti Disabled
     yapar ve durdurur, sağlayıcının tüm WFP nesnelerini siler. Kaldırılacak bir şey
     yoksa 0 döner; politika kaldırılamazsa, hâlâ yüklü görünüyorsa ya da hizmet
     durdurulamazsa (çalışan hizmet politikayı yeniden uygulayabilirdi) sıfırdan farklı
     döner ve Windows Installer kaldırmayı **geri alır**: hizmet ve `aurasplit.exe`
     (kurtarma aracı) yerinde kalır. Önce `AuraSaveRecoverState` ertelenmiş eylemi
     `recover --msi --save-state` ile başlangıç türünü, çalışma bayrağını, WFP politika
     varlığını ve politikadaki korunan uygulama yollarını mevcut güvenli yazma yordamıyla
     sürüm 2 `recover-state.json` dosyasına kaydeder; hata olursa
     hizmet/WFP değişmez. Ardından `AuraRecoverRollback` kaydedilir (Execute=rollback,
     Impersonate=no, Return=ignore, WixQuietExec): `recover-rollback --msi` gizli komutu,
     MSI hizmeti ve dosyaları geri getirdikten sonra eski başlangıç türünü/çalışma
     bayrağını geri yükler. Yalnızca kayıtta önceden mevcut olan WFP politikasını,
     profil veya yeni keşif gerektirmeden kayıtlı yollarla add-only uygular; böylece
     kısmi kurtarmadan kalan bloklar korunur. Önceden politika yoksa oluşturmaz.
     Eski veya bilinmeyen kayıt sürümlerinde hiçbir durumu değiştirmez. Bir adımın
     hatası diğer geri yükleme girişimlerini engellemez; hatalar MSI günlüğündedir.
  3. MSI hizmeti durdurur ve siler (`ServiceControl Stop=both Remove=uninstall Wait=yes`).
  4. `AuraCleanData` (commit, LocalSystem, `Return="ignore"`, ek koşul `AURAEXEFOUND`):
     MSI'ye gömülü küçük `auraclean.exe`, `uninstall --msi` çalıştırır; kurulu exe artık silinmiş
     olsa da çalışabilir. Önce `recover` tekrar çalışır (hata → veri korunur, loglanır).
     Profil ve kurtarma kaydı commit aşamasına kadar korunur. Sonra
     `paths.CleanDataDir`: klasör bağlantı izlenmeden, `FILE_SHARE_DELETE` olmadan açılır ve
     tanıtıcı sonuna kadar tutulur (başkası klasörü yeniden adlandıramaz/silemez/
     değiştiremez); gerçek klasör, sahip ve DACL güvenilir (SY/BA/TI) ve üst zincirde
     reparse point yok olmalıdır. Girdiler bu tanıtıcıdan listelenir
     (`FILE_FULL_DIR_INFO`) ve her biri ona **göreli** açılır (`NtCreateFile`,
     `RootDirectory`, `OBJ_DONT_REPARSE`, `FILE_OPEN_REPARSE_POINT`,
     `FILE_NON_DIRECTORY_FILE`). Yalnızca uygulamanın adları (`profile.json`,
     `tunnel-state.json`, `recover-state.json`, `service.log`, `service.log.N`, `.<ad>.<16 hex>.tmp`), tek bağlantılı
     normal dosya ve güvenilir sahip/DACL kabul edilir. **Hepsi ya da hiçbiri:** başka bir
     şey varsa ya da bir girdi incelenemiyorsa (kullanımda) hiçbir şey silinmez. Silme,
     incelenen tanıtıcılar üzerinden yapılır (`FileDispositionInfoEx`, POSIX anlamı; eski
     sistemde `FileDispositionInfo`); hiçbir ad iki kez çözülmez. Klasör ancak sonra boşsa
     yine tutulan tanıtıcıyla silinir. Güvenilmeyen/beklenmeyen klasör bırakılır, nedeni
     elle incelenir ve kaldırma **başarılı** biter. Native EXE commit eyleminin stdout
     ayrıntıları MSI günlüğüne aktarılmaz; günlükte eylemin dönüş kodu bulunur.
     `util:RemoveFolderEx` (yol adıyla
     özyinelemeli silme; Codex 4. tur bulgu 1) kaldırıldı; MSI `%ProgramData%` altında
     hiçbir şeyi yol adıyla silmez.
  5. Dosyalar ve kısayol kaldırılır.
  Commit öncesi hata olursa profil ve kurtarma kaydı hâlâ yerindedir; geri alma bunları
  kullanır. Commit temizliği hatası artık geri alınmaz; veri klasörü elle incelemeye kalır.
- **Yükseltme (`MajorUpgrade Schedule="afterInstallInitialize"`):** eski ürün
  `InstallInitialize`'dan hemen sonra (`RemoveExistingProducts` 1501), bu kurulumun
  işleminin **içinde** kaldırılır. Yeni kurulum sonradan başarısız olursa Windows Installer
  ikisini birlikte geri alır: eski ürünün dosyaları, hizmet kaydı ve (Windows Installer'ın
  durdurduğu hizmet için) çalışma durumu geri yüklenir — beklenen Windows Installer
  davranışı, **NOT TESTED** (S15). Eski ürünün kaldırılması `UPGRADINGPRODUCTCODE` ile
  çalıştığından ne `recover` ne veri temizliği çalışır: profil ve kalıcı politika korunur
  (eski 0.1.0-beta derlemelerindeki `RemoveFolderEx` de aynı koşulla çalışmaz).
- **Yükseltme/onarım sonrası başlatma:** `AuraResume` (`start --msi`) artık
  **`Execute="commit"`** (LocalSystem): yalnızca kurulum betiğinin tamamı başarıyla
  bittikten sonra, `InstallFinalize` içinde çalışır; hizmeti yalnızca profil ve kalıcı
  politika varsa otomatik başlatmaya alıp başlatır (`resumeDecision`). Kurulum başarısız
  olursa hiç çalışmaz. `RollbackDisabled` set edilmiş yükseltme, onarım ve tam kaldırma
  `InstallInitialize` öncesinde Türkçe hatayla reddedilir; rollback/commit atlanamaz.
- `--msi` bayrağı yalnızca `recover`, `recover-rollback`, `start`, `uninstall` ile kabul edilir: hiçbir zaman
  soru sormaz, UAC ile yeniden başlatmaz, Enter beklemez; yönetici/SYSTEM değilse hiçbir
  şey yapmaz. `recover --msi` kaldırılacak bir şey yoksa da 0 döner. UAC ile kendini
  yükseltme (`ShellExecute "runas"`) yalnızca kullanıcının başlattığı etkileşimli komutlar
  içindir (Başlat menüsünden `setup`, konsoldan `start`/`stop`/...).

## Paket sözleşmesi (Go, module `aurasplit`)

| Paket | Sahibi | API |
|---|---|---|
| `internal/profile` | ortak | `Profile`, `WireGuard`, `Load`, `Marshal`, `Validate` |
| `internal/paths` | ortak + engine ajanı | `DataDir`, `InstallDir`, `ProfilePath`, `LogPath`, `StatePath`, `InstalledExePath`; `EnsureSecureDir`, `WriteSecureFile`, `WriteSecureFileInDir`, `StageSecureFile`, `OpenSecureAppend`, `ReplaceFile`, `IsTrustedAppDir`, `IsTrustedFile`, `CleanDataDir` (`CleanResult`), `QuarantineInfix` (SDDL `O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`; `InstallSDDL` = MSI'nin kurulum klasörüne koyduğu tanımlayıcı, ek olarak `BU` okuma/çalıştırma) |
| `internal/logfile` | engine ajanı | `Open(dir, name string, maxSize int64, backups int) (*Writer, error)` — kesin boyut sınırlı döndürmeli günlük; `Degraded() bool`; `Scrub`/`ScrubString` (kullanıcı yolları) |
| `internal/provider` | Codex | `ParseWireGuardConf(data []byte) (profile.WireGuard, error)`; `RegisterWARP(ctx context.Context, c *http.Client) (profile.WireGuard, error)` |
| `internal/engine` | engine ajanı | `BuildConfig(p *profile.Profile) ([]byte, error)` (ad uç noktası çözülemezse `ErrEndpointUnresolved`); `BuildBlockConfig`; `Check(p *profile.Profile) error`; `Run(ctx context.Context, p *profile.Profile, opts RunOptions) error` (ctx iptaline kadar bloklar; `RunOptions{LogWriter, Debug, OnState, RetryDelay, OnTunnelUp func() (io.Closer, error), OnConnectivity func(ProbeResult), ProbeURL}`; durumlar `StateStarting`, `StateTunnelStarted`, `StateBlocking`, `StateError`, `StateStopped`; bağlantı `ConnConnecting`, `ConnVerified`, `ConnDegraded`, `ConnDisconnected`) |
| `internal/wfp` | engine ajanı | `Policy` arayüzü: `Apply(paths []string, mode ApplyMode) (ApplyResult, error)` (`AddOnly`/`Authoritative`; `*IncompleteError`/`ErrIncomplete` geçerli sonuçla döner), `PermitOnTunnel(luid uint64, paths []string) (Permit, error)` (`Permit`: `io.Closer` + `Paths()`), `RemoveAll() error`, `Installed() (bool, int, error)`; `New() *Firewall`; `NewGuard(...)` (`Reconcile`, `TunnelUp`, `Run(ctx, interval, kick)`, `Status`); `Discover`, `DiscoverIn`, `ProfileDirs`, `ErrCapReached`, `WatchTargets`, `WatchTargetsIn`, `RunWatcher`, `TunnelLUID`; `ProviderKey`, `SubLayerKey`, `SubLayerWeight` |
| `internal/service` | engine ajanı | `IsAdmin() bool`; `IsWindowsService() (bool, error)`; `Verify(exePath string) error` (MSI'nin kaydettiği hizmeti doğrular: tırnaklı komut satırı, LocalSystem, kendi süreci, `BFE`; hizmeti CLI **oluşturmaz/silmez**); `EnableNonCrashRecovery() error`; `SetAutoStart(bool) error`; `Disable() error`; `ScrubEventText`; hatalar `ErrNotInstalled`, `ErrNotRunning`, `ErrStartPending`, `ErrFatal` (gözetici durur, hizmet sıfırdan farklı kodla çıkar); `Start() error`; `StartWait(timeout) error`; `Stop() error`; `Status() (string, error)`; `StatusPID() (string, uint32, error)`; `RunService(run func(ctx context.Context) error) error` |
| `cmd/aurasplit` | CLI ajanı | `setup` (yalnızca kurulu kopyadan; yapılandırma), `status`, `start`, `stop`, `restart`, `disable`, `recover`, `uninstall` (yalnızca MSI ile kaldırmayı anlatır), `recover --msi` / `start --msi` / `uninstall --msi` (Windows Installer bağlamı, etkileşimsiz), `run [--debug]` (ön planda hata ayıklama, konsola günlük), `service` (gizli; SCM çağırır), `version` |
| `cmd/auraclean` / `internal/msiclean` | paketleme | Küçük, yalnızca MSI içine gömülen temizleme yardımcısı; `uninstall --msi`, yönetici/SYSTEM denetimi. CLI ile ortak kurtarma ve veri temizliği kodu; `internal/paths`, `internal/service` ve WFP kaldırması için `internal/wfp` kullanır; engine/sing-box içermez. Commit öncesi profil ve geri alma kaydı korunur; kurtarma hatasında veri silinmez. |
| `installer` | paketleme | `AuraSplitTR.wxs` (WiX 5.0.2 + `WixToolset.Util.wixext`; `build.ps1` derler ve ICE ile doğrular) |

## Güvenlik kuralları (bütün ajanlar)

- Özel anahtar, preshared key ve WARP token asla loglanmaz/ekrana basılmaz.
- Yalnızca HTTPS; TLS doğrulaması kapatılmaz. WARP API yanıt boyutu sınırlanır.
- Kaynak kodda kişisel veri, kullanıcı adı, mutlak kullanıcı yolu, gerçek anahtar yok.
  Test anahtarları test içinde üretilir.
- Derleme `-trimpath -buildvcs=false -tags with_gvisor,with_wireguard,with_external_windivert`
  ile yapılır (binary içinde yerel yol kalmaz; WinDivert sürücüsü gömülmez).
- Lisans: sing-box GPL-3.0-or-later olduğu için proje GPL-3.0-or-later.
