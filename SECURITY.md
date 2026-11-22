# Güvenlik / Security

## Tehdit modeli (özet)

### Korunanlar

- **Özel anahtar yerel kalır.** WireGuard özel anahtarı (ve varsa preshared key)
  yalnızca `%ProgramData%\AuraSplitTR\profile.json` içinde saklanır. Klasörün sahibi
  `Administrators` grubudur ve korumalı ACL'i yalnızca `SYSTEM` ile `Administrators`
  grubuna izin verir; normal kullanıcı hesapları ve yönetici olmadan çalışan programlar
  okuyamaz veya değiştiremez.
- **Klasör güveni.** Veri ve kurulum klasörleri Known Folder API'siyle bulunur (ortam
  değişkenleriyle değil). Yoksa güvenli tanımlayıcıyla atomik olarak oluşturulur. Varsa
  bağlantı (junction/symlink) olmadığı doğrulanır ve sahibi ile ACL'i (yalnızca-miras
  girdileri dahil) incelenir. Güvenilir değilse klasör **silinmez**, korumalı ACL'li bir
  `AuraSplitTR.quarantine-<zaman>` klasörü olarak kenarda tutulur ve yenisi oluşturulur.
  Güvenilirse ACL yeniden yazılır ve her alt öğenin sahibi ile ACL'i ayrı ayrı denetlenir:
  güvenilmeyen günlük dosyaları içerikleri kopyalanmış **yeni** dosyalarla değiştirilir
  (eski tanıtıcılar yeni dosyaya erişemez); güvenilmeyen `profile.json`,
  ve `tunnel-state.json` yeniden kullanılmaz (profil için `setup`
  yeniden çalıştırılmalı); uygulamaya ait olmayan her şey karantina klasörüne
  **taşınır**, silinmez. İncelenemeyen bir öğe (kullanımda, erişim reddi) güvenilmez
  sayılmaz: işlem hiçbir şeyi değiştirmeden hata verir. Hizmet her başlangıçta bu
  denetimi tekrarlar. Karantina klasörleri eski bir profil (özel anahtar) içerebilir;
  inceledikten sonra yönetici olarak elle silin (MSI kaldırması bunları silmez).
  (Kurulum klasörü bu taramaya girmez: Windows Installer'a aittir ve `setup` onu yalnızca
  denetler.)
- **Günlük dosyası** bağlantı izlenmeden açılır; reparse point, sabit bağlantı ya da
  güvenilmeyen sahip/ACL varsa yukarıdaki kurala göre değiştirilir. Boyut sınırı
  kesindir (2 MB + 2 yedek): döndürme başarısız olursa yeni satırlar atılır ve sayılır,
  döndürme 30 sn'de bir yeniden denenir. Kullanıcı profil yolları tüm satırlarda
  (sing-box satırları dahil) `C:\Users\<user>` ile değiştirilir. sing-box günlüğü sınırlı
  bir kuyruktan geçer; disk yavaşlasa da tünel beklemez (fazla satırlar atılıp sayılır).
- **Kurulum güveni: Windows Installer (MSI).** Program dosyası, hizmet kaydı, olay
  günlüğü kaynağı ve Başlat menüsü kısayolu standart bir MSI paketiyle
  (`installer/AuraSplitTR.wxs`) kurulur ve kaldırılır; `aurasplit.exe` artık kendini
  kopyalamaz, hizmet oluşturmaz veya silmez. Kurulum klasörü `%ProgramFiles%\AuraSplitTR`
  MSI tarafından korumalı bir ACL ile (SYSTEM + Administrators tam, Users okuma/çalıştırma)
  oluşturulur. `setup` (yapılandırma) yalnızca kurulu kopyadan çalışır — karar yol metniyle
  değil, süreç başında paylaşımsız açılan çalışan görüntünün dosya kimliğiyle verilir — ve
  hiçbir şeyi değiştirmeden önce kurulum klasörünün ve `aurasplit.exe`'nin yalnızca
  SYSTEM/Administrators/TrustedInstaller tarafından değiştirilebildiğini ve kayıtlı
  hizmetin tırnaklı `"<kurulu exe>" service` komut satırıyla LocalSystem olarak, `BFE`
  bağımlılığıyla çalıştığını doğrular. Uymuyorsa MSI onarımını ister. Yeni profil ancak
  çalışan hizmet durdurulduktan sonra eskisinin yerine geçer. MSI hizmeti **El ile**
  başlatma türüyle kaydeder; yalnızca yapılandırma onu otomatik yapar.
- **İmza.** Sürümler henüz Authenticode ile imzalı değildir (iş akışında imzalama adımı
  hazırdır, yapılandırılmadıkça atlanır; sahte veya kendinden imzalı imza üretilmez).
  İmzasız bir programın hizmet kurması ve kalıcı WFP filtresi eklemesi bazı antivirüs
  ürünlerince (ör. canlı testte Kaspersky davranış algılaması, eski kendi kendini kuran
  sürümde) şüpheli bulunabilir. Antivirüsü kapatmayın, istisna eklemeyin; yanlış alarmı
  üreticiye bildirin. Araç hiçbir antivirüs algılamasını atlatmaya çalışmaz.
- **Kaldırma** Windows Installer ile yapılır: önce `recover --msi` (LocalSystem, pencere
  ve soru yok) kalıcı WFP politikasını kaldırır ve hizmeti devre dışı bırakıp durdurur.
  **Bu adım başarısız olursa** (politika kaldırılamadı ya da hâlâ yüklü, WFP motoru
  açılamadı, hizmet durdurulamadı) özel eylem `Return="check"` olduğundan kaldırma
  **geri alınır**: program ve hizmet kalır, Discord engelli ama kurtarma aracı yerinde
  olur. Kurulu `aurasplit.exe` yoksa (ör. antivirüs karantinası) kaldırma hiç başlamaz ve
  Türkçe bir hata iletisi ne yapılacağını söyler: dosyayı karantinadan geri yükleyin ya
  da aynı sürümün MSI paketini yeniden indirip kurun/onarın ve sonra kaldırın; yalnızca
  Discord engelini hemen kaldırmak için aynı sürümün `aurasplit.exe` dosyasıyla yönetici
  olarak `aurasplit.exe recover` çalıştırın (sağlayıcı anahtarı programa gömülüdür; başka
  sürümler de aynı anahtarı kullanır ama aynı sürüm önerilir). Kurulu exe geri
  yüklenmeden kaldırma sürdürülemez; dosya denetimini atlayan özellik yoktur.
  Kurtarmadan önce başlangıç türü, çalışma bayrağı, WFP politika varlığı ve politikadaki
  korunan uygulama yolları güvenli, sürüm 2 `recover-state.json` dosyasına yazılır.
  Geri alma servis durumunu aynen geri yükler; yalnızca önceden mevcut WFP politikasını
  kayıtlı yollarla add-only uygular (kısmi kurtarmadan kalan blokları korur).
  Profil veya yeni keşif gerekmez; önceden politika yoksa oluşturulmaz.
  Eski veya bilinmeyen kayıt sürümleri hiçbir durum değiştirilmeden reddedilir.
  Kayıt VPN anahtarı içermez. Profil ve kayıt başarılı işlemin commit aşamasına kadar
  korunur; veri temizliği MSI'ye gömülü aynı sürüm araçla o aşamada çalışır.
  Temizlik hatasında veri klasörü kalabilir; hata MSI günlüğüne yazılır.
- **Veri klasörünün silinmesi** artık yol adıyla özyinelemeli yapılmaz (WiX
  `RemoveFolderEx` kaldırıldı: klasörü önceden oluşturan standart bir kullanıcı, denetim
  ile silme arasında onu bir junction ile değiştirerek SYSTEM'in silme işlemini başka
  yere yönlendirebilirdi — Codex 4. tur bulgu 1). `uninstall --msi` (LocalSystem)
  klasörü bağlantı izlemeden ve `FILE_SHARE_DELETE` vermeden açar ve tanıtıcıyı sonuna
  kadar tutar (başkası klasörü yeniden adlandıramaz, silemez, değiştiremez); gerçek
  klasör, sahip ve ACL yalnızca SYSTEM/Administrators/TrustedInstaller olmalıdır. Girdiler
  bu tanıtıcıdan listelenir ve her biri ona göreli, reparse point izlenmeden açılır;
  yalnızca uygulamanın kendi dosyaları (`profile.json`, `tunnel-state.json`,
  `service.log*`, kendi geçici dosyaları), tek bağlantılı normal ve güvenilir dosyalar
  olarak, aynı tanıtıcılar üzerinden silinir. Güvenilmeyen klasör ya da beklenmeyen tek
  bir girdi bile varsa **hiçbir şey silinmez**; klasör elle incelemeye bırakılır,
  kaldırma başarılı biter. Böyle bırakılmış bir klasör özel anahtar içerebilir:
  içeriğini inceleyip yönetici olarak elle silin. Native EXE commit eyleminin stdout
  ayrıntıları MSI günlüğüne aktarılmaz; günlükte eylemin dönüş kodu bulunur.
  Klasör yalnızca boşsa, tutulan
  tanıtıcıyla silinir. Yükseltmede bu adımlar çalışmaz. Karantina klasörleri silinmez.
- **Yükseltme geri alınabilir:** eski sürüm yeni sürümün kurulum işleminin içinde
  kaldırılır (`MajorUpgrade Schedule="afterInstallInitialize"`); yeni kurulum başarısız
  olursa eski sürüm geri gelir. Hizmet yalnızca kurulum işlemi tamamlandıktan sonra
  (commit özel eylemi) yeniden başlatılır. `RollbackDisabled` set edilmiş yükseltme,
  onarım ve tam kaldırma işlem başlamadan Türkçe hatayla reddedilir.
- **Cloudflare WARP kaydı:** anahtar çifti cihazda üretilir; Cloudflare'e yalnızca açık
  anahtar gönderilir. HTTP yönlendirmeleri izlenmez (3xx hata sayılır).
- **Gizli değerler loglanmaz.** Özel anahtar, preshared key ve WARP token ekrana veya
  günlüğe yazılmaz.
- **Yalnızca HTTPS.** Ağ istekleri (WARP kaydı) HTTPS ile yapılır, TLS sertifika
  doğrulaması kapatılmaz, yanıt boyutu sınırlanır.
- **Telemetri yok.** Araç hiçbir kullanım verisi, analiz veya hata raporu göndermez.
- **Temiz derleme.** `-trimpath -buildvcs=false` ile derlenir; binary içinde
  derleyen kişinin yerel yolları bulunmaz. (İstisna: gömülü üst akış **wintun** DLL'i,
  kendi yazarının derleme ortamına ait bir PDB yolu içerir; bu üst akıştan gelir.)
- **Kalıcı fail-closed (WFP).** Bulunan her Discord programı (tüm kullanıcı
  profillerinde `AppData\Local\Discord*\Update.exe` ve `app-*\Discord*.exe`) için
  kalıcı Windows Filtering Platform kuralları vardır: `ALE_AUTH_CONNECT_V4/V6` ve
  `ALE_AUTH_RECV_ACCEPT_V4/V6` katmanlarında yerel döngü (loopback) izni ve diğer her
  şeye engel. Bu kurallar BFE tarafından açılışta, kullanıcı oturum açmadan yüklenir ve
  hizmet durduğunda veya çöktüğünde de geçerlidir. Çalışan hizmet, tünel başarıyla
  başladıktan **sonra** yalnızca TUN arayüzü (LUID) için dinamik bir izin ekler; bu izin
  hizmet süreciyle birlikte kaybolur. `stop` sonrası Discord engelli kalır; doğrudan
  bağlantı yalnızca açık bir `disable` (onaylı) veya `recover` ile mümkündür; ikisi de
  hizmeti **durdurmadan önce devre dışı (Disabled)** yapar, böylece SCM'nin sıradaki bir
  kurtarma yeniden başlatması kuralları geri yükleyemez (`start`/`setup` yeniden etkinleştirir).
  **Fail-closed yalnızca bulunan envanteri kapsar:** kural silme yalnızca hatasız ve
  tam bir taramadan sonra, her programın uygulama kimliği okunabildiyse yapılır ve diski
  hâlâ var olan bir programın kuralı **asla** silinmez. Eksik tarama, sınır aşımı veya
  okunamayan uygulama kimliği yalnızca ekleme yapar (WFP'deki mevcut kurallar, önceki
  sürecinkiler dahil, korunur), `status` "Kapsam: EKSİK" gösterir ve 10 sn'de bir yeniden
  denenir. Tünel izni de ayrı izlenir: başarısız/eksik izin yeniden denenir ve `status`
  izni yalnızca kapsadığı programlar için "açık" gösterir. Eksik bir yeni izin (ör. bir
  programın uygulama kimliği geçici olarak okunamadı) eski izni kapatmaz; eski ve yeni
  oturum (en fazla 2) tam bir yenisi açılana kadar birlikte kalır ve durum "EKSİK" olur.
  WFP'nin devre dışı (`FWPM_FILTER_FLAG_DISABLED`) bildirdiği bir filtre koruma
  **sayılmaz** (`status` sayısına girmez); aranan bir filtre devre dışıysa aynı işlemde
  silinip yeniden eklenir. Politika bütçesi: mevcut + önerilen toplam en fazla 256 program,
  profil başına 32; aşılırsa yeni programlar eklenmez, kapsam "EKSİK" gösterilir ve var olan
  kurallar yer açmak için silinmez (dinamik izin de aynı bütçeyle sınırlıdır).
  **NOT TESTED:** gerçek WFP çağrıları bu makinede çalıştırılmadı; yalnızca sahte bir
  arka uçla birim testleri ve WFP çağrısı yapmayan yapı (marshalling) testleri var.
  Fail-closed davranışının hiçbir kısmı (aşağıdaki pencereler dahil) gerçek bir ağda
  **doğrulanmadı**. Yetkili bir yönetici testi gerekir.
- **Tünel başlatılamazsa fail-closed.** Tünel başlatılamazsa (ör. açılışta ağ yok,
  sunucu adı çözülemiyor) hizmet aynı TUN arayüzüyle Discord trafiğini ve Discord DNS
  sorgularını **reddeden** bir yapılandırma çalıştırır ve tüneli yeniden dener. Bir
  sing-box örneği 10 sn içinde kapanmazsa aynı süreçte yeni örnek başlatılmaz (eski örnek
  TUN'u hâlâ tutuyor olabilir): hizmet sıfırdan farklı kodla çıkar ve SCM kurtarma
  eylemi onu temiz bir süreçte yeniden başlatır; arada kalıcı kurallar Discord'u engeller.
  Bağlantı denetimi (probe) `www.cloudflare.com` adını yerel çözücüye değil, tünel
  içinden profilin DNS sunucusuna (varsayılan 1.1.1.1) sorar ve IP'ye bağlanır; TLS
  sertifikası yine ad üzerinden doğrulanır. `status`
  komutu tünel durumunu hizmet durumundan ayrı gösterir; kayıt yalnızca SCM'nin
  bildirdiği hizmet sürecine (PID + başlangıç zamanı) aitse ve son 90 sn içinde
  yenilenmişse gösterilir, aksi halde "bilinmiyor" yazar. "Tünel başlatıldı"
  yapılandırmanın uygulandığı anlamına gelir; WireGuard el sıkışması doğrulanmaz
  (sing-box v1.14.4 bunu dışa açmıyor).

### DNS güvencesi (dar kapsam)

Yalnızca listelenen Discord alan adları (`discord.com`, `discord.gg`, `discordapp.com`,
`discordapp.net`, `discord.media`, `discordcdn.com`, `discord.co`, `discord.new`,
`discord.gift`, `discord.dev`, `discordstatus.com`, `discordsays.com`, `dis.gd` ve tam ad
`discord-attachments-uploads-prd.storage.googleapis.com`) her zaman tünel içindeki
çözücüye sorulur. Discord'un kullanabileceği diğer alan adları (üçüncü taraf hizmetler)
için bu güvence **yoktur**; Discord süreçleri kendi çözücülerini kullanırsa yakalanır,
ancak Windows'ta sorguların çoğu DNS İstemcisi hizmetinden geldiği için süreç bilgisi
görünmez.

### Korunmayanlar (bilinen fail-open pencereleri)

- **Kalıcı engellemenin kapsamı dışında kalanlar.** Kalıcı kurallar uygulama kimliğine
  (tam program yolu) bağlıdır. Şunlar bu kurallarla **engellenmez**: listelenen konumlar
  dışına kurulmuş Discord kopyaları, `ExtraProcessNames` ile eklenen programlar, Discord
  kurulum dosyaları ve tarayıcıdaki Discord. Bunlar hizmet çalışırken tünele
  yönlendirilir, hizmet çalışmıyorken doğrudan bağlanabilir. Kurallar hiç uygulanamazsa
  (ör. BFE hatası) `status` `PROTECTION_ACTIVE: HAYIR` gösterir ve eski davranış
  geçerlidir (hizmet çalışmıyorken doğrudan).
- **Güncelleme yarışı (kalan mimari sınır).** Kurallar tam program yoluna bağlıdır;
  gelecekteki bir sürüm ilk bağlantısından önce kapsanamaz. Hizmet her Discord kurulum
  klasörünü değişiklik bildirimiyle (`FindFirstChangeNotification`) izler ve yeni bir
  `app-*` klasörü/programı göründükten yaklaşık 1 sn sonra kuralları ekler; 60 sn'lik
  periyodik tarama yedektir. Kalan pencereler: (1) yeni sürüm, izleyici uzlaştırmayı
  bitirmeden **ve** aynı anda tünel/hizmet çalışmazken bağlanırsa doğrudan çıkabilir
  (hizmet çalışırken sing-box onu yine tünele yönlendirir); (2) hizmet durmuşken
  hazırlanmış (staged) bir sürüm, hizmet yeniden başlayıp tarayana kadar kapsanmaz.
  Not: hizmet dururken `Update.exe` de engelli olduğu için güncelleyici bu sürede yeni
  sürüm **indiremez**; yine de el ile kopyalanan veya hizmet durdurulmadan hemen önce
  inmiş bir sürüm bu pencereye girer. Bulma sınırları (64 profil, klasör başına 16 exe,
  profil başına 32, toplam 256 yol) aşılırsa sessizce atlanmaz: tarama eksik sayılır,
  hiçbir kural silinmez. Bir klasör izlemesi açılamaz ya da düşerse hemen günlüğe yazılır
  ve 1 sn'den 60 sn'ye artan aralıklarla yeniden kurulur; arada yalnızca 60 sn'lik tarama
  çalışır (pencere o süre kadar uzar).
- **DNS, hizmet çalışmıyorken.** Discord'un `discord.com` gibi ad sorguları Windows DNS
  İstemcisi (svchost) üzerinden gider; WFP bunları Discord'a bağlayamaz. Hizmet
  çalışmıyorken bu sorgular ISS çözücüsüne açık metin gidebilir (bağlantının kendisi
  engellenir).
- **sing-box içindeki yönlendirme hatası.** Hizmet çalışırken bir Discord bağlantısının
  süreç bilgisi okunamazsa ve hedef bir Discord alan adı değilse sing-box onu `direct`
  çıkışa gönderebilir; bu soket `aurasplit.exe`'ye aittir, WFP onu Discord'a bağlayamaz.
- **Başka güvenlik yazılımları.** Daha yüksek ağırlıklı bir alt katmanda "hard permit"
  kullanan başka bir VPN/güvenlik duvarı Discord engelini aşabilir (test edilmedi).
- **Program dosyası silinirse.** Kurallar kalır ve Discord engelli kalır. Çözüm: aynı
  programı yeniden indirip `aurasplit.exe recover` çalıştırmak (sağlayıcı GUID'i
  programa gömülüdür: `4699124e-3633-487f-90c5-77e86738322c`).
- **VPN sağlayıcısı** (Cloudflare, Proton veya kullandığınız WireGuard sunucusu) tünelden
  geçen Discord trafiğinin meta verilerini (hedef IP, zaman, hacim) görebilir. Discord
  trafiği zaten TLS ile şifrelidir, ancak sağlayıcıya güvenmeniz gerekir.
- **Yerel yönetici** (veya yönetici yetkisiyle çalışan kötü amaçlı yazılım) profil
  dosyasını ve özel anahtarı okuyabilir.
- **Discord dışındaki trafik** tünelden geçmez; bu bir gizlilik/anonimlik aracı değildir.
- İndirdiğiniz orijinal `.conf` dosyası özel anahtarı içerir; kurulumdan sonra silmek
  kullanıcının sorumluluğundadır.
- Yerel ağınızdaki ve ISS'nizdeki gözlemciler bir VPN sunucusuna bağlandığınızı görebilir.

### Günlükler

- Varsayılan düzey `warn`: normal bağlantılar ve DNS sorguları (gezinme geçmişi)
  **yazılmaz**. Yalnızca başarısız DNS sorguları veya bağlantı hataları bir alan adı ya da
  IP adresi içerebilir.
- `aurasplit.exe run --debug` her bağlantıyı ve hedefini yazar; yalnızca ön planda ve
  yalnızca konsola yazılır, dosyaya yazılmaz.

### Sürüm yayımlama

- Resmî sürümler yalnızca elle başlatılan `.github/workflows/release.yml` ile
  etiketli kaynaktan derlenir; `SHA256SUMS.txt` ve GitHub derleme kaynağı
  (provenance) kanıtı üretilir, sürüm **taslak** olarak oluşturulur ve elle
  yayımlanır. Doğrulama: [docs/BUILD.md](docs/BUILD.md).
- Kurulum paketi `AuraSplitTR-<sürüm>-x64.msi` sabitlenmiş WiX 5.0.2 ile derlenir ve
  ICE kurallarıyla doğrulanır; `SHA256SUMS.txt` ve derleme kaynağı kanıtı exe, msi ve
  zip'i kapsar.
- Sürüm dosyaları şu anda **Authenticode ile imzalı değildir**; SmartScreen uyarısı
  ve antivirüs yanlış alarmları görülebilir. İş akışındaki imzalama adımları
  yapılandırılırsa sıra: exe imzası → MSI derleme → MSI imzası → `SHA256SUMS.txt` ve
  provenance.
- GPL-3.0 tam metni `LICENSE`, üçüncü taraf lisansları `THIRD_PARTY_LICENSES.md`
  dosyasındadır.

## Güvenlik açığı bildirme

Lütfen güvenlik açıklarını herkese açık bir issue, tartışma veya pull request
olarak **bildirmeyin**. Bunun yerine:

1. **Tercih edilen:** GitHub özel güvenlik bildirimi —
   `https://github.com/umut720s/aura-split-tr/security/advisories/new`
   (depo sayfasında *Security → Report a vulnerability*).
2. Bu mümkün değilse: `<security-contact>`.

Mümkünse şunları ekleyin:

- Etkilenen sürüm (`aurasplit.exe version`) ve Windows sürümü
- Sorunun açıklaması, etkisi ve yeniden üretme adımları
- Günlükten ilgili satırlar. Paylaşmadan önce **kullanıcı adlarını** (ör.
  `C:\Users\<ad>\...` yollarında), bilgisayar adını, IP adreslerini ve paylaşmak
  istemediğiniz alan adlarını gizleyin. **`.conf` dosyası, `profile.json`, özel
  anahtar, preshared key veya WARP token göndermeyin.** Günlük bunları içermez,
  yine de gizli değer olmadığından emin olun.

Süreç (hedefler, garanti değildir): alındı bildirimi 7 gün içinde; ilk
değerlendirme 14 gün içinde; düzeltme ve eşgüdümlü açıklama en geç 90 gün içinde.
Düzeltme yayımlanana kadar ayrıntılar gizli tutulur; isterseniz bildirim
sahibi olarak anılırsınız. Desteklenen sürüm: yalnızca en son yayımlanan sürüm.

### English

Please report vulnerabilities **privately**, not as a public issue, discussion
or pull request:

1. Preferred: GitHub private vulnerability reporting —
   `https://github.com/umut720s/aura-split-tr/security/advisories/new`.
2. Otherwise: `<security-contact>`.

Include the version (`aurasplit.exe version`), Windows version, impact and
reproduction steps. **Redact user names** (e.g. `C:\Users\<name>\...`), machine
names, IP addresses and host names from log lines, and never send `.conf`
files, `profile.json`, private/preshared keys or WARP tokens. Targets: ack
within 7 days, triage within 14 days, fix and coordinated disclosure within
90 days. Only the latest release is supported.

Known limitations (English summary): persistent WFP filters block the discovered
Discord executables outside the tunnel also while the service is stopped, crashed or
not yet started (NOT TESTED on a real machine and NOT verified in a real network;
unit-tested with a fake backend only). Filters that WFP reports as disabled never
count as protection (they are deleted and re-added in the same transaction). The
persistent policy (existing plus proposed) is bounded at 256 executables, 32 per
profile; beyond that new executables are not added and coverage is reported as
incomplete, existing blocks are never removed to make room, and the dynamic permit uses
the same budget. A partial permit replacement never closes the old permit session
(at most 2 sessions until a complete replacement exists). A failed or dropped directory
watch is reported at once and re-established with a 1 s to 60 s backoff.
Fail-closed covers only the discovered and resolved executable inventory: filters
are removed only after a complete, error-free discovery with every app ID resolved,
and never for an executable that still exists on disk; any incomplete pass is
add-only and shown as incomplete in `status`. Remaining update race: a new Discord
version is covered about 1 s after its directory/executable appears (directory
watcher, 60 s rescan as backstop); a version launched before that while the tunnel
is down, or staged while the service was stopped (Update.exe itself is blocked then,
so it cannot download while stopped), is not covered until the next reconcile.
Not covered: Discord copies outside `%LOCALAPPDATA%\Discord*`, installers, Discord in a
browser (not covered by WFP; tunnelled by domain only while the service runs), DNS
lookups made by the Windows DNS Client (Dnscache) while the service is down (they can
reach the ISP resolver in clear text; the connections are blocked), and flows
sing-box routes to `direct` after a process-lookup failure. `stop` keeps Discord
blocked; `disable`/`recover` set the service to Disabled before stopping it and then
remove the filters (Discord goes direct; no queued SCM restart can re-apply them). If the exe is
lost, download the same tool and run `aurasplit.exe recover`. DNS protection covers the listed Discord domains only. Logs default to `warn`
and contain no browsing history unless `run --debug` (console only) is used. The
embedded upstream wintun DLL contains its author's build PDB path. Installation trust
now comes from a standard Windows Installer package: the MSI (not aurasplit.exe) copies
the program into an ACL-protected `%ProgramFiles%\AuraSplitTR`, registers the service
(manual start until `setup` configures it) and removes it on uninstall after running
`recover --msi`. That step must succeed (`Return="check"`): if the WFP policy cannot be
removed (or the service cannot be stopped) the uninstall rolls back and keeps the
service and aurasplit.exe. If the installed aurasplit.exe is missing (e.g. AV
quarantine) the uninstall stops with a Turkish error explaining to restore the file or
reinstall/repair the same version, run `aurasplit.exe recover`, then uninstall.
The installed executable must be restored; the check cannot be bypassed. The data
folder is no longer deleted recursively by path (WiX RemoveFolderEx removed: a
pre-created folder could be swapped for a junction between inspection and deletion);
`uninstall --msi` holds a no-follow handle without delete sharing on the folder, requires
SYSTEM/Administrators ownership and ACL, opens every entry relative to that handle without
following reparse points, deletes only AURA Split TR's own plain, single-link, trusted
files through the inspected handles and the folder only if it is then empty; anything
unexpected or an untrusted folder means nothing is deleted (retained for manual
inspection, the uninstall still succeeds). Upgrades remove the old version inside the
new installation's transaction (rollback restores it); the service is restarted by a
commit custom action. `setup` runs only from the installed copy (file identity) and
verifies the folder/exe ACLs and the registered service before changing anything.
Endpoint host names are resolved before a tunnel configuration is built; an unresolved
name keeps Discord blocked (fallback) and is retried, never written into the
configuration. The tunnel is rebuilt (name re-resolved) after VPN_DISCONNECTED or a change
of the host IPv6 capability (preferred usable global address and ::/0 on the IPv4
default interface selected by the pinned sing-tun monitor using route + interface metric),
at most once per 2 minutes, with the persistent policy blocking
Discord in the gap (NOT TESTED on a real network).
Releases are not Authenticode-signed yet (an optional signing step exists and is skipped
unless configured; no fake signatures); verify SHA256SUMS.txt and the build provenance
attestation (docs/BUILD.md). Do not disable antivirus or add exclusions; report false
positives.
