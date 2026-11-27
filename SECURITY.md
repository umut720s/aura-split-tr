# Güvenlik / Security

## Deneysel beta — doğrulama kapsamı

**v0.1.1-beta üretime hazır değildir; exe/MSI imzasızdır ve bağımsız paket düzeyi doğrulaması yoktur.** Yalnızca tek Windows 11 x64 bilgisayarda test edildi. İlk kayıtlar IPv4-only Ethernet ve Kaspersky Plus açıkken alındı; sonraki R3/R4 denemeleri iki fiziksel adaptörü kapsar.

[Canlı test kaydı](docs/testing/phase3_live_results_2026-11-22.md): WARP ve Proton ile örneklenen Discord TCP soketleri TUN üzerindeydi. Genel WireGuard seçeneğinde yine Proton `.conf` kullanıldı; diğer genel sağlayıcılar canlı test edilmedi. Stop/crash/ağ kesintisinde olumlu TCP örneklemesi, UDP/DNS/IPv6 veya açılış penceresi için izolasyon kanıtı değildir.

Run 4 dosya seçiciyi, başlangıç durumunu ve ağ kesintisi bildirimini doğruladı. Run 5 sınırlı fiziksel NIC yakalamalarında hizmet durmuşken **doğrudan browser Discord TLS ve açık metin DNS** kaydetti. Run 6 koruma öncesi açılmış bir desktop TCP bağlantısının fiziksel NIC'te kaldığını kaydetti. **Kapsamlı paket yakalamalı sızıntı kabul testleri tamamlanmadı** (`tools/leaktest` mevcuttur); bu eski yakalamalar sızıntısızlık kanıtı değildir.

R3'te iki adaptörle DNS/İnternet kesildi; R4'te ikisi de İnternet erişimine sahipken sorun tekrarlanmadı. Sonradan eklenen sağlık tabanlı çıkış failover'ı **canlı test edilmedi**. Kesintide `aurasplit.exe stop` veya `disable` kullanın; ikincisi engelleri kaldırır ve Discord doğrudan bağlanabilir. Başka VPN istemcisinin tünelini aynı anda çalıştırmayın.

[Ağ izolasyonu denetimi](docs/audits/network_isolation_audit.md) ve [iyileştirme planı — P0 progress](docs/audits/security_remediation_plan.md#p0-progress) açık bulguları korur. Deneysel yayın, güvenlik kabul kapısının geçildiği anlamına gelmez. [README — bilinen sınırlar](README.md#bilinen-sınırlar) kullanıcı kapsamını özetler. Zorlanmış MSI geri alma/kurtarma hata yolları, yerel IPv6 ve diğer makineler/antivirüsler canlıda doğrulanmadı.

[Sürüm notları / Release notes](docs/RELEASE_NOTES_v0.1.1-beta.md)

## Tehdit modeli (özet)

### Korunanlar

- **Özel anahtar yerel kalır.** WireGuard özel anahtarı (ve varsa preshared key)
  uygulamanın aktif kopyasında `%ProgramData%\AuraSplitTR\profile.json` içinde saklanır; indirilen `.conf` ve tutulmuş karantina kopyaları da anahtar içerebilir. Klasörün sahibi
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
- **İmza.** **v0.1.1-beta dosyaları (exe ve MSI) Authenticode ile imzalı DEĞİLDİR.**
  Windows SmartScreen ve antivirüs ürünleri uyarı verebilir. Her dosyanın SHA-256
  özetini aynı sürümün `SHA256SUMS.txt` dosyasıyla karşılaştırın ve GitHub derleme
  kaynağı doğrulamasını (build provenance attestation) yapın:
  `gh attestation verify <file> -R umut720s/aura-split-tr` (`<file>` yerine indirilen
  dosyanın yolunu yazın). Doğrulama başarısızsa dosyayı çalıştırmayın.
  **Antivirüsü asla kapatmayın veya istisna eklemeyin.** Yanlış pozitifleri antivirüs
  üreticisine bildirin. Authenticode imzalama daha sonraki bir sürüm için planlanıyor.
- **Kaldırma** Windows Installer ile yapılır: önce `recover --msi` (LocalSystem, pencere
  ve soru yok) kalıcı WFP politikasını kaldırır ve hizmeti devre dışı bırakıp durdurur.
  **Bu adım başarısız olursa** (politika kaldırılamadı ya da hâlâ yüklü, WFP motoru
  açılamadı, hizmet durdurulamadı) özel eylem `Return="check"` olduğundan kaldırma
  **geri alınması amaçlanır**: program ve hizmet korunur; kayıtlı program engelleri ve kurtarma aracı yerinde
  olur. Kurulu `aurasplit.exe` yoksa (ör. antivirüs karantinası) kaldırma hiç başlamaz ve
  Türkçe bir hata iletisi ne yapılacağını söyler: dosyayı karantinadan geri yükleyin ya
  da aynı sürümün MSI paketini yeniden indirip kurun/onarın ve sonra kaldırın; yalnızca
  Discord engelini hemen kaldırmak için aynı sürümün `aurasplit.exe` dosyasıyla yönetici
  olarak `aurasplit.exe recover` çalıştırın (sağlayıcı anahtarı programa gömülüdür; başka
  sürümler de aynı anahtarı kullanır ama aynı sürüm önerilir). Kurulu exe geri
  yüklenmeden kaldırma sürdürülemez; dosya denetimini atlayan özellik yoktur.
  Kurtarmadan önce başlangıç türü, çalışma bayrağı, WFP politika varlığı ve politikadaki
  korunan uygulama yolları güvenli, sürüm 2 `recover-state.json` dosyasına yazılır.
  Geri alma kayıtlı servis durumunu geri yüklemeyi amaçlar; yalnızca önceden mevcut WFP politikasını
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
- **Cloudflare WARP kaydı:** anahtar çifti cihazda üretilir; Cloudflare'e açık anahtar ve kayıt meta verileri gönderilir; özel anahtar gönderilmez. HTTP yönlendirmeleri izlenmez (3xx hata sayılır).
- **Gizli değerler loglanmaz.** Özel anahtar, preshared key ve WARP token ekrana veya
  günlüğe yazılmaz.
- **Yalnızca HTTPS.** Ağ istekleri (WARP kaydı) HTTPS ile yapılır, TLS sertifika
  doğrulaması kapatılmaz, yanıt boyutu sınırlanır.
- **Telemetri yok.** Araç hiçbir kullanım verisi, analiz veya hata raporu göndermez.
- **Temiz derleme.** `-trimpath -buildvcs=false` ile derlenir; binary içinde
  derleyen kişinin yerel yolları bulunmaz. (İstisna: gömülü üst akış **wintun** DLL'i,
  kendi yazarının derleme ortamına ait bir PDB yolu içerir; bu üst akıştan gelir.)
- **Sınırlı kalıcı WFP engelleri.** Yalnızca manifestteki keşfedilmiş, AppID'si çözülmüş ve politikası başarıyla uygulanmış tam yolların yeni off-TUN bağlantılarını engellemeyi amaçlar. Manifest desktop/updater, bilinen helper yolları ve kök/SquirrelTemp kurucularıyla sınırlıdır; özel konumlar kapsam dışıdır. Politika bütçesi toplam 256, profil başına 32 programdır; eksik kapsam `status` ile bildirilir. Hizmet durunca dinamik TUN izni kaybolur, kalıcı engeller kalır. **Bu, uçtan uca fail-closed güvencesi değildir:** engine kimlik kaybı (P0-D), enrollment yarışı ve eski akış sınırları sürer.
- **Bağlantı durumu izolasyon kanıtı değildir.** `status` hizmeti, tüneli, bağlantı probe'unu ve kapsamı ayrı gösterir. `VPN_CONNECTIVITY_VERIFIED` bağlantı kontrolünün sonucudur; `PROTECTION_READY` politika/kapsam/eski süreç kapısı durumudur. Hiçbiri paket düzeyi doğrulaması değildir. Tünel başlatılamazsa eşleşen trafik için reject yapılandırması ve yeniden deneme uygulanır; sınıflandırılamayan akışlar ve DNS için genel engelleme güvencesi yoktur.

### DNS ve browser — best-effort

**Tarayıcı Discord ve DNS fail-closed değildir (P0-F/P0-G açık).** Çalışan hizmet listeli Discord adlarını tünel içi çözücüye yönlendirmeye çalışır; liste dışı sorgular, Windows DNS Client üzerinden kaybolan çağırıcı kimliği ve şifreli DNS/domain görünürlüğü kapsamı sınırlar. Hizmet durmuşken açık metin DNS ve browser Discord doğrudan bağlantıları kaydedildi.

### Korunmayanlar (bilinen fail-open pencereleri)

- **Kapsam dışı yollar.** Tarayıcı, özel konuma kopyalanmış Discord ve manifest dışındaki kurucu/yardımcılar için kalıcı engelleme güvencesi yoktur. Süreç/alan adı fallback yönlendirmesi doğrulanmış enrollment değildir; başarısız policy veya eksik keşif hazır koruma sayılmaz.
- **Yeni sürüm yarışı.** Yeni Discord sürümü ilk bağlantısından önce enrollment tamamlanmazsa doğrudan çıkabilir. Watcher/tarama gecikmeyi azaltır, ilk bağlantıyı engelleyen bir yürütme sınırı sağlamaz; hizmet durmuşken hazırlanmış sürüm de bir sonraki uzlaştırmaya kadar kapsanmayabilir. Helpers/installers yalnızca bilinen manifest yolları ve kapasite sınırları içinde kapsanır (P0-E kısmen açık).
- **Önceden açılmış bağlantılar.** Etkinleştirme veya sağlayıcı değişimi sonrasında Discord'u tepsiden tamamen kapatıp yeniden başlatın. Eski süreç kapısı kapsamı daraltır, paketle doğrulanmış TCP/UDP sonlandırma güvencesi vermez.
- **DNS, hizmet çalışmıyorken.** Discord'un `discord.com` gibi ad sorguları Windows DNS
  İstemcisi (svchost) üzerinden gider; WFP bunları Discord'a bağlayamaz. Hizmet
  çalışmıyorken bu sorgular ISS çözücüsüne açık metin gidebilir (bağlantının kendisi
  engellenmesi amaçlanır; kapsam sınırları yukarıdadır).
- **sing-box içindeki yönlendirme hatası.** Hizmet çalışırken bir Discord bağlantısının
  süreç bilgisi okunamazsa ve hedef bir Discord alan adı değilse sing-box onu `direct`
  çıkışa gönderebilir; bu soket `aurasplit.exe`'ye aittir, WFP onu Discord'a bağlayamaz.
- **Başka güvenlik yazılımları.** Daha yüksek ağırlıklı bir alt katmanda "hard permit"
  kullanan başka bir VPN/güvenlik duvarı Discord engelini aşabilir (test edilmedi).
- **Program dosyası silinirse.** Kalıcı kurallar kayıtlı yollar için kalır; bu tüm Discord trafiğinin engellendiği anlamına gelmez. Çözüm: aynı
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

GitHub özel güvenlik bildirimi yolunu kullanın: https://github.com/umut720s/aura-split-tr/security/advisories/new
(depo sayfasında **Security → Report a vulnerability**).

Mümkünse şunları ekleyin:

- Etkilenen sürüm (`aurasplit.exe version`) ve Windows sürümü
- Sorunun açıklaması, etkisi ve yeniden üretme adımları
- Günlükten ilgili satırlar. Paylaşmadan önce **kullanıcı adlarını** (ör.
  `C:\Users\<ad>\...` yollarında), bilgisayar adını, IP adreslerini ve paylaşmak
  istemediğiniz alan adlarını gizleyin. **`.conf` dosyası, `profile.json`, özel
  anahtar, preshared key veya WARP token göndermeyin.** Günlük bunları içermez,
  yine de gizli değer olmadığından emin olun. **Sansürlenmemiş günlükleri asla göndermeyin.**

Süreç (hedefler, garanti değildir): alındı bildirimi 7 gün içinde; ilk
değerlendirme 14 gün içinde; düzeltme ve eşgüdümlü açıklama en geç 90 gün içinde.
Düzeltme yayımlanana kadar ayrıntılar gizli tutulur; isterseniz bildirim
sahibi olarak anılırsınız. Desteklenen sürüm: yalnızca en son yayımlanan sürüm.

### English

**Experimental beta, not production-ready; unsigned exe/MSI and not independently packet-verified.** Testing used one Windows 11 x64 PC, initially IPv4-only Ethernet with Kaspersky Plus active, later two-NIC R3/R4 runs. Providers tested: WARP and Proton. The generic WireGuard option used a Proton config; other generic providers are not live-tested.

[Live results](docs/testing/phase3_live_results_2026-11-22.md): sampled Discord TCP used the TUN; stop/crash/outage observations do not prove UDP/DNS/IPv6/boot isolation. Run 4 verified the picker/start-up/network-change UX. Historical run 5 limited captures recorded stopped-service browser TLS and plaintext DNS escaping; run 6 recorded a pre-protection desktop TCP socket remaining direct. **No comprehensive packet-capture leak acceptance suite has been completed** (`tools/leaktest` exists). These observations do not establish leak-free operation.

R3 lost DNS/Internet with two NICs; R4 did not reproduce it with both NICs having Internet access. Health-aware egress failover was added afterwards and **has not been tested live**. If Internet breaks, use `aurasplit.exe stop` or `disable`; `disable` removes blocks and allows direct traffic. Do not run another VPN client's tunnel concurrently. Native IPv6, other PCs/AVs and forced MSI rollback/recovery failure paths remain unverified live.

Please report vulnerabilities **privately**, not as a public issue, discussion
or pull request:

Use GitHub private vulnerability reporting: https://github.com/umut720s/aura-split-tr/security/advisories/new
(**Report a vulnerability** on the **Security** tab).

Include the version (`aurasplit.exe version`), Windows version, impact and
reproduction steps. **Redact user names** (e.g. `C:\Users\<name>\...`), machine
names, IP addresses and host names from log lines, and never send `.conf`
files, `profile.json`, private/preshared keys, WARP tokens or unredacted logs. Targets: ack
within 7 days, triage within 14 days, fix and coordinated disclosure within
90 days. Only the latest release is supported.

Known limitations: browser Discord and DNS are **best-effort, not fail-closed (P0-F/P0-G open)**. Process-identity loss in the engine can route a Discord flow direct (P0-D open). Persistent WFP blocks cover only successfully enrolled manifest paths within capacity bounds, including known helpers and root/SquirrelTemp installers; they do not establish end-to-end isolation. New versions can connect before enrollment; custom/Downloads/other Temp paths have no persistent-block assurance. Fully quit Discord from the tray and restart it after enabling protection or changing providers: pre-existing connections may remain direct. Neither a successful connectivity probe nor `PROTECTION_READY` proves packet isolation.

See [README limitations](README.md#known-limitations), the [isolation audit](docs/audits/network_isolation_audit.md), [remediation plan / P0 progress](docs/audits/security_remediation_plan.md#p0-progress) and [multi-NIC analysis](docs/audits/r3_multinic_analysis.md). Experimental publication does not close findings or satisfy the security acceptance gate.

`stop` retains enrolled-program blocks and automatic startup. `disable`/`recover` disable/stop the service and remove blocks; Discord may then connect directly. If the installed exe is missing, verify and repair/reinstall the same MSI version, run `recover` as administrator and retry uninstall via Windows Apps. Unexpected/untrusted data and quarantine folders may remain for inspection. Downloaded configs also contain private keys; delete them after setup and never share them.

Verify each downloaded file's SHA-256 against the same release's `SHA256SUMS.txt` and its build provenance with `gh attestation verify <file> -R umut720s/aura-split-tr`. Do not run it if either check fails. These checks do not provide Authenticode signing or prove safety. **Never disable antivirus or add exclusions.** Report false positives to the AV vendor.
