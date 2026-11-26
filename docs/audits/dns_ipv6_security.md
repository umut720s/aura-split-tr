# DNS ve IPv6 güvenlik denetimi

Tarih: 2026-11-26 · İncelenen çalışma ağacı: `b5df99b` · Salt okunur kaynak denetimi.

## Yönetici özeti

**DNS dahil eksiksiz fail-closed hedefi sağlanmıyor.** Kalıcı WFP politikası envanterdeki Discord programlarının yeni IPv4/IPv6 bağlantılarını sınırlar; Windows DNS Client üzerinden yapılan sorguların sahibi ise Discord değildir. Servis durduğunda DNS adlarının fiziksel NIC'e çıkması kayıtlı canlı kanıtla doğrulanmış. Çalışırken de listelenmeyen adların sistem çözümleyicisinden ve tarayıcı/Windows şifreli DNS'inden çıkması için kodda engel yoktur. Tarayıcı Discord'u servis dışında kalıcı korumaya sahip değildir.

IPv6 filtreleri kodda mevcut; native IPv6 üzerinde güvenlik kanıtı yok. IPv6 yeteneği seçilen IPv4 çıkış adaptörüne göre belirleniyor. Olumsuz kararda global AAAA bastırma **ve tüm süreçleri kapsayan dinamik IPv6 engeli** uygulanıyor; ikinci adaptördeki geçerli IPv6 erişimi de etkilenebilir. IPv6'yı sistem genelinde kapatmak önerilen çözüm değildir.

## Kapsam

| Trafik sınıfı | Çalışan TUN içindeki sınıflandırma | Servis yokken kalıcı kapsam |
|---|---|---|
| Masaüstü Discord | Kurulum dizini regex'i veya dört istemci adı; ayrıca alan adı listesi | Yalnız keşfedilip AppID'ye çevrilmiş tam program yolları; Dnscache bu kapsamda değil |
| Güncelleyici / kurucular / yardımcılar | Standart Discord dizini altındaki bütün süreçler; `Discord*Setup*.exe` regex'i. `Update.exe` yalnız adla eşleşmez | Keşif yalnız kurulum kökündeki `Update.exe` ve `app-*` doğrudan altındaki `Discord*.exe` dosyalarını bulur; indirilen kurucular, `updater_launcher.exe` ve iç modül yardımcıları kapsam dışı |
| Tarayıcı Discord'u | Bütün süreçlerden listelenmiş adlar, sniff edilen ad veya reverse mapping | Tarayıcı AppID'si için kalıcı engel yok; site sekmesine özel kill switch yok |

Kaynak: `internal/engine/config.go:DiscordPathRegex:35`, `:DiscordInstallerRegex:40`, `:DiscordProcessNames:45`, `:DiscordDomains:55`, `:buildConfig:364`; `internal/wfp/discover.go:DiscoverIn:59`, `:discordExes:176`; `internal/wfp/policy.go:persistentFilters:434`; `internal/wfp/marshal_windows.go:buildFilter:104`.

25 Kasım kullanıcı gözlemi: `app-1.0.9270` istemcisinin örneklenen TCP soketleri TUN'da; kalıcı politika 2, tünel izni 3 program bildirmiş. Sürüm dizinindeki `updater_launcher.exe`, `modules\discord_utils-1\discord_utils\DiscordSystemHelper.exe`, `modules\discord_voice-1\discord_voice\audio_effects_helper.exe`, `modules\discord_voice-1\discord_voice\gpu_encoder_helper.exe` dosyaları bu keşifle kapsanmaz; sonuncusu çalışırken görülmüş. **Çalışıyor olması ağ kullandığını kanıtlamaz.** Sayılar tam yol envanteri yerine geçmez; yeni sürümdeki tek TCP örneklemesi yardımcıların DNS/UDP/IPv6 güvenliğini göstermez.

## Yöntem ve kanıt sınırı

`cmd/aurasplit`, `internal/engine`, `internal/wfp`, `internal/service`, `internal/paths`, `installer/AuraSplitTR.wxs`, `tools/leaktest`, `ARCHITECTURE.md`, mevcut audit raporları ve test planı/sonuçlarındaki ilgili akışlar incelendi. Eski raporların satırları ve eski açık bulguları güncel kod yerine kanıt sayılmadı. Build, Go komutu, test, capture, servis/WFP/TUN/rota/VPN işlemi veya internet taraması yapılmadı. Bu dosya tek yazma çıktısıdır.

Bağımlılık kaynak kısaltmaları, `%GOMODCACHE%/github.com/sagernet/` altında:

- **SB** = `sing-box@v1.14.4`.
- **ST** = `sing-tun@v0.9.7-0.20261023115432-040db71fcd33`.
- **SG** = `sing@v0.9.7-0.20261023115459-5dc452e537bf`.

`Verified (in code)` yalnız uygulanan mantığı; `Verified (live evidence)` kayıtlı gerçek gözlemi belirtir. **PASS** yalnız belirtilen gerçek gözlemin dar kapsamı içindir. Windows/Chromium kaynakları bu denetimde bulunmadığından onların sorgu başlatma, native DoH tercihleri ve Happy Eyeballs davranışı ayrıca **ASSUMPTION / NOT TESTED** olarak ele alınır. Kaynak kod, olası yolun önünü açtığını gösterir; o yolun bu PC'de seçildiğini göstermez.

### Kayıtlı canlı kanıt

| Kanıt | Bu denetimin değerlendirmesi |
|---|---|
| 22 Kasım Proton/WARP; boot sonrası istemci TCP'si TUN'da; stop/crash örneklemesinde Ethernet Discord TCP'si yok | **PASS — yalnız örneklenen TCP**. DNS/UDP ve boot başlangıcından itibaren paket yokluğu çıkarılamaz. Kaynak: `docs/testing/phase3_live_results_2026-11-22.md:S6/S14a/S11:19`, `:Live run 2:112` |
| Kablo çıkar/tak; yeniden bağlantı ve 0 off-TUN Discord TCP örneği | **PASS — kayıtlı TCP ve toparlanma**, DNS/IPv6 geçişi **NOT TESTED**. Kaynak: aynı dosya `:Live run 3:126`, `:Live run 4:140` |
| Aynı dosyanın sonradan eklenmiş Live run 5, L1+L4 | **PASS — görünür DNS/SNI/Host göstergesi yok**, raporlanan WG paketleri var; genel sızıntısızlık **INCONCLUSIVE**. Kaynak `:Live run 5:151`, özellikle `:157`; IPv4-only Ethernet, IPv6 unbound, Kaspersky Plus; IPv6 paketi yokluğu native IPv6 testi değildir |
| Live run 5 L2/L2b: stop sırasında fiziksel DNS adları; açık tarayıcı sekmesinden Discord TLS | **FAIL — DNS gizliliği ve servis dışı tarayıcı fail-closed**. L2b'de 9 DNS sorgusu ve 0 görünür Discord TLS/Host kayıtlı. Kaynak aynı dosya `:L2/L2b:158` |
| Live run 6: koruma öncesinde açılan bir Discord TCP soketi fiziksel NIC'te kalmış | **FAIL — önceden kurulmuş bağlantının hemen kesilmesi**; yalnız IPv4 gözlemi. `:Live run 6:163`, `:obs.:170` |
| 25 Kasım güncelleme gözlemi | **PASS — örneklenen yeni istemci TCP'si TUN'da**; DNS/UDP/IPv6 **NOT TESTED**. Kaynak: bu denetim için verilen kullanıcı gözlemi |

Görevdeki “TCP socket sampling paket yakalama değildir; DNS/UDP yakalanmadı” sınırı 25 Kasım gözlemine uygulanır. Depodaki Live run 5 ayrıca capture sonuçları kaydeder; bu bağımsız, tarihli kayıt burada açıkça ayrılmıştır. Ham capture incelenmedi, yeniden ölçüm yapılmadı. Ses kanalının çalışması UDP yolunun ölçümü değildir.

## Doğrulanmış DNS ve IPv6 mekanizması

1. `remote`, ilk uygun profil DNS IP'sine (yoksa `1.1.1.1`) port 53 üzerinden **`wg` detour** kullanır; DNS sunucusunun IPv6 seçimi host'a değil WG profilinde IPv6 adresi bulunmasına bağlıdır. `local` final çözümleyicidir. **Remote hata verince local'e geçiş kuralı yoktur.** Kaynak: `internal/engine/config.go:remoteDNSAddr:289`, `:tunnelDNSServer:300`, `:buildConfig:444`.
2. Remote UDP transport, TC yanıtında **aynı dialer ile TCP 53** dener; bu da WG detour'dadır. Local transport Windows adaptör DNS adreslerini port 53 olarak okuyup AURA sürecinden UDP, gerekirse TCP gönderir; Windows native DoH ayarını HTTPS transport'a çeviren yol burada yoktur. Dolayısıyla sistemde DoH açık olması AURA'nın `local` sorgularını şifreli yapmaz. Kaynak: `SB/dns/transport/udp.go:NewUDP:45`, `:ExchangeAsync:115`, `:exchangeTCP:176`; `SB/dns/transport/local/local_shared.go:serverSetFor:22`; `SB/dns/transport/local/systemconfig/source_windows.go:readConfig:81`.
3. Auto-route için varsayılan DNS modu hijack; TUN DNS'si adresin bir sonraki IP'sidir: IPv4 `172.19.0.2`, IPv6 varsa `fdfe:dcba:9876::2`. TUN'a gelen UDP DNS doğrudan hijack edilebilir; TCP DNS sniff ve `hijack-dns` ile işlenir. Kaynak: `ST/tun.go:DNSModeOrDefault:128`, `:Inet4DNSAddress:150`, `:Inet6DNSAddress:166`; `SB/protocol/tun/inbound.go:JudgeFlow:544`, `:NewDNSPacket:554`; `SB/route/dns.go:hijackDNSStream:20`, `:HijackDNSPacket:56`; `internal/engine/config.go:buildConfig:393`.
4. `strict_route` Windows'ta dinamik WFP oturumudur. AURA AppID'sine ağırlık 13 **hard permit**, TUN arayüzüne 11 soft permit, uzak port 53'e protokolden bağımsız 10 block ekler: UDP/TCP 53 kapsanır, 443/853 kapsanmaz. Bu genel DNS block'u kalıcı AURA politikasında yoktur. Kaynak: `ST/tun_windows.go:NativeTun.Start:213`, özellikle `:222`, `:250`, `:355`, `:398`; `internal/wfp/policy.go:persistentFilters:434`.
5. DNS sırası: host IPv6 yoksa **bütün AAAA** sorgularına boş NOERROR; sonra WG IPv6 yoksa korunan ad/süreç AAAA'larına boş NOERROR; sonra süreç yolu, süreç adı, alan adı eşleşmeleri remote veya block modunda reject; diğerleri local. Host IPv6 yokken block modundaki AAAA da reject'ten önce boş yanıtlanır: sorgu upstream'e gitmez. HTTPS/SVCB tipleri bu AAAA kuralıyla filtrelenmez; şifreli DNS ve istemci önbelleği de bu kuralın dışındadır. Kaynak: `internal/engine/config.go:buildConfig:372`, `:419`, `:428`, `:438`.
6. Host kararı, AF_INET varsayılan rota + arayüz metriği en küçük olan up/connected ve sanal/loopback olmayan adaptörü seçer. Yalnız o adaptörde preferred global IPv6 ve `::/0` birlikte varsa true; ULA, link-local, Teredo, 6to4 sayılmaz. Tablo okuma hatası başlangıçta false olur. Bu bir erişilebilirlik testi değildir; gateway'in gerçekten çalıştığını kanıtlamaz. Kaynak: `internal/engine/hostipv6.go:hostHasIPv6:51`, `:usableGlobalV6:101`, `:defaultV4Interface:116`, `:decideHostIPv6:151`; `internal/engine/hostipv6_windows.go:detectHostIPv6:17`; karşılaştırma `ST/monitor_windows.go:checkUpdate:157`.
7. True kararda TUN'a IPv6 verilir; ST tam adres uzayı kapsamından route exclusions çıkarır. Bunlar her zaman tek bir `::/0` satırı olarak görünmek zorunda değildir. `fc00::/7`, `fe80::/10`, `ff00::/8` hariçtir; uygulama rota kurallarındaki private→direct de süreç kuralından öncedir. Envanterdeki programın fiziksel IPv6 bağlantısını kalıcı V6 WFP block sınırlar; TUN içindeki yanlış `direct` kararı ise AURA AppID'siyle dışarı çıkar. Kaynak: `internal/engine/config.go:excludedRoutes:80`, `:buildConfig:393`, `:414`; `ST/tun_rules.go:BuildAutoRouteRanges:109`; `internal/wfp/policy.go:Layers:103`, `:persistentFilters:434`, `:tunnelFilters:455`; `internal/wfp/marshal_windows.go:buildFilter:104`.

## DNS/IPv6 yol tablosu

**R**: tünel çalışıyor (VPN peer erişilemiyor olsa da TUN mevcut olabilir). **B**: block config çalışıyor. **S/C/O**: stopped / crashed / boot'ta TUN başlamadan önce; kalıcı envanter politikasının önceden kurulmuş olması varsayılır. **G**: reconnect/rebuild sırasında eski TUN kapanmış, yenisi henüz hazır değil. **Fiziksel** aşağıda seçilen çıkış NIC'ini ifade eder; VPN iç paketi değil, şifreli WG dış paketi de fiziksel NIC'ten geçer. S/C/O/G'de Windows'un seçtiği gerçek DNS adaptörü bu denetimde ölçülmedi.

| Yol ve gönderen süreç | R | B | S / C / O | Reconnect / G | Kanıt / durum |
|---|---|---|---|---|---|
| Listeli Discord adı, Windows API → `svchost.exe`/Dnscache, UDP/TCP 53 | Dnscache→TUN DNS; yeniden sorguyu `aurasplit.exe`→WG içi DNS; dış NIC yalnız WG. Fiziksele bağlı alternatif :53 dinamik block | TUN DNS reject (host-v6 false AAAA boş); fiziksel :53 block | Dnscache→sistem DNS, fiziksel NIC mümkün; istemci bağlantısı engelli olsa da **ad çıkar** | Eski TUN varken R/B; G'de S gibi | config/strict-route kaynakları yukarıda; stop DNS **FAIL (live)**, crash/boot/G **NOT TESTED** |
| Listede olmayan ad; Discord/updater adına Dnscache UDP/TCP 53 | Dnscache→TUN; süreç svchost olduğundan final local; **AURA→adaptör DNS→fiziksel** | Aynı local yol; Discord çağırıcısı bilinmez | Dnscache→sistem DNS→fiziksel mümkün | TUN varken local; G'de sistem DNS | SEC-DNS-002; bu uygulamanın hangi ek adları istediği **NOT TESTED** |
| Uygulamanın kendi UDP/TCP 53 çözümleyicisi: doğru tanınan Discord/Update/kurucu | Uygulama→TUN→AURA→WG DNS; ad listede olmasa da süreç kuralı | TUN'da reject; fiziksel :53 dinamik block | Envanterdeki uygulama WFP ile block; keşfedilmeyen kurucu/yardımcı fiziksel DNS gönderebilir | Eski TUN varken R/B; G'de envanter block / kapsam dışı serbest | `SB/route/dns.go:hijackDNSStream:20`, `:HijackDNSPacket:56`; canlı TCP DNS **NOT TESTED** |
| Discord/Chromium'un kendi DoH (TCP/UDP 443) veya DoT (TCP 853) soketi | Sahibi Discord olarak bulunursa **bütün şifreli akış WG**; DNS içeriği hijack edilmez | Süreç kuralı reject | Envanter AppID block; envanter dışı kurucu/yardımcı fiziksele çıkabilir | G'de aynı envanter sınırı | SEC-DNS-003/V6-002; bu sürümün kendi DoH/DoT kullanımı **ASSUMPTION / NOT TESTED** |
| Tarayıcının DoH/DoT soketi: browser/network process | Resolver'ın adı Discord listesinde değilse TUN→AURA direct→fiziksel; sorgu adı şifreli, reverse map'e girmez | Genellikle aynı direct yol | Tarayıcı→fiziksel; Discord bağlantısına kalıcı engel yok | G'de doğrudan; eski TUN'da domain sınıflandırma sınırlı | SEC-DNS-003; gerçek resolver/DoH modu **NOT TESTED** |
| Windows native DoH: Dnscache/sistem çözümleyicisi | Seçilirse svchost→TUN→AURA direct→fiziksel 443; açık sorgu adı görülmez. Fiziksele doğrudan bağlanan 443 de :53 block'una takılmaz | Aynı; query içeriği domain reject'e görünmez | Seçilirse sistem süreci→fiziksel 443 | G'de aynı; TUN dönüşünde hangi resolver'ın seçileceği ölçülmedi | **ASSUMPTION**, AURA'da bunu zorlayan veya engelleyen kural yok; SEC-DNS-003 |
| İlgisiz uygulama, klasik sistem DNS | svchost→TUN→AURA local→adaptör DNS→fiziksel; global AAAA kuralı varsa upstream AAAA yok | Aynı | svchost→sistem DNS→fiziksel | Eski TUN/B mevcutken aynı; G'de sistem DNS | config: final local; ST :53 filtresi istisnası AURA; IPv4 dışındaki ağlar **NOT TESTED** |
| WG endpoint bootstrap: `aurasplit.exe` Windows resolver çağrısı; kabloda gönderen sistem resolver uygulamasına bağlı | İlk kurulum öncesi sistem DNS; rebuild hazırlığında eski TUN'un local yolu kullanılabilir. Amaç fiziksel underlay DNS | Retry'da B çalışırken local; peer Discord domain listesine girerse reject/remote döngüsü olasılığı ayrıca incelenmeli | O'da AURA başlarken sistem DNS→fiziksel; S'de çalışan AURA yok, C'de restart'a kadar yeni AURA sorgusu yok | Hazırlık eski TUN altında; literal IP kullanılır; iki lookup çağrısı cache'e rastlayabilir | `hostipv6.go:resolvePeerHost:15` **`LookupNetIP("ip")`**; `engine.go:probeEndpoint:286`; IPv4-only seçim **AAAA sorgusu hiç gönderilmez** demek değildir |
| Connectivity probe: `aurasplit.exe`, UDP 53 | `dialWG`→WG DNS, sonra HTTPS de WG; local fallback yok | Probe başlatılmaz | Çalışmaz | Eski probe kapanır, yenisi yeni tünelde; G'de çalışmaz | `probe.go:tunnelDial:117`, `:resolveViaTunnel:146`, `:dnsQuery:161`; `engine.go:startProbe:325`, `:Run/serve:499`; truncation'da probe hata verir, TCP retry yapmaz |
| Dnscache / uygulama cache hit | Yeni DNS paketi yok; bağlantı süreç/domain/sniff kurallarına bağlı | DNS paketi yok; süreç/domain reject'e bağlı | DNS paketi yok; envanter WFP bağlantı block'u sürer, browser serbest | Yeni AURA instance reverse map'i eskisini taşımaz; uygulama cache'i kalabilir | `ST/tun_windows.go:NativeTun.Start:209`, `:Close:619`; `SB/dns/router.go:NewRouter:116`; cache yokluğu güvenlik kanıtı değildir |
| Protected public IPv6 bağlantısı, doğru AppID ve doğru süreç sınıflandırma | Host-v6 true: uygulama→TUN→WG; WG IPv6 yoksa doğrudan fallback olmadan başarısız. Host-v6 false: ST global v6 block | TUN reject veya global v6 block | Envanterdeki programın yeni fiziksel v6 bağlantısı persistent block; browser/yardımcı kapsamı farklı | G'de envanter block; host yeteneği değişiminde karar gecikebilir | V6 WFP kodu doğrulanmış; native IPv6, dual-stack gerçek yol **NOT TESTED** |

**Cache ayrımı:** ST normal Start/Close sırasında Windows resolver cache'ini flush etmeyi çağırır. Crash'te `Close` çalışacağı varsayılamaz; tarayıcı/Discord iç cache'ini temizleyen uygulama kodu yoktur. Önceden cache'lenmiş ad hiç DNS paketi oluşturmadan bağlantı kurdurabilir; flush ise stop sonrasında yeniden ad sorgulanmasına yol açabilir. DNS leak bağlantı/mesaj/credential leak kanıtı değildir; kendi başına alan adı/zaman bilgisi kaybıdır.

LLMNR/mDNS/NetBIOS, standart UDP/TCP 53 hijack'iyle aynı kapsamda değildir; multicast/link-local/broadcast exclusions vardır (`config.go:excludedRoutes:80`). Discord'un bu protokolleri kullandığı veya Discord adlarını bunlarla sızdırdığı doğrulanmadı.

## Bulgular

**SEC-DNS-001** | Severity: Medium | Component: Servis dışı ve rebuild aralığı DNS gizliliği

**Source:** `internal/wfp/policy.go:persistentFilters:434`; `ST/tun_windows.go:NativeTun.Start:222`, `:398`, `:Close:619`; `internal/engine/engine.go:Run/closeCurrent:509`, `:Run/block:632`; `docs/testing/phase3_live_results_2026-11-22.md:Live run 5/L2b:159`.

**Root cause:** Kalıcı filtreler yalnız program AppID'siyle eşleşir. Dnscache'in sorguları Discord AppID'si taşımaz. Genel :53 koruması TUN'un dinamik oturumuyla kalkar; boot/G penceresini kapsayan ad politikası yoktur.

**Leak scenario:** Discord'un sistem çözümleme isteği, bağlantısı WFP'de engellense bile servis stop olduğunda fiziksel DNS'ye gider. Crash, boot-before-TUN ve rebuild gap'te aynı izin boşluğu vardır; bu durumlarda fiilen sorgu oluşması ölçülmedi.

**Impact (traffic / DNS / credential):** DNS adları/zaman bilgisi açığa çıkar. Bu bulgu masaüstü Discord TCP verisinin veya credential'ın çıktığını göstermez.

**Fix:** Listeli Discord suffix/exact host'ları için servis ömründen bağımsız, çakışma denetimli ve rollback destekli NRPT + sürekli yerel resolver tasarla: resolver yalnız WG hazırken upstream'e çıksın, yokken cevap vermesin/reject etsin. Native DoH ve üçüncü taraf DNS proxy etkileşimini ayrıca doğrula. Tüm svchost DNS'sini kalıcı engellemek ilgisiz uygulamaları bozar; NRPT de istemcinin kendi DoH'sini tek başına çözmez.

**Verification:** Leaktest **L2**, browser kapalı ve açık ayrı; ardından **L3** rebuild gap, crash ve boot-before-TUN varyantları. Yetkili bakımcı cache sıcak/soğuk A/AAAA ile UDP/TCP 53'ü fiziksel tüm çıkışlarda kontrol etmeli. Ad görülürse bağlantı engelli olsa da DNS sonucu **FAIL**. Stop **FAIL (recorded live)**; crash/boot/G **NOT TESTED**.

**Status: Verified (in code and live evidence).**

**SEC-DNS-002** | Severity: Medium | Component: Dnscache attribution ve local DNS çıkışı

**Source:** `internal/engine/config.go:buildConfig:403`, `:438`, `:478`; `SB/route/dns.go:HijackDNSPacket:56`; `SB/common/process/searcher_windows.go:FindProcessInfo:38`; `SB/dns/transport/local/systemconfig/source_windows.go:readConfig:81`; `SB/dns/transport/local/local_shared.go:serverSetFor:22`.

**Root cause:** DNS kuralı sorguyu başlatan Discord API çağrısını değil, paketi gönderen svchost'u görür. Yalnız listeli adlar remote'a gider; diğer adlar AURA'nın hard-permit'li local transport'undan açık UDP/TCP 53 olarak çıkar. Windows native DoH yapılandırması bu local transport'u otomatik DoH yapmaz.

**Leak scenario:** Discord/güncelleyici üçüncü taraf CDN/telemetri veya yeni bir alan adı için sistem DNS ister; ad listede değilse VPN sağlıklıyken veya block modunda bile fiziksel DNS'ye gönderilir. Bu sürümün böyle bir sorgusu yakalanmış değildir.

**Impact (traffic / DNS / credential):** Korunan sürecin listelenmeyen DNS adları sızabilir; uygulama bağlantısı ayrıca WG'ye gidebilir veya block olabilir. Credential sızıntısı kanıtı yok.

**Fix:** “Korunan uygulamanın tüm DNS'si” gerekiyorsa çağırıcı kimliğini koruyan uygulamaya özgü resolver/proxy ya da ayrı ağ ortamı kullan. Listeli domain NRPT yalnız bilinen adları kapatır; liste güncellemesini tam süreç DNS izolasyonu olarak sunma. İlgisiz uygulamaların DNS'sini topluca VPN'e taşımak split hedefini değiştirir.

**Verification:** **L1/L3**, updater için ayrı tekrar; kontrollü, liste dışı test adıyla sistem API DNS ve uygulamanın kendi UDP/TCP DNS'sini karşılaştır. Sorgu sahibini özel yerel trace ile ilişkilendir; genel NIC capture tek başına çağırıcı API sürecini kanıtlamaz. **NOT TESTED**.

**Status: Verified (in code); gerçek Discord ek ad sorgusu Not tested.**

**SEC-DNS-003** | Severity: High | Component: Şifreli DNS ve tarayıcı Discord fail-closed kapsamı

**Source:** `ST/tun_windows.go:NativeTun.Start:398`; `internal/engine/config.go:buildConfig:393`, `:438`, `:498`; `internal/wfp/discover.go:DiscoverIn:59`; `SB/route/route.go:prepareMatchMetadata:572`, `:actionSniff:736`; `docs/testing/phase3_live_results_2026-11-22.md:Live run 5/L2:158`.

**Root cause:** :53 block ve DNS hijack TLS/HTTPS içindeki sorguyu göremez. Browser ve Windows resolver soketleri Discord süreç kuralına girmez. Tarayıcı fail-closed'u görünür domain/sniff/reverse map'e bağlıdır, kalıcı site engeli yoktur.

**Leak scenario:** Browser DoH/DoT veya native DoH, listelenmemiş resolver'a direct gider. Çözülen Discord adı map'e girmez; sonraki akışın SNI'si görünürse yine WG'ye gidebilir, fakat ECH/düşük sniff görünürlüğünde direct'e düşebilir. Servis kapalıyken browser Discord TLS'nin fiziksel NIC'e çıkması zaten kayıtlıdır. Discord.exe'nin **kendi** DoH/DoT akışı doğru süreç atfıyla WG'ye gider; Windows üzerinden yaptığı DoH aynı güvenceyi almaz.

**Impact (traffic / DNS / credential):** Resolver Discord sorgu adını ve direct bağlantı kaynağını öğrenebilir; fiziksel ağ şifreli DNS'in iç adını otomatik göremez. Tarayıcı Discord trafiği VPN dışında çıkabilir; HTTPS/TLS credential içeriğinin açıkta olduğunu göstermez. ECH kullanımı bu PC/Discord domain'lerinde doğrulanmadı.

**Fix:** Tarayıcıda tam fail-closed vaat edilecekse ayrı browser instance/profilini kimliği korunmuş proxy/ağ izolasyonu üzerinden zorunlu WG'ye bağla ve onun AppID'sine kalıcı off-tunnel engel uygula. İlgisiz sekmeleri direct tutmak için siteyi güvenilir şekilde ayıran browser entegrasyonu gerekir; mevcut IP/SNI yaklaşımı şifreli adlarda yeterli değildir. Native DoH için desteklenen domain politikası ve bypass testini ekle; rastgele bütün browser 443/853'ünü engelleme.

**Verification:** **L4** R/B/S/C/O/G durumlarında, browser Secure DNS kapalı/açık/custom, DoT ve native DoH ayrı; **L3** reconnect. Resolver kontrollü kayıtları ve süreç/adapter korelasyonu gerekir: analyzer'ın 0 göstergesi şifreli DNS/ECH için PASS değildir. Servis dışı browser **FAIL (recorded live)**; çalışan DoH/ECH/native DoH **NOT TESTED**.

**Status: Verified (in code and service-stopped live evidence); çalışan şifreli-DNS/ECH kombinasyonları Suspected.**

**SEC-DNS-004** | Severity: Medium | Component: reverse_mapping ve cache üzerinden domain kimliği

**Source:** `internal/engine/config.go:buildConfig:481`; `SB/dns/router.go:NewRouter:116`, `:recordReverseMapping:1121`, `:LookupReverseMapping:1385`; `SB/route/route.go:prepareMatchMetadata:605`, `:actionSniff:736`; `ST/tun_windows.go:NativeTun.Start:209`, `:Close:619`.

**Root cause:** Map en fazla 1024 IP→tek ad girdisi tutar; A/AAAA **record owner** ve TTL kaydeder, istemci/çağırıcı veya orijinal sorgu kimliği tutmaz. Aynı IP için yeni yanıt önceki adı değiştirir; CNAME zincirinde kaydedilen owner liste dışı CDN adı olabilir. Yeni instance'da eski map yoktur; uygulama cache'i kalabilir.

**Leak scenario:** DoH/cache nedeniyle hiç görülmemiş veya başka adla ezilmiş ortak CDN IP'sine giden ve güvenilir SNI sunmayan browser Discord akışı direct olur. Tersi durumda ilgisiz uygulama aynı IP için Discord adı devralıp WG'ye/reject'e gidebilir. Doğru süreç atıflı masaüstü istemci/güncelleyici önce süreç kuralıyla eşleşir; bu map'e güvenmek zorunda değildir.

**Impact (traffic / DNS / credential):** Browser VPN dışı trafik veya ilgisiz uygulamanın yanlış yönlendirilmesi/erişim kaybı; mevcut ölçümlerle gerçekleşmiş sızıntı kanıtı yok. DNS sorgusu olmaması güvenlik kanıtı değildir.

**Fix:** Reverse map'i güvenlik sınırı olarak kullanma. Korunması gereken browser trafiği için sorgu/bağlantı kimliğini koruyan proxy veya dikkatle tasarlanmış FakeIP yaklaşımı kullan; cache/restart ve shared CDN ayrımını doğrula. Yalnız map'i kapatmak bilinmeyen akışın direct olmasını düzeltmez.

**Verification:** **L4/L3**: aynı IPv4/IPv6'ya dönen iki kontrollü host, sorgu sırasını ters çevirme, CNAME owner, TTL bitişi/kapasite, uygulama cache'i sıcak ve TUN rebuild; ECH/sniff edilemeyen akış. İlgisiz host direct kalmalı, korunan host WG veya block olmalı. **NOT TESTED**.

**Status: Verified (in code); gerçek ağdaki yanlış sınıflandırma Not tested.**

**SEC-V6-001** | Severity: Medium | Component: Global IPv6 engeli / AAAA bastırma ve ağ geçişleri

**Source:** `internal/engine/hostipv6.go:hostHasIPv6:51`, `:decideHostIPv6:151`; `internal/engine/config.go:buildConfig:414`, `:419`; `ST/tun_windows.go:NativeTun.Start:300`; `internal/engine/engine.go:hostCheckInterval:304`, `:Run/serve:486`, `:494`, `:535`, `:546`; `internal/engine/network.go:canRebuild:16`.

**Root cause:** Tek seçili IPv4 çıkışının IPv6 yeteneği bütün host için kullanılır. False olduğunda ST'nin V6 ALE block'u **tüm uygulamalara** uygulanır (AURA hard permit ve belirli NDP permit istisnaları); global AAAA boşaltma da ilgisiz uygulamalara uygulanır. İzleme 60 saniyede bir bool karşılaştırır; çalışma sırasındaki okuma hatasını yok sayar. Rebuild en sık 2 dakikada bir ve kullanılabilir fiziksel IPv4 şartıyla yapılır.

**Leak scenario:** Bu bulgu birincil olarak erişim kaybıdır: IPv4-only Ethernet seçiliyken başka adaptörde geçerli IPv6 bulunsa bile uygulamaların yeni IPv6 bağlantıları engellenir. IPv6 sonradan gelirse yeni karara kadar blok sürer; IPv6 giderse eski TUN IPv6'yı kabul edip AURA direct çıkışında hata verebilir. Aynı adaptörde gateway/adres değişip true→true kalırsa bu watcher rebuild istemez; IPv6'ya özel arıza, IPv4-first probe başarılı kaldığında fark edilmeyebilir.

**Impact (traffic / DNS / credential):** İlgisiz uygulamalar için IPv6/AAAA davranışı sistem genelinde değişir, IPv6-only hedefler erişilemez olabilir. Happy Eyeballs IPv4 alternatifi bulursa etkisini gizleyebilir; cache/DoH'den gelen AAAA'nın bu DNS filtresini görmemesi fallback veya bypass güvenliği kanıtı değildir. Doğru envanter V6 WFP block'u bu gecikme yüzünden kendiliğinden kalkmaz.

**Fix:** Aileye göre gerçek çıkış seçimi ve olay tabanlı adres/rota takibi tasarla; hazır olmayan IPv6'yı yalnız korunan trafik için block et. İlgisiz süreçleri engelleyen ST no-v6 filtresini kaldırmak/değiştirmek, korunan süreç V6 WFP kapsamı ve direct IPv6 yoluyla birlikte doğrulanmalı. IPv6'yı sistem genelinde kapatmayı varsayılan çözüm yapma; capability okuma hatasını görünür degraded durumu yap.

**Verification:** **L1/L3/L4** native dual-stack + ikinci NIC; IPv6 global adres/default route ayrı ayrı eklenip kaldırılır, aynı NIC gateway değişir, IPv4 default NIC değişir; geçiş 60 s ve rate-limit boyunca ölçülür. Browser Happy Eyeballs, literal IPv6, IPv6-only kontrol hedefi ve ilgisiz uygulama IPv6 erişimi ayrı kontrol edilir. Bu varyantlar **NOT TESTED**; IPv4-only YouTube düzeltmesinin kullanıcı gözlemi **PASS**, bu çoklu-adaptör durumunu kanıtlamaz.

**Status: Verified (in code); native IPv6/çoklu adaptör etkisi Not tested.**

**SEC-V6-002** | Severity: High | Component: TUN içi süreç atfı başarısızlığı; dual-stack DNS/bağlantı yolu

**Source:** `SG/common/winiphlpapi/helper.go:FindPid:74`; `SB/common/process/searcher_windows.go:FindProcessInfo:38`; `SB/route/process_cache.go:searchProcessInfo:38`; `internal/engine/config.go:buildConfig:393`, `:438`, `:498`; `ST/tun_windows.go:NativeTun.Start:250`.

**Root cause:** FindPid kaynak adres ailesine göre yalnız IPv4 **veya** IPv6 TCP/UDP tablosunu arar; UDP wildcard eşleşmesi vardır, iki aile arasında fallback yoktur. Süreç bulma hatası reject üretmez. Domain eşleşmesi de yoksa final direct/local seçilir. Yeniden gönderilen soketin sahibi AURA olduğundan korunan AppID block'u onu durdurmaz.

**Leak scenario:** TUN'a girmiş Discord soketinin sahibi bulunamaz ve hedefi listelenmiş/görünür domain değilse bağlantı AURA direct çıkışına gider; kendi açık DNS'si de local'e düşebilir. AF_INET6 dual-stack soketinin IPv4 peer'e giderken yalnız v6 tabloda bulunması olası bir tetikleyicidir, **bu Windows sürümünde kanıtlanmış değildir**. Tablo erişim/race hatası da aynı kod yoluna ulaşır. Native IPv6'daki gerçek atıf başarısı ölçülmedi.

**Impact (traffic / DNS / credential):** Korunan süreçten türetilmiş IPv4/IPv6 trafik veya DNS fiziksel çıkışa taşınabilir. TLS credential gizliliği ayrıca korunabilir; credential çalındığı iddia edilmez. Etki yüksek, fakat dual-stack tetikleyiciye ait canlı exploit kanıtı yoktur.

**Fix:** Kaynak süreç kimliğini yönlendirme boyunca taşıyan mekanizma kullan; belirsiz akışta direct/local'e sessiz fallback yapma. Yalnız “bilinmeyen bütün süreçleri block” seçimi ilgisiz uygulama hedefini bozar; family-normalization/cross-table eşleme ve belirsiz korunan akışın ayrılması birlikte ele alınmalı. Alan adının listede olması süreç atfı hatasını her hedef için kapatmaz.

**Verification:** **L1/L3**, kontrollü Discord kapsamındaki süreçle AF_INET/AF_INET6 TCP/UDP, dual-stack IPv4-mapped ve wildcard UDP varyantları; listeli ve liste dışı hedef; kontrollü process-search hata enjeksiyonu yalnız izole test ortamında. Owner/adapter korelasyonu ve fiziksel capture gerekir. Synthetic config testi gerçek yol için PASS değildir. **NOT TESTED**.

**Status: Verified (in code: fail-open hata yolu); dual-stack kaynaklı tetiklenme Suspected.**

## Açık sorular ve tamamlanması gereken kanıt

- Native IPv6 üzerinde envanter V6 filter enforcement, TUN permit, WG IPv6 profil desteği ve fiziksel adaptöre explicit bind gerçek paketle ölçülmedi. Route tablosu tek başına WFP enforcement kanıtı değildir.
- Windows native DoH gerçekten etkin mi; Dnscache TUN DNS'siyle onu paralel/öncelikli kullanıyor mu; browser/Discord sürümleri kendi encrypted DNS'lerini kullanıyor mu? Bu denetim host ayarını okumadı veya değiştirmedi. HTTPS/SVCB ECH ve IPv6 ipuçları, cache ve Happy Eyeballs ayrı ölçülmeli.
- Kurucu/updater/helper gerçek ağ sahipleri nelerdir? İç modül yardımcılarının off-TUN IPv4/IPv6/DNS kullanıp kullanmadığı bilinmiyor. Bilinen dosya varlığı otomatik kalıcı WFP koruması sağlamıyor; servis dışında browser/kurucu/yardımcı “korunuyor” denemez.
- Boot capture ilk DNS trafiğinden itibaren başlamalı; BFE bağımlılığı yalnız AURA'nın BFE'den sonra başlamasını sağlar (`installer/AuraSplitTR.wxs:ServiceInstall:153`), kalıcı provider'ın boot-time DNS isim izolasyonu yaptığı anlamına gelmez. Profil/politika hiç kurulmamış fresh MSI başlangıcı ile önceden korunmuş boot ayrılmalı (`cmd/aurasplit/setup.go:runSetup:224`).
- Rebuild hazırlığı eski instance altında; permit sonra eski TUN kapanır; G'de envanter bağlantı engeli kalır, dinamik DNS filtresi kalmaz (`engine.go:Run/prepareTunnel:425`, `:Run/serve:552`, `:570`). Bu aralık ve block-mode DNS yolu gerçek capture ile ölçülmeli; yalnız TCP socket sayımı yeterli değil.
- Leaktest L1–L4 yalnız görünür göstergeleri çıkarır. UDP/TCP 53 çözülür; DoH/DoT içerikleri, ECH ve QUIC SNI çözülmez; snaplen 256 bayt, cache ve kayıp paketler negatif kanıtı sınırlar (`tools/leaktest/analyze.py:analyze:253`, `:333`, `:381`, `:402`; `tools/leaktest/README.md:Senaryolar:69`). Native IPv6 sayacı Discord sızıntısı demek değildir. Şifreli yollar için kontrollü resolver/endpoint ve yerel süreç korelasyonu olmadan sonuç **INCONCLUSIVE** kalmalıdır.

Yeni testlerin hepsi bakımcı tarafından ayrıca yetkilendirilmiş ortamda yapılmalıdır; burada hiçbiri çalıştırılmadı. Ham paketler, gerçek kullanıcı IP'leri, anahtarlar ve kullanıcı yolları bu rapora alınmadı.
