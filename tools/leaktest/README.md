# AURA Split TR — fiziksel NIC sızıntı testi

Bu araçlar yalnızca Ethernet üzerindeki **görünür ad göstergelerini** ölçer.
Sıfır gösterge, sızıntı olmadığının kesin kanıtı değildir. Gerçek capture burada
çalıştırılmadı. Windows 11 x64, Windows PowerShell 5.1 ve Python 3 stdlib yeterli;
Npcap/Wireshark, paket kurulumu veya analiz sırasında ağ erişimi gerekmez.

## Çalıştırma (bakımcı)

Capture için **yönetici olarak açılmış Windows PowerShell** kullanın. Mevcut bir
pktmon oturumu olmamalı: script pktmon'u durdurur ve tüm global filtreleri siler.
`aurasplit.exe` PATH'te, mevcut dizinde veya `%ProgramFiles%\AuraSplitTR` altında
olmalı. Script AURA servis durumunu değiştirmez. Başka konumdaysa önce o dizine geçin.

```powershell
# Repo kökünden, yönetici PowerShell'de; komut çalışırken senaryoyu uygulayın.
.\tools\leaktest\capture.ps1 -Scenario L1 -Seconds 120 -Adapter Ethernet -OutDir C:\AuraTest\evidence\leak
```

Betik fiziksel adaptörü `Get-NetAdapter -Physical` ile doğrular; MAC adresini
`pktmon comp list --json`, desteklenmiyorsa `pktmon list` ile eşleştirir.
Tekil component ID bulunamazsa yakalama başlamaz. Port/adres filtresi eklenmez:
`--comp <id>` fiziksel NIC kapsamını belirler, DNS/TLS/IPv6'nın tamamı incelenebilir.
256 bayt snaplen, 1024 MB segment eşiği ve multi-file modu kullanılır; dönen/eski
paketleri silen circular mod kullanılmaz. Birden çok segment oluşursa kısmi analiz
üretmek yerine betik hata verir; daha kısa süreyle tekrarlayın. Pktmon aynı paketi
birden çok yönde/kenarda gösterebilir: sayılar dosyadaki kayıt sayılarıdır.

Başarıda `.pcapng` ve aynı taban adında `.json` metadata kalır, ETL silinir;
son satır pcapng yoludur. Metadata `Sunucu:` satırındaki IP:port'u, adaptör IP'lerini
ve başlangıç/bitiş zamanını içerir. Endpoint okunamazsa uyarı verir ve hiçbir
akış beyaz listeye alınmaz (özellikle servis durmuşken mümkün). Status hostname
döndürürse çevrimdışı çözümleme yapılmaz. Metadata eksik endpoint'i elle doldururken
**testteki gerçek WireGuard IP ve portunu** kullanın. `wireguard_endpoint` biçimi:
`{"ip":"198.51.100.9","port":51820}`. Yalnız bu uzak uçla UDP trafiği istisnadır;
aynı IP'ye TCP veya farklı porta UDP istisna değildir. Endpoint değişirse yeni capture
alın; tek sidecar tek endpoint içindir.

Hata/iptal sırasında `finally` içinde stop ve filtre temizliği ayrı ayrı denenir.
Başarısız dönüşüm/çoklu segment durumunda özel ETL dosyaları hata incelemesi için
kalır; bunları paylaşmayın. Terminalin zorla öldürülmesi veya güç kesilmesinde
`finally` garantisi yoktur; bakımcı `pktmon stop` ve `pktmon filter remove` uygulamalıdır.

Analiz yükseltme gerektirmez:

```powershell
python -I .\tools\leaktest\analyze.py C:\AuraTest\evidence\leak\L1_<timestamp>_<id>.pcapng
# İsteğe bağlı: --metadata <sidecar.json> --json <report.json> --local-ip 192.0.2.10
# Sentetik testler; gerçek capture/ağ yok:
Set-Location .\tools\leaktest
python -I -m unittest
```

Analizör her seferinde bir capture işler; varsayılan JSON raporu
`<capture>.report.json`, metadata `<capture>.json` olur. pcapng (iki byte order,
çoklu section/interface, EPB/SPB/eski packet block) ve klasik pcap (mikro/nanosaniye),
Ethernet, iç içe VLAN, IPv4, IPv6 uzantıları, UDP/TCP desteklenir. DNS UDP/TCP 53
sorguları, TCP'nin ilk ClientHello SNI'si (her port), ilk HTTP/1.x istek Host'u ve
UDP 443 aday akışları raporlanır. TCP sıra numarasıyla sınırlı birleştirme,
tekrar iletim ve sırasız segment desteği vardır. DNS/SNI/Host kayıtları akış/ad
bazında tekilleştirilir; toplam paket sayısı tekilleştirilmez. IPv6 ND/MLD yerel
kontrol gürültüsü ayrı sayılır; diğer IPv6 paketleri ana IPv6 sayacındadır.

Çıkış kodları: **0** görünür Discord göstergesi yok; **2** WG akışı dışında
Discord DNS/SNI/Host var; **1** dosya/metadata/rapor yazma veya capture formatı hatası.
L2'de bilinen DNS sınırlaması da **2** üretir; sessizce PASS'e çevrilmez.
Kırpılmış paketler format hatası sayılmaz, kapsam uyarısıyla raporlanır.

## Senaryolar

Her senaryoyu ayrı capture ile çalıştırın; capture başladıktan sonra eylemi yapın.
Servis kontrol komutlarını bakımcı ayrı terminalde uygular. Tablo beklentileri
ölçülmüş sonuç değildir; test planının izin/ortam kuralları ayrıca geçerlidir.

| Senaryo | İşlem | Beklenti / kayıt |
|---|---|---|
| L1 | Servis çalışırken Discord'u açın, 30 saniye ses kanalına katılın; ilgisiz bir site açın. | Ethernet'te Discord DNS/SNI/Host yok; WG endpoint paketleri **var**. WG sayısı 0 ise test kanıtı yetersizdir; analizör bunu otomatik PASS saymaz. |
| L2 | Bakımcı `aurasplit.exe stop` uygular; capture sırasında Discord'u açar. | Discord TLS/SNI/Host yok. Windows DNS Client üzerinden Discord DNS adları **görünebilir**: bilinen sınırlama, adları ve kod 2'yi kaydedin. |
| L3 | Servis çalışırken capture boyunca kabloyu çıkarıp tekrar takın, Discord bağlantısını gözleyin. | Bağlantı kesintisinde/yeniden kurulurken Discord DNS/SNI/Host fiziksel NIC'e kaçmamalı; zamanları ve WG'nin geri dönmesini kaydedin. |
| L4 | Servis çalışırken tarayıcıdan `https://discord.com` açın. | Görünür Discord SNI Ethernet'te yok. ECH/QUIC etkinse SNI görünmemesiyle yönlendirme doğrulanamaz; bunu kaydedin. |

## Sınırlar ve gizlilik

- **QUIC SNI çözümlenmez:** Initial secrets DCID'den türetilebilir, ancak header
  protection AES-128-ECB ve payload AES-128-GCM gerektirir; Python stdlib AES sağlamaz.
  UDP hedef port 443 akışları hedef IP ile `sni: "unparsed"` olarak listelenir;
  bunların QUIC olduğu veya Discord'a ait olduğu iddia edilmez.
- 256 bayt her DNS sorusuna/ClientHello'ya yetmez. SNI uzantısı erken ve tam ise
  kaydın kalanı kırpılmışken de okunabilir. Sonraki TCP paketleri kayıp baytları
  tamamlayamaz. ECH, DoH/DoT, HTTP/2/3, IP fragmentleri, capture öncesi kurulmuş
  bağlantılar, önbellek ve paket kaybı adları gizleyebilir. IPv6 sayısı tek başına
  Discord sızıntısı değildir. DNS bulgusu bağlantı kurulduğunu kanıtlamaz.
- TCP birleştirme yön başına 256 KiB / 2048 segment ve toplam 4096 akışla sınırlı;
  atlanan baytlar/gap'ler uyarılır. IP fragmentleri sayılır, birleştirilmez.
- Capture ve sidecar IP'ler/ziyaret edilen adlar içerir. **Repo dışında** tutun;
  script repo içi OutDir'i reddeder. Ham ETL/pcapng veya sidecar paylaşmayın.
  Yalnız **`.report.json`** paylaşın: sidecar'daki yerel IP'ler `<local>` olur;
  sidecar/local-ip yoksa güvenli varsayılan tüm IP'leri maskeler. Ek yerel
  adresler için `--local-ip` tekrarlanabilir. Host adları ve uzak IP'ler de özel
  bilgi olabilir; paylaşmadan önce raporu inceleyin. Script paket payload'larını
  yazdırmaz; analizör sadece çıkarılan DNS/SNI/Host adlarını gösterir.

## English quick start

Maintainer only: run `capture.ps1 -Scenario L1` in elevated Windows PowerShell;
perform L1–L4 above during capture. Analyze offline, unelevated with
`python -I tools/leaktest/analyze.py <capture.pcapng>`.
Run synthetic tests from `tools/leaktest` with `python -I -m unittest`.
Exit 0 = no visible Discord indicators, 2 = Discord DNS/SNI/Host outside the WG
endpoint UDP flow, 1 = parse/I/O error. QUIC SNI, ECH and encrypted DNS remain blind
spots; a clean report does not prove absence of leaks. Keep captures and metadata
outside Git; share only the reviewed, local-IP-masked `.report.json`.
