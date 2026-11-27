# R3 multi-NIC investigation

Scope: R3-4/R3-5 observations in the live results, not a reproduction. No
services, TUN devices, routes or filters were changed during this investigation.
Dependency paths below are relative to `go env GOMODCACHE`, with versions from
go.mod: `github.com/sagernet/sing-box@v1.14.4` (SB),
`github.com/sagernet/sing-tun@v0.9.7-0.20261023115432-040db71fcd33` (ST),
`github.com/sagernet/sing@v0.9.7-0.20261023115459-5dc452e537bf` (S).

## Ranked candidates

1. **Selected interface has no usable Internet path, despite a connected link.**
   ST `monitor_windows.go:185-243` selects the first lowest IPv4 route metric
   plus interface metric, skipping down/disconnected/virtual/loopback interfaces.
   It does not test Internet reachability or NCSI. R3's lower-metric Ethernet
   reported NoTraffic while Wi-Fi reported Internet. SB
   `common/dialer/default.go:103-144` and `route/network.go:340-364` bind direct
   public sockets to that selection (connected-subnet destinations differ below).
   `wg-direct` uses the same dialer. This explains both literal direct timeouts
   and resolver failure, but NCSI alone is not proof of a broken path. Equal
   subnet membership alone does not prove an upstream routing defect either.
2. **DNS server collection and chosen egress disagree.** SB
   `dns/transport/local/systemconfig/source_windows.go:89-169` collects DNS
   servers from ALL up, gateway-bearing, non-tunnel adapters, excluding its own
   interfaces. It does not select only the default NIC's servers or retain
   per-server interface binding. `local_shared.go:38-47,95-119` builds transports
   with one shared dialer and tries servers sequentially; a nonworking first
   server delays the next by the five-second timeout, twice. SB
   `dns/transport_dialer.go:11-16` uses ordinary dialer options, so auto detection
   applies here too. In particular S `common/control/bind_finder_default.go:113-135`
   first matches exact local addresses, then the FIRST running interface prefix
   containing the destination, without route metrics. With equal subnets, a router
   DNS can bind to a different NIC than the metric-selected default; public DNS
   still uses the default. A router DNS learned on Wi-Fi can therefore be queried
   via Ethernet, or the reverse. This can explain DNS failures/delays, but by itself does not explain
   timeouts dialing literal public addresses.
3. **Non-AURA filtering / same-subnet host routing interaction.** Disconnected
   third-party VPN software and an active antivirus were present in R3. No
   source or packet evidence identifies either as the cause. Dual NIC source
   address / return-path asymmetry is also possible. Need packet and socket
   evidence before changing interface selection policy.
4. **Windows iletme / zayıf host etkileşimi (canlı kanıtla daha düşük olasılık).**
   ST `tun_bind_windows.go:31-63`, iletme açık arayüzlerde Windows'un soket
   arayüz bağlamasını yok sayıp çıkışı yeniden TUN'a yönlendirebildiğini belirtir.
   Kaynak mekanizmayı doğrular; R3'ün nedenini doğrulamaz. Kullanıcının sağladığı
   canlı ölçümde Ethernet ve Wi-Fi için IPv4 Forwarding=Disabled,
   WeakHostSend=Disabled ve WeakHostReceive=Disabled idi. Ölçüm sırasında Wi-Fi
   bağlantısı kesikti; ICS hizmeti çalışıyordu. Bu oturumda canlı ölçüm yapılmadı.
   ICS'nin çalışması tek başına arayüzde forwarding açık olduğunu kanıtlamaz.
   Ölçüm bu mekanizmayı zayıflatır; iki arayüz de bağlıyken IPv4 ve IPv6
   durumları yeniden kontrol edilmelidir.

## Rejected or insufficient mechanisms

- **Strict-route permits DNS on only one physical NIC:** false in this pinned
  source. ST `tun_windows.go:252-293` permits the current executable at weight 13
  with CLEAR_ACTION_RIGHT, on both address families, independent of interface.
  Its TUN permit is weight 11 (`:358-396`) and off-TUN remote-port-53 block is
  weight 10 (`:399-437`). Thus AURA's local DNS sockets are exempt on either NIC;
  other processes' DNS to an excluded LAN router can still be blocked. This
  latter limitation alone cannot account for direct literal-IP timeouts.
- AURA already excludes private LAN, link-local and CGNAT routes in
  `internal/engine/config.go:77-93`; adding the same LAN exclusion again cannot
  fix this. Turning off strict_route would reduce DNS isolation.
- `internal/engine/hostipv6.go:67-149` mirrors ST's IPv4 default selection before
  deciding IPv6 capability. It does not select a different NIC for direct DNS.
  The WireGuard detour avoids the dual-family StdNetBind failure; removing that
  detour would restore the previously demonstrated IPv6-less-host defect.

## Implemented next-run diagnostics

Statik kanıt R3'ün nedenini belirlemiyor; rota veya DNS politikası değiştirilmedi.
`internal/engine/multinic_windows.go`, platform arayüzü sağlanmadığı için boş kalan
`nm.NetworkInterfaces()` yerine `windows.GetAdaptersAddresses` kullanır.
Varsayılan rotalar mevcut `GetIpForwardTable2` okuyucusundan; her ailenin metriği,
forwarding ve weak-host bayrakları `GetIpInterfaceEntry` üzerinden okunur.

Tünel başlangıcında ve sing-tun varsayılan arayüz monitörünün her bildiriminde
bütün açık arayüzlerin indeksi, takma adı, IfType değeri, IPv4/IPv6 varsayılan
rota varlığı, en düşük varsayılan rota metriği, arayüz metriği ve bayrakları
kaydedilir. Okunamayan aile/rota tabloları açıkça belirtilir; bunların sıfır/false
alanları ölçüm olarak yorumlanmamalıdır. Birden fazla açık arayüzün IPv4
varsayılan rotası varsa WARN, aksi halde INFO kullanılır.

DNS sunucu sayısı ve her sunucunun adres içermeyen kapsamı (önce arayüzün bağlı
öneki, sonra özel/genel) kaydedilir. Yerel DNS için aday olma durumu ve üretimdeki
InterfaceFinder/varsayılan arayüz mantığının seçeceği çıkış indeksi sunucu
sırasıyla eşleştirilir; bu kayıt paket yakalaması veya başarılı sorgu kanıtı
değildir. Sunucu adresleri, kullanıcı IP'leri, DNS yanıtları ve ham ağ hataları
kaydedilmez. sing-tun'un gerçekten seçtiği varsayılan indeks ayrıca kaydedilir.

Başlangıçtaki sınırlı asenkron TCP/DNS karşılaştırma probları korunur; DNS sorgusu
`example.com.` adını kullanır. Monitör bildiriminde yalnızca tablolar okunur ve
kayıt üretilir. Kapanışta bildirim kaydı kaldırılır, problar iptal edilip beklenir.
Birim testleri sahte bağdaştırıcı/rota tabloları ve sahte prob sonuçları kullanır;
tünel başlatmaz, paket göndermez. Wi-Fi bağlıyken iki ailenin bayraklarını tekrar
ölçmek gerekir.

## Live confirmation (maintainer-controlled, not performed here)

1. Repeat Ethernet-only, both NICs, and Wi-Fi-only with the same profile; capture
   WARN diagnostics, readiness, and direct/tunnel outcomes. Compare selected
   index against route+interface metrics, not NCSI alone.
2. If selected NIC's TCP and DNS probes fail while the other succeeds, candidate
   1 is supported. Check source addresses and gateway ARP/return packets before
   adopting a reachability-based NIC policy.
3. If TCP works on both but DNS differs by NIC/server ordinal, candidate 2 is
   supported. Privately compare local resolver ordering with DNS configuration;
   capture DNS sends/replies on both NICs. Confirm whether the Windows DNS Client
   is attempting an excluded LAN resolver and being blocked outside the TUN.
4. Capture physical/TUN traffic and WFP drops during failure. If bound probes
   succeed but production direct dials fail, inspect auto-bind destination
   selection and third-party filters. Compare third-party VPN disconnected and
   fully exited, without disabling security software.
5. Any eventual fix must retain strict_route and Discord's persistent WFP blocks.
   Recheck app, browser-domain and DNS leak behavior on BOTH physical NICs.
