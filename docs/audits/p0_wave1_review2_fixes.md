# P0 wave-1 ikinci inceleme düzeltmeleri — 2026-11-27

Kod düzeltmesi ağ kabulü değildir; genel release kapısı KAPALI.

| Madde | Düzeltme | Regresyon kanıtı |
|---|---|---|
| 1 | `internal/wfp/guard.go:149,275`: permit kümesi kanonik manifestle sınırlı; eski bloklar kalır, daraltma hatası hazır sayılmaz. | `TestCanonicalPermitsRetainLegacyBlocks`; yalnız derlendi, çalıştırılmadı. |
| 2 | `internal/oldflow/gate.go:95`: okunamayan koruma öncesi orphan değerlendirmesi, PID/adı ve kimlik/ömürle sınırlı bekleme. | `TestUnfamiliarOrphanLifetimeAndResolution` PASS. |
| 3 | `internal/oldflow/gate.go:47`, `internal/wfp/guard.go:344`: kesintisiz doğrulanmış nesil eşikleri; retirement/kayıpta iptal, onarım öncesi readback. | `TestEnrollmentGenerationsRetireCutoffs` PASS; Guard entegrasyon testi yalnız derlendi. |
| 4 | `internal/engine/config.go:363`, `internal/wfp/readiness.go:34`: basename/installer fallback wg/reject; `routed-not-fail-closed`. | `TestFallbackRoutingAndBlockMode` PASS; durum sınıfları testi yalnız derlendi. |
| 5 | `tools/leaktest/capture.ps1:146`, `analyze.py:514,650`: operatör aktivasyon işareti; önceki paketler baseline, sonraki paketler sızıntı değerlendirmesi. | Sınır/eksik işaret testleri PASS; capture betiği yalnız sözdizimi kontrolü. |
| 6 | `internal/oldflow/gate.go:32`, `source_windows.go:40`: PID/oluşturulma zamanı; görüntü okunamasa da zaman sorgusu; doğrulanmış replacement ilgiyi devralmaz. | `TestPIDAndParentReuseDoNotInheritRelevance` PASS. |

Doğrulama PASS: `gofmt -l cmd internal` boş; vet release etiketleri ve ayrıca `acltests` ile temiz.
Release etiketleri: `with_gvisor,with_wireguard,with_external_windivert`.
Önbellekteki staticcheck v0.8.2 PASS; yazılabilir geçici cache kullanıldı, indirme yapılmadı.
`go test -count=1` release etiketleriyle ve ayrıca `acltests` ile PASS; `internal/wfp` ve `internal/paths` hariç.
`python -I -B tools/leaktest/test_analyze.py`: 61 test PASS; PowerShell parser PASS; `git diff --check` PASS.
WFP testleri yalnız `go test -c` ile derlendi; WFP/paths test binary'leri çalıştırılmadı.

Artık sınırlar: okunamayan ilgisiz orphan süreç kapanana/çözülene kadar bekletebilir;
Discord restartı yalnız Discord kimliklerini emekliye ayırır. Başlangıç zamanı hiç
okunamayan süreçlerde snapshot arası gizli PID kullanımı ayırt edilemez. Bilinmeyen
okunabilir özel EXE'ler, launch yarışı ve gözlenmeyen politika değişimleri tam kapsanmaz.
Aktivasyon işareti politika doğrulaması için operatör beyanına dayanır; otomatik readback değildir.
Canlı WFP/servis/recover/TUN/route/firewall, süreç kapatma ve L1–L14: **NOT TESTED**; değiştirilmedi/çalıştırılmadı.

## Round-3 fixes — 2026-11-27

- PARTIAL #1: `winSession.Close` retains its native handle and `sessionPermit.Close`
  retains its session on failure. Guard retains every failed retirement, retries
  closure during reconciliation (including after tunnel shutdown), and prevents
  new sessions/readiness while closure is pending. State/CLI expose
  `pending_permit_closure` / `PERMIT_CLOSURE_PENDING`.
- Restored whole-install-directory routing for all four supported Discord roots,
  alongside manifest rules: `wg` in tunnel mode, `reject` in block mode. Broad
  routing does not expand exact-manifest process-close eligibility or verified
  manifest readiness/classes; unenrolled fallbacks are “routed, not fail-closed”.
- Discovery again enrolls every plain `*.exe` directly under `app-*` and bounded
  `modules/*/*` helper folders, preserving reparse/depth/count/policy limits.
  These extra blocks do not expand canonical permits or destructive eligibility.
- Regression tests added for fake-BFE failed closure/retention/retry/readiness,
  pending-closure CLI status, routing in both modes, supported-root boundaries,
  future-helper persistent blocks/classification and discovery caps.
- Validation: gofmt clean; vet and cached staticcheck v0.8.2 PASS with release tags
  (`with_gvisor,with_wireguard,with_external_windivert`), also with `acltests`.
  `go test -count=1` PASS for both tag sets, excluding `internal/wfp` and
  `internal/paths`. WFP regression tests compiled only; neither excluded package's
  test binary executed. GOCACHE/GOTMPDIR stayed under the requested scratchpad.
- Python check BLOCKED: `python -I -B tools/leaktest/test_analyze.py` could not
  start; installed Python310 interpreter execution returned “Access denied”.
  No Python test result is claimed for this round. No elevation, MSI execution,
  live WFP/service/TUN/route/firewall changes or process termination performed.
