package wfp

import (
	"aurasplit/internal/manifest"
	"fmt"
	"strings"
)

// ClassStatus describes configuration coverage, not measured packet isolation.
type ClassStatus struct {
	Class    string `json:"class"`
	Coverage string `json:"coverage"`
	Reason   string `json:"reason"`
}

// TrafficClasses keeps browser and delegated DNS outside the executable claim.
func TrafficClasses(entries []string, ready bool, reason string) []ClassStatus {
	counts := map[string]int{}
	for _, p := range entries {
		c := manifest.Class(p)
		counts[c]++
	}
	var out []ClassStatus
	for _, c := range []string{"desktop", "updater", "helpers", "installers"} {
		s := ClassStatus{Class: c, Coverage: "not-covered", Reason: "Manifestte bu sınıf için program bulunamadı; özel konumlar kapsam dışı."}
		if counts[c] > 0 {
			s.Coverage, s.Reason = "partial", reason
			if ready {
				s.Coverage, s.Reason = "protected", "Manifest yolları: dört ALE katmanı okundu, tünel izni ve eski akış kapısı tamamlandı; paket izolasyonu ölçülmedi."
			}
		}
		out = append(out, s)
	}
	return append(out, ClassStatus{"routing fallbacks", "routed-not-fail-closed", "Desteklenen Discord kurulum dizinlerindeki tüm programlar, varsayılan süreç adları ve kurulum dosyaları tünel kipinde yönlendirilir, blok kipinde reddedilir; yalnızca yönlendirilen, kaydedilmemiş EXE'ler: routed, not fail-closed. Manifest dışı yollar doğrulanmış manifest kapsamı sayılmaz."}, ClassStatus{"browser Discord", "not-covered", "En iyi çaba (best-effort); kalıcı fail-closed yok."}, ClassStatus{"DNS", "not-covered", "En iyi çaba (best-effort); servis dışı ve şifreli/delege DNS için kalıcı fail-closed yok."})
}

// VerifyPolicy requires an independent readback; legacy implementations fail closed.
func VerifyPolicy(p Policy, paths []string) error {
	v, ok := p.(interface{ Verify([]string) error })
	if !ok {
		return fmt.Errorf("WFP readback desteklenmiyor")
	}
	return v.Verify(paths)
}

// Verify reads committed blocks on all four ALE layers for every requested path.
func (f *Firewall) Verify(paths []string) error {
	s, err := f.b.Open(false)
	if err != nil {
		return err
	}
	defer s.Close()
	return inTxn(s, func() error {
		p, err := s.HasProvider()
		if err != nil {
			return err
		}
		if !p {
			return fmt.Errorf("WFP provider eksik")
		}
		p, err = s.HasSubLayer()
		if err != nil {
			return err
		}
		if !p {
			return fmt.Errorf("WFP sublayer eksik")
		}
		recs, err := s.Filters()
		if err != nil {
			return err
		}
		for _, path := range normalizePaths(paths) {
			id, err := f.b.AppID(path)
			if err != nil {
				return err
			}
			for _, layer := range Layers {
				found := false
				for _, r := range recs {
					if r.Key == filterKey("block", layer, id) && r.Layer == layer && r.Persistent && !r.Disabled && r.Action == ActionBlock && strings.EqualFold(r.Path, path) {
						found = true
						break
					}
				}
				if !found {
					return fmt.Errorf("WFP readback eksik: %s", layer)
				}
			}
		}
		return nil
	})
}
