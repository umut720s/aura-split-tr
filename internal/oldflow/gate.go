// Package oldflow gates readiness on retirement of pre-protection processes.
package oldflow

import (
	"aurasplit/internal/manifest"
	"fmt"
	"strings"
	"time"
)

type Process struct {
	PID        uint32
	ParentPID  uint32
	Name       string
	Image      string
	Started    time.Time
	Unresolved bool
}

type Source interface{ Processes() ([]Process, error) }

func Matches(image string, entries []string) bool { return manifest.Exact(image, entries) }

// Gate is owned by one protection session. Cutoffs are recorded only after
// policy readback. Unknown relevant identities are retained until absent.
// The caller serializes Check; no destructive operation is part of this API.
type Gate struct {
	cutoffs  map[string]time.Time
	relevant map[identity]bool
}

type identity struct {
	pid     uint32
	started time.Time
}

func id(p Process) identity { return identity{p.PID, p.Started} }

func (g *Gate) Check(s Source, entries []string) (bool, string) {
	if g.cutoffs == nil {
		g.cutoffs = map[string]time.Time{}
	}
	if g.relevant == nil {
		g.relevant = map[identity]bool{}
	}
	now := time.Now()
	// Each continuous verified enrollment is a generation. Empty entries retire
	// all generations, including on readback failure, recovery or policy loss.
	active := map[string]bool{}
	for _, p := range entries {
		key := manifest.Normalize(p)
		active[key] = true
		if _, ok := g.cutoffs[key]; !ok {
			g.cutoffs[key] = now
		}
	}
	for key := range g.cutoffs {
		if !active[key] {
			delete(g.cutoffs, key)
		}
	}
	if len(entries) == 0 {
		return false, "Doğrulanmış kayıt yok; eski akış kapısı bekliyor."
	}
	procs, err := s.Processes()
	if err != nil {
		return false, "Süreç envanteri okunamadı; Discord yeniden başlatma kapısı bekliyor."
	}
	relevant := map[identity]bool{}
	current := map[uint32]Process{}
	for _, p := range procs {
		current[p.PID] = p
	}
	for _, p := range procs {
		unresolved := p.Unresolved || p.Image == "" || p.Started.IsZero()
		if manifest.Accepts(p.Image) || (unresolved && g.relevant[id(p)]) || heuristic(p.Name) || heuristic(p.Image) {
			relevant[id(p)] = true
		}
	}
	// Resolve ancestry independent of snapshot ordering, including grandchildren.
	for changed := true; changed; {
		changed = false
		for _, p := range procs {
			parent, exists := current[p.ParentPID]
			// A recycled parent PID is not evidence of ancestry.
			if exists && (parent.Started.IsZero() || p.Started.IsZero() || !parent.Started.After(p.Started)) && relevant[id(parent)] && !relevant[id(p)] {
				relevant[id(p)] = true
				changed = true
			}
		}
	}
	pending, unresolved := 0, 0
	var blockers []string
	for _, p := range procs {
		// An unreadable pre-enrollment orphan may be an unfamiliar Discord
		// child. No PID-only history is used when its parent has disappeared.
		unknownChain := false
		seen := map[uint32]bool{p.PID: true}
		child := p
		for child.ParentPID != 0 {
			parent, exists := current[child.ParentPID]
			if !exists || seen[parent.PID] || parent.Image == "" || parent.Unresolved || parent.Started.IsZero() || child.Started.IsZero() || parent.Started.After(child.Started) {
				unknownChain = true
				break
			}
			seen[parent.PID] = true
			child = parent
		}
		before := p.Started.IsZero()
		for _, cutoff := range g.cutoffs {
			before = before || !p.Started.After(cutoff)
		}
		possibleOrphan := p.Image == "" && before && unknownChain
		if (relevant[id(p)] || possibleOrphan) && (p.Unresolved || p.Image == "" || p.Started.IsZero()) {
			unresolved++
			blockers = append(blockers, fmt.Sprintf("PID %d (%s)", p.PID, p.Name))
			continue
		}
		if !Matches(p.Image, entries) {
			// A supported running image may have been deleted from disk before
			// discovery. Absence from the enrolled set is not retirement evidence.
			if manifest.Accepts(p.Image) {
				pending++
			}
			continue
		}
		if !p.Started.After(g.cutoffs[manifest.Normalize(p.Image)]) {
			pending++
		}
	}
	g.relevant = relevant
	if unresolved > 0 {
		return false, fmt.Sprintf("%d olası Discord sürecinin kimliği/başlangıcı okunamadı: %s; süreç kapanana veya kimliği çözülene kadar bekliyor. Discord'u tamamen kapatıp yeniden başlatın.", unresolved, strings.Join(blockers, ", "))
	}
	if pending > 0 {
		return false, fmt.Sprintf("%d koruma öncesi veya kaydı eksik Discord süreci açık; bekliyor: Discord'u tamamen kapatıp yeniden başlatın.", pending)
	}
	return true, "Koruma öncesi manifest süreçleri kalmadı; eski akış kapısı tamamlandı."
}

func heuristic(s string) bool {
	s = strings.ToLower(s)
	return strings.Contains(s, "discord") || strings.HasSuffix(s, "update.exe") || strings.HasSuffix(s, "updater_launcher.exe") || strings.HasSuffix(s, "_helper.exe")
}
