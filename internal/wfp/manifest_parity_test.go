package wfp

import (
	"aurasplit/internal/engine"
	"aurasplit/internal/manifest"
	"path/filepath"
	"regexp"
	"testing"
)

// CI executes this test; never run the WFP test binary on the development host.
func TestEngineDiscoveryRootParity(t *testing.T) {
	base := t.TempDir()
	rx := regexp.MustCompile(engine.DiscordPathRegex)
	for _, root := range append(manifest.Roots(), "DiscordCustom", "DiscordOther", "Other") {
		p := filepath.Join(base, "AppData", "Local", root, "app-1", "audio_effects_helper.exe")
		touch(t, p)
		got, err := DiscoverIn([]string{base})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, entry := range got {
			if entry == p {
				found = true
			}
		}
		if found != rx.MatchString(manifest.Normalize(p)) || found != manifest.Accepts(p) {
			t.Fatalf("root divergence: %s", root)
		}
	}
}
