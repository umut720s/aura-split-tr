// Package manifest owns the supported Discord executable contract.
package manifest

import (
	"encoding/json"
	"path"
	"regexp"
	"strings"
)

// Roots returns a copy so callers cannot change the shared contract.
func Roots() []string {
	return []string{"Discord", "DiscordPTB", "DiscordCanary", "DiscordDevelopment"}
}

func names() string {
	var out []string
	for _, r := range Roots() {
		out = append(out, regexp.QuoteMeta(r))
	}
	return "(?:" + strings.Join(out, "|") + ")"
}

// PathRegex uses only syntax shared by Go RE2 and Python re.
func PathRegex() string {
	desktop := names() + `\.exe`
	helpers := `(?:updater_launcher|DiscordSystemHelper|audio_effects_helper|gpu_encoder_helper)\.exe`
	modules := `modules\\(?:discord_utils-[^\\]+\\discord_utils\\DiscordSystemHelper|discord_voice-[^\\]+\\discord_voice\\(?:audio_effects_helper|gpu_encoder_helper))\.exe`
	installer := `Discord[^\\]*Setup[^\\]*\.exe`
	return `(?i)\\AppData\\Local\\(?:` + names() + `\\(?:Update\.exe|` + installer + `|app-[^\\]+\\(?:` + desktop + `|` + helpers + `|` + modules + `))|SquirrelTemp\\` + installer + `)$`
}

var matcher = regexp.MustCompile(PathRegex())

// Normalize rejects ambiguous components instead of granting prefix membership.
func Normalize(p string) string {
	p = strings.ReplaceAll(p, "/", `\`)
	for _, part := range strings.Split(p, `\`) {
		if part == "." || part == ".." {
			return ""
		}
	}
	return strings.ToLower(p)
}

func Accepts(p string) bool { return matcher.MatchString(Normalize(p)) }

// Exact requires both a supported path and exact membership in the enrolled set.
func Exact(image string, entries []string) bool {
	if !Accepts(image) {
		return false
	}
	for _, p := range entries {
		if Normalize(image) == Normalize(p) {
			return true
		}
	}
	return false
}

func Class(p string) string {
	if !Accepts(p) {
		return ""
	}
	n := path.Base(strings.ReplaceAll(Normalize(p), `\`, "/"))
	if n == "update.exe" {
		return "updater"
	}
	if strings.Contains(n, "setup") {
		return "installers"
	}
	for _, r := range Roots() {
		if strings.EqualFold(n, r+".exe") {
			return "desktop"
		}
	}
	return "helpers"
}

// JSON is a generated, path-free contract for offline evidence tooling.
func JSON() []byte {
	b, _ := json.MarshalIndent(struct {
		Version   int      `json:"version"`
		Roots     []string `json:"roots"`
		PathRegex string   `json:"path_regex"`
	}{1, Roots(), PathRegex()}, "", "  ")
	return append(b, '\n')
}
