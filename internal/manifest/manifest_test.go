package manifest

import (
	"bytes"
	"os"
	"testing"
)

func TestExportParity(t *testing.T) {
	b, err := os.ReadFile("../../tools/leaktest/executable_manifest.json")
	if err != nil || !bytes.Equal(b, JSON()) {
		t.Fatalf("regenerate executable manifest with go run ./internal/manifest/cmd/export: %v", err)
	}
}

func TestMembership(t *testing.T) {
	for _, root := range append(Roots(), "DiscordCustom", "DiscordOther", "discord-backup") {
		p := `C:\Users\fixture\AppData\Local\` + root + `\app-1\audio_effects_helper.exe`
		want := root != "DiscordCustom" && root != "DiscordOther" && root != "discord-backup"
		if Accepts(p) != want {
			t.Fatal(p)
		}
	}
	for _, tail := range []string{`app-1\utility.exe`, `app-1\modules\other\other\extra.exe`, `app-1\..\app-1\Discord.exe`, `unrelated.exe`} {
		if Accepts(`C:\Users\fixture\AppData\Local\Discord\` + tail) {
			t.Fatal(tail)
		}
	}
	if Exact(`C:\Users\fixture\AppData\Local\Discord\app-1\Discord.exe`, []string{`C:\Users\fixture\AppData\Local\Discord\Update.exe`}) {
		t.Fatal("prefix accepted")
	}
}
