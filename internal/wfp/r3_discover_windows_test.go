//go:build windows

package wfp

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestR3ProfileDirectoryIncomplete(t *testing.T) {
	expand := func(s string) (string, error) { return s, nil }
	for _, value := range []string{"", "relative", `%UnknownRoot%\profile`} {
		if _, err := profileDirectory(value, nil, expand); err == nil {
			t.Fatal(value)
		}
	}
	if _, err := profileDirectory(`C:\fixture`, errors.New("denied"), expand); err == nil {
		t.Fatal("read failure ignored")
	}
	if _, err := profileDirectory(`C:\fixture`, nil, func(string) (string, error) { return "", errors.New("expand") }); err == nil {
		t.Fatal("expand failure ignored")
	}
	if got, err := profileDirectory(`C:\fixture`, nil, expand); err != nil || got != `C:\fixture` {
		t.Fatal(got, err)
	}
}

func TestR3CountStableUntilTransientFilesRemoved(t *testing.T) {
	root := t.TempDir()
	inst := filepath.Join(root, "AppData", "Local", "Discord")
	for _, name := range []string{"Discord.exe", "updater_launcher.exe", "DiscordSystemHelper.exe", "audio_effects_helper.exe", "gpu_encoder_helper.exe"} {
		touch(t, filepath.Join(inst, "app-1", name))
	}
	touch(t, filepath.Join(inst, "Update.exe"))
	var transient []string
	for _, name := range []string{"DiscordSetup.exe", "DiscordPTBSetup.exe", "DiscordCanarySetup.exe"} {
		p := filepath.Join(root, "AppData", "Local", "SquirrelTemp", name)
		touch(t, p)
		transient = append(transient, p)
	}
	first, err := DiscoverIn([]string{root})
	if err != nil || len(first) != 9 {
		t.Fatal(len(first), err)
	}
	again, err := DiscoverIn([]string{root})
	if err != nil || !reflect.DeepEqual(first, again) {
		t.Fatal("unchanged inventory drifted", err)
	}
	for _, p := range transient {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	last, err := DiscoverIn([]string{root})
	if err != nil || len(last) != 6 {
		t.Fatal(len(last), err)
	}
}
