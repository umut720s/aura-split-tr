//go:build windows

package msiclean

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"aurasplit/internal/paths"
)

func TestUninstallRecoveryGateAndOutput(t *testing.T) {
	for _, tt := range []struct {
		name        string
		recoverCode int
		result      paths.CleanResult
		err         error
		want        string
	}{
		{name: "recovery failed", recoverCode: 1, want: "Veri klasörüne dokunulmadı.\n"},
		{name: "missing", result: paths.CleanResult{Missing: true}, want: "- Veri klasörü yok (temiz): "},
		{name: "removed", result: paths.CleanResult{Removed: true, Deleted: []string{paths.ProfileName}}, want: "- Veri klasörü silindi (1 AURA Split TR dosyası): "},
		{name: "untrusted", result: paths.CleanResult{Kept: []string{"güvenilmeyen klasör"}}, want: "  Neden: güvenilmeyen klasör\n"},
		{name: "cleanup error", err: errors.New("geçersiz klasör"), want: "  Neden: geçersiz klasör\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), paths.AppDirName)
			var calls []string
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			original := os.Stdout
			os.Stdout = writer
			defer func() { os.Stdout = original; reader.Close(); writer.Close() }()
			code := uninstall(func() int { calls = append(calls, "recover"); return tt.recoverCode },
				func() string { calls = append(calls, "dir"); return dir },
				func(got string) (paths.CleanResult, error) {
					calls = append(calls, "clean")
					if got != dir {
						t.Errorf("directory=%q, want %q", got, dir)
					}
					return tt.result, tt.err
				},
				func() ([]string, []string) {
					calls = append(calls, "quarantine")
					return []string{"güvenilir"}, []string{"yabancı"}
				})
			writer.Close()
			os.Stdout = original
			output, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			if code != tt.recoverCode || !strings.Contains(string(output), tt.want) {
				t.Fatalf("code=%d output=%q; want code=%d containing %q", code, output, tt.recoverCode, tt.want)
			}
			if tt.recoverCode != 0 {
				if !reflect.DeepEqual(calls, []string{"recover"}) {
					t.Fatalf("failed recovery touched data: %v", calls)
				}
			} else if !strings.Contains(string(output), "Not: karantina klasörleri silinmedi (elle inceleyin):\n   güvenilir\n   yabancı\n") {
				t.Fatalf("missing quarantine notice: %q", output)
			}
		})
	}
}
