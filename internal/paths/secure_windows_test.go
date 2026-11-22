//go:build windows

package paths

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"golang.org/x/sys/windows"
)

// Pure-logic tests of the trust rules. They run by default. Everything that
// creates ACL'd files, junctions or quarantine directories, or adjusts token
// privileges, lives in secure_acl_windows_test.go behind the acltests build
// tag (audit F-3): those binaries match AV heuristics on this machine.

func TestDACLTrust(t *testing.T) {
	for sddl, want := range map[string]bool{
		SecureSDDL:     true,
		InstallSDDL:    true,
		secureFileSDDL: true,
		// Inherited file DACL under the MSI install folder (InstallSDDL).
		`O:BAD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)`: true,
		`D:P(A;OICI;FA;;;SY)(A;OICIIO;FA;;;BU)`:                    false, // inherit-only still counts
		`D:P(A;OICIIO;GA;;;CO)(A;OICI;FA;;;BA)`:                    false, // CREATOR OWNER
		`D:P(A;;FR;;;WD)(A;;FA;;;BA)`:                              true,  // read only
		`D:P(D;;FA;;;WD)(A;;FA;;;BA)`:                              true,  // deny entries are harmless
		`D:P(A;;0x40;;;BU)(A;;FA;;;BA)`:                            false, // FILE_DELETE_CHILD
		`D:P(A;;WD;;;AU)(A;;FA;;;BA)`:                              false, // WRITE_DAC
		`D:P(A;OICI;0x1200a9;;;BU)(A;;FA;;;SY)`:                    true,
		`D:P(A;OICI;FA;;;SY)(A;OICI;GW;;;S-1-1-0)`:                 false,
	} {
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatalf("%s: %v", sddl, err)
		}
		dacl, _, err := sd.DACL()
		if err != nil {
			t.Fatalf("%s: %v", sddl, err)
		}
		got, err := daclTrusted(dacl, isTrustedSID)
		if err != nil || got != want {
			t.Errorf("daclTrusted(%s) = %v, %v; want %v", sddl, got, err, want)
		}
	}
	if ok, _ := daclTrusted(nil, isTrustedSID); ok {
		t.Error("NULL DACL trusted")
	}
}

func TestClassify(t *testing.T) {
	for name, want := range map[string]childKind{
		"profile.json":                          kindSecret,
		"PROFILE.JSON":                          kindSecret,
		"tunnel-state.json":                     kindState,
		"service.log":                           kindLog,
		"service.log.1":                         kindLog,
		"service.log.12":                        kindLog,
		"service.log.0":                         kindUnknown,
		"service.log.x":                         kindUnknown,
		".profile.json.0123456789abcdef.tmp":    kindTemp,
		".service.log.1.0123456789abcdef.tmp":   kindTemp,
		".other.json.0123456789abcdef.tmp":      kindUnknown,
		".profile.json.0123.tmp":                kindUnknown,
		"aurasplit.exe":                         kindUnknown,
		"notes.txt":                             kindUnknown,
		"profile.json:stream":                   kindUnknown,
		"..profile.json.0123456789abcdef.tmp.x": kindUnknown,
	} {
		if got := classifyData(name); got != want {
			t.Errorf("classifyData(%q) = %v, want %v", name, got, want)
		}
	}
}

// The MSI package must put exactly InstallSDDL on the install folder;
// setup verifies the folder with the same trust rules.
func TestInstallerSDDLMatches(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "installer", "AuraSplitTR.wxs"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`<PermissionEx\s+Sddl="([^"]+)"`).FindAllSubmatch(data, -1)
	if len(m) != 1 {
		t.Fatalf("expected exactly one PermissionEx Sddl in the installer, found %d", len(m))
	}
	if got := string(m[0][1]); got != InstallSDDL {
		t.Fatalf("installer SDDL %q != InstallSDDL %q", got, InstallSDDL)
	}
}
