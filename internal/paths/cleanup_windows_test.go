//go:build windows

package paths

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"aurasplit/internal/testutil"
)

// These tests run unelevated: the directory and its files are created by
// the current user with the restricted descriptors plus the current user,
// and cleanPolicy trusts the current user. No junctions, no Everyone ACLs,
// no privileges (see the note at the top of secure_acl_windows_test.go).

func cleanPolicy(t *testing.T) (dirPolicy, string, string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	me := user.User.Sid
	u := me.String()
	pol := dirPolicy{
		classify: classifyData,
		trusted:  func(sid *windows.SID) bool { return isTrustedSID(sid) || (sid != nil && sid.Equals(me)) },
	}
	return pol, `D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;` + u + `)`, `D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;` + u + `)`
}

func makeAppDir(t *testing.T, sddl string) string {
	t.Helper()
	dir := filepath.Join(testutil.TempDir(t), AppDirName)
	sd, err := parseSD(sddl)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := windows.UTF16PtrFromString(dir)
	if err := windows.CreateDirectory(p, securityAttributes(sd)); err != nil {
		t.Fatal(err)
	}
	return dir
}

func makeFile(t *testing.T, path, sddl string) {
	t.Helper()
	f, err := createNew(path, sddl)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("x"); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

var ownNames = []string{"profile.json", "tunnel-state.json", "recover-state.json", ".recover-state.json.0123456789abcdef.tmp", "service.log", "service.log.1", ".profile.json.0123456789abcdef.tmp"}

func TestCleanDirRemovesOwnFilesAndDirectory(t *testing.T) {
	pol, dsddl, fsddl := cleanPolicy(t)
	dir := makeAppDir(t, dsddl)
	for _, n := range ownNames {
		makeFile(t, filepath.Join(dir, n), fsddl)
	}
	res, err := cleanDir(dir, pol)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Removed || len(res.Kept) != 0 || len(res.Deleted) != len(ownNames) {
		t.Fatalf("result %+v", res)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("directory still exists: %v", err)
	}
}

// Anything unexpected keeps everything: all or nothing.
func TestCleanDirUnexpectedEntriesKeepEverything(t *testing.T) {
	pol, dsddl, fsddl := cleanPolicy(t)
	cases := map[string]func(t *testing.T, dir string){
		"foreign file": func(t *testing.T, dir string) { makeFile(t, filepath.Join(dir, "notes.txt"), fsddl) },
		"directory with our name": func(t *testing.T, dir string) {
			if err := os.Mkdir(filepath.Join(dir, "service.log.3"), 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"foreign directory": func(t *testing.T, dir string) {
			if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"hard-linked log": func(t *testing.T, dir string) {
			outside := filepath.Join(filepath.Dir(dir), "elsewhere.txt")
			makeFile(t, outside, fsddl)
			from, _ := windows.UTF16PtrFromString(filepath.Join(dir, "service.log.2"))
			to, _ := windows.UTF16PtrFromString(outside)
			if err := windows.CreateHardLink(from, to, 0); err != nil {
				t.Skipf("hard link: %v", err)
			}
		},
	}
	for name, add := range cases {
		t.Run(name, func(t *testing.T) {
			dir := makeAppDir(t, dsddl)
			for _, n := range ownNames {
				makeFile(t, filepath.Join(dir, n), fsddl)
			}
			add(t, dir)
			res, err := cleanDir(dir, pol)
			if err != nil {
				t.Fatal(err)
			}
			if res.Removed || len(res.Deleted) != 0 || len(res.Kept) == 0 {
				t.Fatalf("result %+v", res)
			}
			for _, n := range ownNames {
				if _, err := os.Lstat(filepath.Join(dir, n)); err != nil {
					t.Fatalf("%s was touched: %v", n, err)
				}
			}
		})
	}
}

// An entry another process holds open without sharing cannot be inspected:
// nothing is deleted.
func TestCleanDirInUseKeepsEverything(t *testing.T) {
	pol, dsddl, fsddl := cleanPolicy(t)
	dir := makeAppDir(t, dsddl)
	for _, n := range ownNames {
		makeFile(t, filepath.Join(dir, n), fsddl)
	}
	p, _ := windows.UTF16PtrFromString(filepath.Join(dir, "service.log"))
	h, err := windows.CreateFile(p, windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	res, err := cleanDir(dir, pol)
	windows.CloseHandle(h)
	if err != nil {
		t.Fatal(err)
	}
	if res.Removed || len(res.Deleted) != 0 || !strings.Contains(strings.Join(res.Kept, "|"), "service.log") {
		t.Fatalf("result %+v", res)
	}
	if _, err := os.Lstat(filepath.Join(dir, "profile.json")); err != nil {
		t.Fatal("profile deleted although another entry was in use")
	}
}

// The production trust rules (SYSTEM/Administrators/TrustedInstaller) do
// not trust a directory owned by a standard user: it is left alone.
func TestCleanDirUntrustedDirectoryLeftAlone(t *testing.T) {
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("an elevated process creates Administrators-owned objects")
	}
	_, dsddl, fsddl := cleanPolicy(t)
	dir := makeAppDir(t, dsddl)
	makeFile(t, filepath.Join(dir, "profile.json"), fsddl)
	res, err := cleanDir(dir, dataPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if res.Removed || len(res.Deleted) != 0 || len(res.Kept) != 1 || !strings.Contains(res.Kept[0], "owner or ACL") {
		t.Fatalf("result %+v", res)
	}
	if _, err := os.Lstat(filepath.Join(dir, "profile.json")); err != nil {
		t.Fatal("file in an untrusted directory was deleted")
	}
}

func TestCleanDirMissingAndInvalid(t *testing.T) {
	pol, _, _ := cleanPolicy(t)
	res, err := cleanDir(filepath.Join(testutil.TempDir(t), AppDirName), pol)
	if err != nil || !res.Missing {
		t.Fatalf("missing: %+v %v", res, err)
	}
	if _, err := cleanDir(testutil.TempDir(t), pol); err == nil {
		t.Fatal("directory with another name accepted")
	}
	if _, err := cleanDir(`relative\`+AppDirName, pol); err == nil {
		t.Fatal("relative path accepted")
	}
}

func TestPlanCleanup(t *testing.T) {
	good := cleanEntry{name: "profile.json", kind: kindSecret, plain: true, trusted: true}
	if ok, r := planCleanup([]cleanEntry{good}); !ok || len(r) != 0 {
		t.Fatalf("good: %v %v", ok, r)
	}
	if ok, _ := planCleanup(nil); !ok {
		t.Fatal("empty directory refused")
	}
	for _, bad := range []cleanEntry{
		{name: "x.txt", kind: kindUnknown, plain: true, trusted: true},
		{name: "service.log", kind: kindLog, plain: false, trusted: true},
		{name: "service.log", kind: kindLog, plain: true, trusted: false},
		{name: "service.log", kind: kindLog, err: errors.New("sharing violation")},
	} {
		if ok, r := planCleanup([]cleanEntry{good, bad}); ok || len(r) != 1 {
			t.Errorf("%+v: ok=%v reasons=%v", bad, ok, r)
		}
	}
}
