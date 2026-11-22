//go:build windows && acltests

// Filesystem ACL, junction, quarantine and privilege tests. They are gated
// behind the acltests tag because the resulting test binary (it spawns
// cmd.exe mklink, writes Everyone-writable DACLs, calls SetSecurityInfo and
// AdjustTokenPrivileges) was flagged by Kaspersky as
// VHO:Trojan.Win64.Convagent.gen. Run them with:
//
//	go test -tags with_gvisor,with_wireguard,acltests ./internal/paths/
//
// The elevated-only tests additionally need an administrator shell.

package paths

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"aurasplit/internal/testutil"
)

// The restricted ACL removes access for non-elevated users, so this test
// only runs from an elevated shell.
func TestWriteSecureFile(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("requires an elevated process")
	}
	dir := filepath.Join(testutil.TempDir(t), "secure")
	path := filepath.Join(dir, "profile.json")
	for _, data := range []string{"first", "second"} {
		if err := WriteSecureFile(path, []byte(data)); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(path)
		if err != nil || string(b) != data {
			t.Fatalf("read back %q, %v", b, err)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %d entries", len(entries))
	}
}

func makeJunction(t *testing.T, link, target string) {
	t.Helper()
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(filepath.Join(sys, "cmd.exe"), "/c", "mklink", "/J", link, target).CombinedOutput()
	if err != nil {
		t.Skipf("cannot create junction: %v %s", err, out)
	}
}

// Junctions need no privilege, so these run unelevated too.
func TestEnsureSecureDirRefusesReparsePoints(t *testing.T) {
	base := testutil.TempDir(t)
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	makeJunction(t, link, target)
	if err := EnsureSecureDir(link); err == nil || !strings.Contains(err.Error(), "reparse") {
		t.Fatalf("junction as directory: %v", err)
	}
	if err := EnsureSecureDir(filepath.Join(link, "sub")); err == nil || !strings.Contains(err.Error(), "reparse") {
		t.Fatalf("junction in parent chain: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, "sub")); !os.IsNotExist(err) {
		t.Fatal("directory was created through the junction")
	}
}

func TestEnsureSecureDirRelativeRefused(t *testing.T) {
	if err := EnsureSecureDir(`relative\dir`); err == nil {
		t.Fatal("relative path accepted")
	}
}

// testPolicy is the data-directory policy with the current (unelevated)
// user added as a trusted principal and the owner left to the default, so
// the adoption logic can be exercised without administrator rights.
func testPolicy(t *testing.T) dirPolicy {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	me := user.User.Sid
	u := me.String()
	dir := `D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;` + u + `)`
	return dirPolicy{
		dirSDDL:        dir,
		fileSDDL:       `D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;` + u + `)`,
		quarantineSDDL: dir,
		classify:       classifyData,
		trusted:        func(sid *windows.SID) bool { return isTrustedSID(sid) || (sid != nil && sid.Equals(me)) },
	}
}

// retryTempDir is kept for readability; testutil.TempDir retries the
// cleanup while an on-access scanner holds moved files delete-pending.
func retryTempDir(t *testing.T) string { t.Helper(); return testutil.TempDir(t) }

// untrustedFileSDDL lets Everyone write: a file with this DACL is proven
// untrustworthy.
const untrustedFileSDDL = `D:P(A;;FA;;;WD)`

func writeWithSDDL(t *testing.T, path, sddl, data string) {
	t.Helper()
	f, err := createNew(path, sddl)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(data); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func identity(t *testing.T, path string) fileKey {
	t.Helper()
	h, err := openNoFollow(path, windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	info, err := handleInfo(h)
	if err != nil {
		t.Fatal(err)
	}
	return keyOf(info)
}

func quarantines(t *testing.T, dir string) []string {
	t.Helper()
	m, err := filepath.Glob(dir + QuarantineInfix + "*")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// An adopted, trusted directory keeps trusted application files, replaces
// an untrusted log with a fresh copy, quarantines an untrusted profile and
// every foreign entry, and removes only stale staging files of its own.
func TestAdoptHandlesChildren(t *testing.T) {
	pol := testPolicy(t)
	dir := filepath.Join(retryTempDir(t), "AuraSplitTR")
	if err := ensureDir(dir, pol); err != nil {
		t.Fatal(err)
	}
	writeWithSDDL(t, filepath.Join(dir, ProfileName), untrustedFileSDDL, "attacker profile")
	writeWithSDDL(t, filepath.Join(dir, LogName), untrustedFileSDDL, "old log\n")
	writeWithSDDL(t, filepath.Join(dir, StateName), pol.fileSDDL, "state")
	writeWithSDDL(t, filepath.Join(dir, "notes.txt"), pol.fileSDDL, "foreign")
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(dir, ".profile.json.0123456789abcdef.tmp")
	fresh := filepath.Join(dir, ".profile.json.fedcba9876543210.tmp")
	writeWithSDDL(t, stale, pol.fileSDDL, "x")
	writeWithSDDL(t, fresh, pol.fileSDDL, "y")
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	logBefore := identity(t, filepath.Join(dir, LogName))

	if err := ensureDir(dir, pol); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Lstat(filepath.Join(dir, ProfileName)); !os.IsNotExist(err) {
		t.Fatal("untrusted profile was kept in place")
	}
	if got := readFile(t, filepath.Join(dir, LogName)); got != "old log\n" {
		t.Fatalf("log content not carried over: %q", got)
	}
	if identity(t, filepath.Join(dir, LogName)) == logBefore {
		t.Fatal("untrusted log was reused instead of replaced")
	}
	h, err := openNoFollow(filepath.Join(dir, LogName), windows.READ_CONTROL)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := objectTrusted(h, pol.trusted)
	windows.CloseHandle(h)
	if err != nil || !ok {
		t.Fatalf("replacement log not trusted: %v %v", ok, err)
	}
	if got := readFile(t, filepath.Join(dir, StateName)); got != "state" {
		t.Fatalf("trusted state changed: %q", got)
	}
	if _, err := os.Lstat(stale); !os.IsNotExist(err) {
		t.Fatal("stale staging file kept")
	}
	if _, err := os.Lstat(fresh); err != nil {
		t.Fatal("fresh staging file removed")
	}
	q := quarantines(t, dir)
	if len(q) != 1 {
		t.Fatalf("quarantine directories: %v", q)
	}
	if got := readFile(t, filepath.Join(q[0], ProfileName)); got != "attacker profile" {
		t.Fatalf("quarantined profile: %q", got)
	}
	if got := readFile(t, filepath.Join(q[0], "notes.txt")); got != "foreign" {
		t.Fatalf("quarantined entry: %q", got)
	}
	if st, err := os.Stat(filepath.Join(q[0], "sub")); err != nil || !st.IsDir() {
		t.Fatal("sub-directory not quarantined")
	}
	for _, name := range []string{"notes.txt", "sub"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s left in place", name)
		}
	}
}

// A directory whose ACL lets Everyone write is renamed to a quarantine
// name with its content intact, and a fresh directory takes its place.
func TestUntrustedDirKeptInQuarantine(t *testing.T) {
	pol := testPolicy(t)
	dir := filepath.Join(retryTempDir(t), "AuraSplitTR")
	sd, err := parseSD(`D:P(A;OICI;FA;;;WD)`)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := windows.UTF16PtrFromString(dir)
	if err := windows.CreateDirectory(p, securityAttributes(sd)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ProfileName), []byte("planted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureDir(dir, pol); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("new directory not empty: %v %v", entries, err)
	}
	q := quarantines(t, dir)
	if len(q) != 1 {
		t.Fatalf("quarantine directories: %v", q)
	}
	if got := readFile(t, filepath.Join(q[0], ProfileName)); got != "planted" {
		t.Fatalf("quarantined content: %q", got)
	}
	h, err := openNoFollow(q[0], windows.READ_CONTROL)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := objectTrusted(h, pol.trusted)
	windows.CloseHandle(h)
	if err != nil || !ok {
		t.Fatalf("quarantine directory ACL not restricted: %v %v", ok, err)
	}
}

// An entry that cannot be moved (another process holds it open without
// delete sharing) is an inspection failure: the call fails and nothing is
// moved or deleted. It is quarantined once the handle is closed.
func TestSweepInUseEntryNotTouched(t *testing.T) {
	pol := testPolicy(t)
	dir := filepath.Join(retryTempDir(t), "AuraSplitTR")
	if err := ensureDir(dir, pol); err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(dir, "locked.bin")
	writeWithSDDL(t, locked, pol.fileSDDL, "busy")
	lp, _ := windows.UTF16PtrFromString(locked)
	h, err := windows.CreateFile(lp, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = ensureDir(dir, pol)
	windows.CloseHandle(h)
	if err == nil {
		t.Fatal("in-use entry did not cause an error")
	}
	if got := readFile(t, locked); got != "busy" {
		t.Fatalf("in-use entry changed: %q", got)
	}
	if q := quarantines(t, dir); len(q) != 0 {
		t.Fatalf("empty quarantine left behind: %v", q)
	}
	if err := ensureDir(dir, pol); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(locked); !os.IsNotExist(err) {
		t.Fatal("entry not quarantined after release")
	}
}

// Elevated only: the production policy quarantines links, hard-linked files
// and foreign names (never deleting them or touching link targets).
func TestEnsureSecureDirSweepsChildren(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("requires an elevated process")
	}
	base := testutil.TempDir(t)
	dir := filepath.Join(base, "secure")
	if err := EnsureSecureDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := WriteSecureFile(filepath.Join(dir, ProfileName), []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := WriteSecureFile(filepath.Join(dir, "other.json"), []byte("y")); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(base, "other")
	os.Mkdir(other, 0o700)
	makeJunction(t, filepath.Join(dir, "junction"), other)
	if err := os.Link(filepath.Join(dir, ProfileName), filepath.Join(base, "hardlink")); err != nil {
		t.Fatal(err)
	}
	if err := EnsureSecureDir(dir); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		// profile.json had a second link and must be gone as well.
		t.Fatalf("unexpected entries survived: %v", entries)
	}
	q := quarantines(t, dir)
	if len(q) != 1 {
		t.Fatalf("quarantine directories: %v", q)
	}
	for _, name := range []string{ProfileName, "other.json", "junction"} {
		if _, err := os.Lstat(filepath.Join(q[0], name)); err != nil {
			t.Fatalf("%s not quarantined: %v", name, err)
		}
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatal("junction target was touched")
	}
}

// Elevated only: the log opener refuses hard links and recreates the file.
func TestOpenSecureAppend(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("requires an elevated process")
	}
	base := testutil.TempDir(t)
	dir := filepath.Join(base, "secure")
	if err := EnsureSecureDir(dir); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "outside.txt")
	os.WriteFile(outside, []byte("keep"), 0o600)
	logPath := filepath.Join(dir, "service.log")
	if err := os.Link(outside, logPath); err != nil {
		t.Fatal(err)
	}
	f, _, err := OpenSecureAppend(logPath)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("log"))
	f.Close()
	if b, _ := os.ReadFile(outside); string(b) != "keep" {
		t.Fatalf("write went through the hard link: %q", b)
	}
}

// CleanDataDir never follows a junction: neither at the directory itself
// nor for an entry inside it. The junction targets are left untouched.
func TestCleanDirRefusesJunctions(t *testing.T) {
	pol, dsddl, fsddl := cleanPolicy(t)
	base := testutil.TempDir(t)
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	makeFile(t, filepath.Join(target, "profile.json"), fsddl)

	link := filepath.Join(base, AppDirName)
	makeJunction(t, link, target)
	res, err := cleanDir(link, pol)
	if err != nil {
		t.Fatal(err)
	}
	if res.Removed || len(res.Deleted) != 0 || len(res.Kept) == 0 {
		t.Fatalf("junction directory: %+v", res)
	}

	dir := makeAppDir(t, dsddl)
	makeFile(t, filepath.Join(dir, "service.log"), fsddl)
	makeJunction(t, filepath.Join(dir, "profile.json"), target)
	res, err = cleanDir(dir, pol)
	if err != nil {
		t.Fatal(err)
	}
	if res.Removed || len(res.Deleted) != 0 || len(res.Kept) == 0 {
		t.Fatalf("junction entry: %+v", res)
	}
	if _, err := os.Lstat(filepath.Join(target, "profile.json")); err != nil {
		t.Fatal("junction target content was deleted")
	}
}
