//go:build windows

package paths

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Security descriptors. Every object is owned by the built-in
// Administrators group and has a protected DACL ("P"), so nothing is
// inherited from the (user-writable) parent such as %ProgramData%.
const (
	// SecureSDDL is used for the data directory: full access for SYSTEM and
	// Administrators only. Children inherit it.
	SecureSDDL = `O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`
	// secureFileSDDL is the explicit descriptor of files in the data directory.
	secureFileSDDL = `O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)`

	// InstallSDDL is the descriptor the MSI package puts on the install
	// directory (PermissionEx in installer/AuraSplitTR.wxs; a test keeps
	// both equal): SYSTEM and Administrators full access, Users read &
	// execute. Files installed into it inherit it. The CLI never writes
	// there; setup only verifies it (IsTrustedAppDir / IsTrustedFile).
	InstallSDDL = `O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)`
)

// trustedInstallerSID is NT SERVICE\TrustedInstaller.
const trustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

// writeMask is every right that lets the holder change an object or its
// directory contents.
const writeMask = windows.GENERIC_ALL | windows.GENERIC_WRITE |
	windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA |
	0x40 /* FILE_DELETE_CHILD */ | windows.FILE_WRITE_ATTRIBUTES |
	windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER

// readMask is every right that lets the holder read file content. For the
// profile (private key) a read grant to an untrusted principal already
// makes the file untrusted: the key may have leaked.
const readMask = windows.GENERIC_ALL | windows.GENERIC_READ | windows.FILE_READ_DATA

const (
	// staleTempAge is how old one of our own staging files must be before
	// a sweep removes it; younger ones may belong to a writer in progress.
	staleTempAge = 10 * time.Minute
	// maxCopiedLog bounds how much of an untrusted log file is carried
	// over into its fresh replacement.
	maxCopiedLog = 8 << 20
)

// childKind says what a directory entry is to the application, which
// decides how an untrusted entry is handled.
type childKind int

const (
	// kindUnknown is not an application name: always moved to quarantine.
	kindUnknown childKind = iota
	// kindSecret (profile.json) is never reused when untrusted: it could
	// have been written by an attacker. It is quarantined and setup must be
	// run again.
	kindSecret
	// kindState (tunnel-state.json) is rewritten by the service; untrusted
	// content could fake readiness, so it is quarantined.
	kindState
	// kindLog (service.log, service.log.N): the content is copied into a
	// freshly created file that replaces the untrusted one.
	kindLog
	// kindTemp is one of our own staging files (".<name>.<hex>.tmp").
	kindTemp
)

type dirPolicy struct {
	dirSDDL        string
	fileSDDL       string
	quarantineSDDL string
	classify       func(name string) childKind
	// trusted reports whether sid may own or modify our objects.
	trusted func(sid *windows.SID) bool
}

var (
	dataPolicy = dirPolicy{
		dirSDDL: SecureSDDL, fileSDDL: secureFileSDDL, quarantineSDDL: SecureSDDL,
		classify: classifyData, trusted: isTrustedSID,
	}
)

var (
	tempNameRe   = regexp.MustCompile(`^\.(.+)\.[0-9a-f]{16}\.tmp$`)
	logBackupRe  = regexp.MustCompile(`^[1-9][0-9]?$`)
	errVanished  = errors.New("entry vanished")
	errUntrusted = errors.New("untrusted file")
	// errChanged: an entry was replaced between inspection and action. In a
	// trusted directory only SYSTEM/Administrators (for example the service
	// rewriting its state file) can do that, so the entry is inspected again.
	errChanged = errors.New("changed while it was inspected")
)

func classifyData(name string) childKind {
	switch {
	case strings.EqualFold(name, ProfileName):
		return kindSecret
	case strings.EqualFold(name, StateName), strings.EqualFold(name, RecoverStateName):
		return kindState
	case strings.EqualFold(name, LogName):
		return kindLog
	}
	if len(name) > len(LogName)+1 && strings.EqualFold(name[:len(LogName)+1], LogName+".") &&
		logBackupRe.MatchString(name[len(LogName)+1:]) {
		return kindLog
	}
	if m := tempNameRe.FindStringSubmatch(name); m != nil {
		if k := classifyData(m[1]); k != kindUnknown && k != kindTemp {
			return kindTemp
		}
	}
	return kindUnknown
}

func parseSD(sddl string) (*windows.SECURITY_DESCRIPTOR, error) {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("parse security descriptor: %w", err)
	}
	return sd, nil
}

func securityAttributes(sd *windows.SECURITY_DESCRIPTOR) *windows.SecurityAttributes {
	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
}

// EnsureSecureDir makes dir a trusted data directory: owned by
// Administrators, DACL SYSTEM + Administrators only (protected). A missing
// directory is created atomically with that descriptor.
//
// An existing directory is adopted only if it is a real directory (not a
// reparse point) whose owner and DACL (inherit-only entries included) never
// let a non-administrator modify it. Its descriptor is then reset and its
// entries are checked one by one: application files that are trusted keep
// their content and get the restricted descriptor; untrusted application
// files are replaced by freshly created files (log content is copied, the
// profile and the state file are not reused); everything else is moved
// into a quarantine directory next to dir, never deleted.
//
// An existing directory that fails the trust check is renamed to
// dir+QuarantineInfix+timestamp (kept for inspection, ACL restricted
// best effort) and recreated, because a non-administrator may still hold
// handles to it. If an entry cannot be inspected (sharing violation,
// access denied) nothing is moved or deleted and an error is returned.
// The parent must already exist and no ancestor may be a reparse point.
func EnsureSecureDir(dir string) error { return ensureDir(dir, dataPolicy) }

// The program directory (%ProgramFiles%\AuraSplitTR) is owned by Windows
// Installer: it is created, secured (InstallSDDL) and cleaned by the MSI
// package, never swept or rewritten by the CLI.

func ensureDir(dir string, pol dirPolicy) error {
	if dir == "" {
		return errors.New("empty directory path")
	}
	dir = filepath.Clean(dir)
	if !filepath.IsAbs(dir) || strings.HasPrefix(dir, `\\`) {
		return fmt.Errorf("directory must be an absolute local path: %s", dir)
	}
	if err := checkAncestors(dir); err != nil {
		return err
	}
	sd, err := parseSD(pol.dirSDDL)
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	err = windows.CreateDirectory(p, securityAttributes(sd))
	if err == nil {
		return nil
	}
	if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}
	return adoptDir(dir, pol, sd)
}

// checkAncestors refuses a path whose parent chain contains a reparse
// point (junction, symbolic link, mount point).
func checkAncestors(dir string) error {
	for cur := filepath.Dir(dir); ; {
		p, err := windows.UTF16PtrFromString(cur)
		if err != nil {
			return err
		}
		attrs, err := windows.GetFileAttributes(p)
		if err != nil {
			return fmt.Errorf("parent directory %s: %w", cur, err)
		}
		if attrs&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			return fmt.Errorf("parent %s is not a directory", cur)
		}
		// A volume root reports no reparse attribute; anything else that
		// does is a junction or link and could redirect us.
		if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return fmt.Errorf("parent directory %s is a reparse point (link); refusing to use it", cur)
		}
		next := filepath.Dir(cur)
		if next == cur {
			return nil
		}
		cur = next
	}
}

// openNoFollow opens path itself (never the target of a link).
func openNoFollow(path string, access uint32) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(p, access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
}

func handleInfo(h windows.Handle) (windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	err := windows.GetFileInformationByHandle(h, &info)
	return info, err
}

// fileKey identifies a file object: volume serial number plus file index.
type fileKey struct{ volume, high, low uint32 }

func keyOf(info windows.ByHandleFileInformation) fileKey {
	return fileKey{info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow}
}

func isTrustedSID(sid *windows.SID) bool {
	if sid == nil {
		return false
	}
	if sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return true
	}
	return sid.String() == trustedInstallerSID
}

// objectTrusted reports whether only trusted principals own or can modify
// the object behind h. A false result with a nil error is proof of
// untrustworthiness; a non-nil error means the object could not be
// inspected.
func objectTrusted(h windows.Handle, trusted func(*windows.SID) bool) (bool, error) {
	return objectTrustedMask(h, trusted, writeMask)
}

// objectTrustedMask is objectTrusted with the set of rights that an
// untrusted principal must not hold.
func objectTrustedMask(h windows.Handle, trusted func(*windows.SID) bool, mask uint32) (bool, error) {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, fmt.Errorf("read security descriptor: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return false, fmt.Errorf("read owner: %w", err)
	}
	if !trusted(owner) {
		return false, nil
	}
	dacl, _, err := sd.DACL()
	if errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) || (err == nil && dacl == nil) {
		// No DACL / NULL DACL grants everyone full access.
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read DACL: %w", err)
	}
	return daclTrustedMask(dacl, trusted, mask)
}

// daclTrusted reports whether no ACE grants a modifying right to an
// untrusted principal. Inherit-only ACEs count too: they are copied onto
// every new child. Object and callback ACEs never appear on our objects and
// are treated as suspicious.
func daclTrusted(dacl *windows.ACL, trusted func(*windows.SID) bool) (bool, error) {
	return daclTrustedMask(dacl, trusted, writeMask)
}

func daclTrustedMask(dacl *windows.ACL, trusted func(*windows.SID) bool, mask uint32) (bool, error) {
	if dacl == nil {
		return false, nil
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return false, fmt.Errorf("read ACE %d: %w", i, err)
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			return false, nil
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if uint32(ace.Mask)&mask != 0 && !trusted(sid) {
			return false, nil
		}
	}
	return true, nil
}

// applySD sets the protected DACL (and the owner, if sd has one) from sd on
// the object behind h.
func applySD(h windows.Handle, sd *windows.SECURITY_DESCRIPTOR) error {
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("read owner: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read DACL: %w", err)
	}
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if owner != nil {
		info |= windows.OWNER_SECURITY_INFORMATION
	}
	return windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, info, owner, nil, dacl, nil)
}

func adoptDir(dir string, pol dirPolicy, sd *windows.SECURITY_DESCRIPTOR) error {
	// Inspect with read-only rights first: an untrusted descriptor may deny
	// us WRITE_DAC, and that alone proves nothing.
	h, err := openNoFollow(dir, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return fmt.Errorf("inspect directory %s (in use or access denied; nothing was changed): %w", dir, err)
	}
	info, err := handleInfo(h)
	if err == nil && checkDirInfo(dir, info) != nil {
		// A link or a file at our directory name (for example planted by a
		// standard user before the first install) is renamed aside like an
		// untrusted directory. MoveFileEx renames the link itself, never
		// its target.
		windows.CloseHandle(h)
		return replaceUntrustedDir(dir, pol, sd, info)
	}
	trusted := false
	if err == nil {
		if trusted, err = objectTrusted(h, pol.trusted); err != nil {
			err = fmt.Errorf("inspect security of %s (nothing was changed): %w", dir, err)
		}
	}
	windows.CloseHandle(h)
	if err != nil {
		return err
	}
	if !trusted {
		return replaceUntrustedDir(dir, pol, sd, info)
	}
	h, err = openNoFollow(dir, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return fmt.Errorf("open directory %s to reset its security: %w", dir, err)
	}
	again, err := handleInfo(h)
	if err == nil && keyOf(again) != keyOf(info) {
		err = fmt.Errorf("directory %s changed while it was inspected", dir)
	}
	if err == nil {
		if err = applySD(h, sd); err != nil {
			err = fmt.Errorf("set security on %s: %w", dir, err)
		}
	}
	windows.CloseHandle(h)
	if err != nil {
		return err
	}
	return sweepChildren(dir, pol)
}

func checkDirInfo(dir string, info windows.ByHandleFileInformation) error {
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%s is a reparse point (link); refusing to use it, delete it and retry", dir)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return fmt.Errorf("%s exists but is not a directory", dir)
	}
	return nil
}

// quarantineName returns a new, unique name next to dir.
func quarantineName(dir string) (string, error) {
	var suffix [3]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", err
	}
	return dir + QuarantineInfix + time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(suffix[:]), nil
}

func moveFile(from, to string) error {
	f, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	t, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(f, t, windows.MOVEFILE_WRITE_THROUGH)
}

// replaceUntrustedDir renames an untrusted directory to a quarantine name
// (kept, not deleted) and creates a fresh one. Handles another user may
// still hold follow the old directory.
//
// info is what was inspected; only a real directory with that file ID gets
// the quarantine descriptor afterwards (see protectQuarantine).
func replaceUntrustedDir(dir string, pol dirPolicy, sd *windows.SECURITY_DESCRIPTOR, info windows.ByHandleFileInformation) error {
	quarantine, err := quarantineName(dir)
	if err != nil {
		return err
	}
	if err := moveFile(dir, quarantine); err != nil {
		return fmt.Errorf("%s is not trusted (a link, a file, or owner/ACL lets non-administrators modify it) and cannot be moved aside; move it away manually and retry: %w", dir, err)
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	if err := windows.CreateDirectory(p, securityAttributes(sd)); err != nil {
		return fmt.Errorf("recreate directory %s (untrusted content kept in %s): %w", dir, quarantine, err)
	}
	// Best effort: the quarantined content is no longer used, the ACL only
	// keeps other users away from what it may contain.
	if checkDirInfo(dir, info) == nil {
		_ = protectQuarantine(quarantine, pol, keyOf(info))
	}
	return nil
}

// protectQuarantine gives the quarantine directory itself the restricted
// descriptor (children keep theirs). If the current DACL denies us, the
// restore and take-ownership privileges of the elevated token are used.
//
// The name is re-opened, so another object may have been put there in the
// meantime (the previous owner can rename the moved directory away). The
// descriptor is applied only if the opened object is a real directory with
// the file ID that was inspected before the move.
func protectQuarantine(q string, pol dirPolicy, want fileKey) error {
	sd, err := parseSD(pol.quarantineSDDL)
	if err != nil {
		return err
	}
	apply := func() error {
		h, err := openNoFollow(q, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER|windows.FILE_READ_ATTRIBUTES)
		if err != nil {
			return err
		}
		defer windows.CloseHandle(h)
		info, err := handleInfo(h)
		if err != nil {
			return err
		}
		if checkDirInfo(q, info) != nil || keyOf(info) != want {
			return errChanged
		}
		return applySD(h, sd)
	}
	err = apply()
	if err == nil || errors.Is(err, errChanged) {
		return err
	}
	return withPrivileges([]string{"SeRestorePrivilege", "SeTakeOwnershipPrivilege"}, apply)
}

// withPrivileges enables the named privileges of the process token for the
// duration of fn and restores their previous state afterwards.
func withPrivileges(names []string, fn func() error) error {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		return err
	}
	defer tok.Close()
	type privileges struct {
		count uint32
		privs [4]windows.LUIDAndAttributes
	}
	if len(names) > 4 {
		return errors.New("too many privileges")
	}
	var want, prev privileges
	for i, name := range names {
		n, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return err
		}
		if err := windows.LookupPrivilegeValue(nil, n, &want.privs[i].Luid); err != nil {
			return err
		}
		want.privs[i].Attributes = windows.SE_PRIVILEGE_ENABLED
	}
	want.count = uint32(len(names))
	var retLen uint32
	if err := windows.AdjustTokenPrivileges(tok, false, (*windows.Tokenprivileges)(unsafe.Pointer(&want)),
		uint32(unsafe.Sizeof(prev)), (*windows.Tokenprivileges)(unsafe.Pointer(&prev)), &retLen); err != nil {
		return err
	}
	defer windows.AdjustTokenPrivileges(tok, false, (*windows.Tokenprivileges)(unsafe.Pointer(&prev)), 0, nil, nil)
	return fn()
}

// sweeper checks the entries of an adopted directory.
type sweeper struct {
	dir    string
	pol    dirPolicy
	fileSD *windows.SECURITY_DESCRIPTOR
	qdir   string // quarantine for entries, created on first use
}

func newSweeper(dir string, pol dirPolicy) (*sweeper, error) {
	fileSD, err := parseSD(pol.fileSDDL)
	if err != nil {
		return nil, err
	}
	return &sweeper{dir: dir, pol: pol, fileSD: fileSD}, nil
}

// sweepChildren applies the child policy to every entry of dir.
func sweepChildren(dir string, pol dirPolicy) error {
	s, err := newSweeper(dir, pol)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("list %s: %w", dir, err)
	}
	for _, e := range entries {
		if err := s.handle(e.Name()); err != nil {
			return err
		}
	}
	return nil
}

type childState struct {
	plain    bool // regular file with exactly one link
	trusted  bool // owner and DACL trusted (only meaningful when plain)
	key      fileKey
	modified time.Time
}

// inspectMask opens child without following links and with read-only
// rights; mask lists the rights untrusted principals must not hold. It
// returns errVanished if child no longer exists, and any other error if it
// cannot be inspected (sharing violation, access denied).
func (s *sweeper) inspectMask(child string, mask uint32) (childState, error) {
	var st childState
	h, err := openNoFollow(child, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return st, errVanished
		}
		return st, err
	}
	defer windows.CloseHandle(h)
	info, err := handleInfo(h)
	if err != nil {
		return st, err
	}
	st.key = keyOf(info)
	st.modified = time.Unix(0, info.LastWriteTime.Nanoseconds())
	st.plain = info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) == 0 &&
		info.NumberOfLinks == 1
	if !st.plain {
		return st, nil
	}
	st.trusted, err = objectTrustedMask(h, s.pol.trusted, mask)
	return st, err
}

// handle applies the policy to one entry of s.dir, inspecting it again
// (a few times) if it is replaced meanwhile.
func (s *sweeper) handle(name string) error {
	var err error
	for i := 0; i < 3; i++ {
		err = s.handleOnce(name)
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return nil // removed meanwhile (by a trusted writer)
		}
		if !errors.Is(err, errChanged) {
			return err
		}
	}
	return err
}

func (s *sweeper) handleOnce(name string) error {
	child := filepath.Join(s.dir, name)
	kind := s.pol.classify(name)
	mask := uint32(writeMask)
	if kind == kindSecret {
		mask |= readMask
	}
	st, err := s.inspectMask(child, mask)
	if errors.Is(err, errVanished) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot inspect %s (in use or access denied; nothing was changed): %w", child, err)
	}
	if !st.plain || kind == kindUnknown {
		// Links, reparse points, directories and foreign names are never
		// used; keep them for inspection.
		return s.quarantine(child)
	}
	if kind == kindTemp {
		if !st.trusted {
			return s.quarantine(child)
		}
		if time.Since(st.modified) > staleTempAge {
			if err := os.Remove(child); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove stale temporary file %s: %w", child, err)
			}
		}
		return nil
	}
	if st.trusted {
		return s.resetSecurity(child, st.key)
	}
	if kind == kindLog {
		return s.replaceWithCopy(child, st.key)
	}
	// Profile, state and program: untrusted content is not reused.
	return s.quarantine(child)
}

// quarantine moves child into the quarantine directory of s.dir.
func (s *sweeper) quarantine(child string) error {
	created := false
	if s.qdir == "" {
		q, err := quarantineName(s.dir)
		if err != nil {
			return err
		}
		sd, err := parseSD(s.pol.quarantineSDDL)
		if err != nil {
			return err
		}
		p, err := windows.UTF16PtrFromString(q)
		if err != nil {
			return err
		}
		if err := windows.CreateDirectory(p, securityAttributes(sd)); err != nil {
			return fmt.Errorf("create quarantine directory %s: %w", q, err)
		}
		s.qdir, created = q, true
	}
	if err := moveFile(child, filepath.Join(s.qdir, filepath.Base(child))); err != nil {
		q := s.qdir
		if created {
			// Do not leave an empty quarantine behind.
			if p, perr := windows.UTF16PtrFromString(q); perr == nil && windows.RemoveDirectory(p) == nil {
				s.qdir = ""
			}
		}
		return fmt.Errorf("cannot move unexpected entry %s to %s (in use?; nothing was deleted): %w", child, q, err)
	}
	return nil
}

// resetSecurity gives a trusted application file the restricted descriptor.
func (s *sweeper) resetSecurity(child string, key fileKey) error {
	h, err := openNoFollow(child, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return fmt.Errorf("open %s to reset its security: %w", child, err)
	}
	defer windows.CloseHandle(h)
	info, err := handleInfo(h)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", child, err)
	}
	if keyOf(info) != key {
		return fmt.Errorf("%s: %w", child, errChanged)
	}
	if err := applySD(h, s.fileSD); err != nil {
		return fmt.Errorf("set security on %s: %w", child, err)
	}
	return nil
}

// replaceWithCopy copies an untrusted log file into a new file created with
// the restricted descriptor and moves that over it. Handles others may hold
// keep pointing at the old, now unlinked file.
func (s *sweeper) replaceWithCopy(child string, key fileKey) error {
	p, err := windows.UTF16PtrFromString(child)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return fmt.Errorf("open untrusted %s for copying (nothing was changed): %w", child, err)
	}
	src := os.NewFile(uintptr(h), child)
	defer src.Close()
	info, err := handleInfo(h)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", child, err)
	}
	if keyOf(info) != key {
		return fmt.Errorf("%s: %w", child, errChanged)
	}
	tmp, err := randomTempName(s.dir, filepath.Base(child))
	if err != nil {
		return err
	}
	dst, err := createNew(tmp, s.pol.fileSDDL)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := io.Copy(dst, io.LimitReader(src, maxCopiedLog)); err != nil {
		dst.Close()
		return fmt.Errorf("copy %s: %w", child, err)
	}
	if err := dst.Sync(); err != nil {
		dst.Close()
		return err
	}
	if err := dst.Close(); err != nil {
		return err
	}
	src.Close()
	if err := ReplaceFile(tmp, child); err != nil {
		return err
	}
	ok = true
	return nil
}

// createNew creates path exclusively (CREATE_NEW never follows or reuses
// an existing name) with the given descriptor applied at creation.
func createNew(path string, sddl string) (*os.File, error) {
	sd, err := parseSD(sddl)
	if err != nil {
		return nil, err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER,
		0, securityAttributes(sd), windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", path, err)
	}
	// Re-apply in case the volume ignored the creation descriptor.
	if err := applySD(h, sd); err != nil {
		windows.CloseHandle(h)
		_ = os.Remove(path)
		return nil, fmt.Errorf("set security on %s: %w", path, err)
	}
	return os.NewFile(uintptr(h), path), nil
}

func randomTempName(dir, base string) (string, error) {
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", err
	}
	return filepath.Join(dir, "."+base+"."+hex.EncodeToString(suffix[:])+".tmp"), nil
}

// ReplaceFile atomically moves src over dst (MoveFileEx with
// MOVEFILE_REPLACE_EXISTING). If dst is a link, the link itself is replaced.
func ReplaceFile(src, dst string) error {
	from, err := windows.UTF16PtrFromString(src)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(dst)
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return fmt.Errorf("replace %s: %w", dst, err)
	}
	return nil
}

// WriteSecureFile atomically writes data to path. The directory is secured
// with EnsureSecureDir; the data goes to a randomly named temporary file in
// the same directory that is created exclusively with the restricted
// descriptor, and the temporary file then replaces path.
func WriteSecureFile(path string, data []byte) error {
	if err := EnsureSecureDir(filepath.Dir(path)); err != nil {
		return err
	}
	return WriteSecureFileInDir(path, data)
}

// WriteSecureFileInDir is WriteSecureFile for a directory this process has
// already secured with EnsureSecureDir (for example the service writing its
// state every 30 seconds); it does not sweep the directory again.
func WriteSecureFileInDir(path string, data []byte) error {
	tmp, err := stageSecure(path, data)
	if err != nil {
		return err
	}
	if err := ReplaceFile(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// StageSecureFile secures the directory of path and writes data to a new,
// randomly named temporary file next to path with the restricted
// descriptor. It returns the temporary file's path; the caller later moves
// it into place with ReplaceFile or removes it.
func StageSecureFile(path string, data []byte) (string, error) {
	if err := EnsureSecureDir(filepath.Dir(path)); err != nil {
		return "", err
	}
	return stageSecure(path, data)
}

func stageSecure(path string, data []byte) (string, error) {
	tmp, err := randomTempName(filepath.Dir(path), filepath.Base(path))
	if err != nil {
		return "", err
	}
	f, err := createNew(tmp, secureFileSDDL)
	if err != nil {
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return "", fmt.Errorf("write temp file: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return "", fmt.Errorf("sync temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("close temp file: %w", err)
	}
	return tmp, nil
}

// OpenSecureAppend opens (or creates) path for appending. The directory must
// have been secured with EnsureSecureDir. The file itself is opened without
// following links and accepted only if it is a regular file with exactly one
// link whose owner and DACL are trusted. Otherwise the entry is handled like
// an untrusted entry during EnsureSecureDir (a log is replaced by a fresh
// copy, anything else is quarantined) and opened once more. It returns the
// file and its current size. Other processes may only read it while it is
// open.
func OpenSecureAppend(path string) (*os.File, int64, error) {
	f, size, err := openAppendVerified(path, dataPolicy)
	if err == nil {
		return f, size, nil
	}
	if !errors.Is(err, errUntrusted) {
		return nil, 0, err
	}
	s, serr := newSweeper(filepath.Dir(path), dataPolicy)
	if serr != nil {
		return nil, 0, serr
	}
	if serr := s.handle(filepath.Base(path)); serr != nil {
		return nil, 0, serr
	}
	return openAppendVerified(path, dataPolicy)
}

func openAppendVerified(path string, pol dirPolicy) (*os.File, int64, error) {
	sd, err := parseSD(pol.fileSDDL)
	if err != nil {
		return nil, 0, err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, 0, err
	}
	h, err := windows.CreateFile(p,
		windows.FILE_APPEND_DATA|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ, securityAttributes(sd), windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, 0, fmt.Errorf("open %s: %w", path, err)
	}
	info, err := handleInfo(h)
	if err != nil {
		windows.CloseHandle(h)
		return nil, 0, fmt.Errorf("inspect %s: %w", path, err)
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 ||
		info.NumberOfLinks != 1 {
		windows.CloseHandle(h)
		return nil, 0, fmt.Errorf("%s: %w (link, reparse point or directory)", path, errUntrusted)
	}
	ok, err := objectTrusted(h, pol.trusted)
	if err != nil {
		windows.CloseHandle(h)
		return nil, 0, fmt.Errorf("inspect %s: %w", path, err)
	}
	if !ok {
		windows.CloseHandle(h)
		return nil, 0, fmt.Errorf("%s: %w (owner or ACL is not SYSTEM/Administrators only)", path, errUntrusted)
	}
	size := int64(info.FileSizeHigh)<<32 | int64(info.FileSizeLow)
	return os.NewFile(uintptr(h), path), size, nil
}

// IsTrustedAppDir reports whether path is a real directory (not a link or
// other reparse point) whose owner and DACL only let SYSTEM,
// Administrators or TrustedInstaller modify it. It is used before showing
// quarantine directories to an administrator (any user can create entries
// with those names in %ProgramData%) and by setup to verify the
// MSI-installed program directory. Nothing is changed.
func IsTrustedAppDir(path string) (bool, error) {
	h, err := openNoFollow(path, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(h)
	info, err := handleInfo(h)
	if err != nil {
		return false, err
	}
	if checkDirInfo(path, info) != nil {
		return false, nil
	}
	return objectTrusted(h, isTrustedSID)
}

// IsTrustedFile reports whether path is a regular file (not a directory,
// link or other reparse point, exactly one hard link) whose owner and DACL
// only let SYSTEM, Administrators or TrustedInstaller modify it. setup uses
// it for the MSI-installed aurasplit.exe, which the LocalSystem service
// runs. Nothing is changed.
func IsTrustedFile(path string) (bool, error) {
	h, err := openNoFollow(path, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(h)
	info, err := handleInfo(h)
	if err != nil {
		return false, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 ||
		info.NumberOfLinks != 1 {
		return false, nil
	}
	return objectTrusted(h, isTrustedSID)
}
