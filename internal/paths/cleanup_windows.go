//go:build windows

package paths

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CleanResult describes what CleanDataDir did. It never contains file
// contents.
type CleanResult struct {
	// Missing: the directory did not exist; nothing to do.
	Missing bool
	// Deleted lists the application files that were deleted.
	Deleted []string
	// Removed: the directory itself was deleted (it was empty afterwards).
	Removed bool
	// Kept explains why the directory (or some of it) was left in place for
	// manual inspection. Empty when everything was removed.
	Kept []string
}

// cleanEntry is one directory entry as inspected through handles.
type cleanEntry struct {
	name    string
	kind    childKind
	plain   bool // regular file, not a reparse point, exactly one link
	trusted bool // owner and DACL trusted (meaningful only when plain)
	err     error
}

// planCleanup decides whether the inspected entries may be deleted. It is
// all or nothing: any entry that is not one of our own plain, trusted
// files (or could not be inspected) keeps everything. Pure (unit-tested).
func planCleanup(entries []cleanEntry) (ok bool, reasons []string) {
	for _, e := range entries {
		switch {
		case e.err != nil:
			reasons = append(reasons, fmt.Sprintf("%s: cannot be inspected (in use or access denied): %v", e.name, e.err))
		case e.kind == kindUnknown:
			reasons = append(reasons, e.name+": not an AURA Split TR file")
		case !e.plain:
			reasons = append(reasons, e.name+": not a regular file (directory, link or hard-linked)")
		case !e.trusted:
			reasons = append(reasons, e.name+": owner or ACL is not SYSTEM/Administrators only")
		}
	}
	return len(reasons) == 0, reasons
}

// CleanDataDir removes the application's own files from the data directory
// (%ProgramData%\AuraSplitTR) and then the directory itself if it is empty.
// It is used by `uninstall --msi` (run by the MSI as LocalSystem) and never
// follows a link:
//
//   - The directory is opened once, without following reparse points, with
//     a share mode that excludes FILE_SHARE_DELETE, and that handle is held
//     until the end. While it is held nobody can rename, delete or replace
//     the directory, so every later operation is on the inspected object.
//   - It must be a real directory (not a reparse point) whose owner and
//     DACL are trusted (SYSTEM/Administrators/TrustedInstaller only), and
//     no ancestor may be a reparse point. Otherwise nothing is deleted.
//   - Entries are listed through the held handle and every entry is opened
//     relative to it (NtCreateFile with RootDirectory, OBJ_DONT_REPARSE,
//     FILE_OPEN_REPARSE_POINT). Each must be one of our names (profile,
//     state, log, log backups, our staging files), a regular file with one
//     link, and trusted. If anything else is present or an entry cannot be
//     inspected, nothing at all is deleted.
//   - The inspected handles stay open and are deleted through those same
//     handles (FILE_DISPOSITION_INFO), so no name is resolved twice.
//   - The directory is deleted through its held handle only if it is empty
//     afterwards.
//
// Anything left in place is reported in CleanResult.Kept; that is not an
// error. The error result is reserved for invalid arguments.
func CleanDataDir(dir string) (CleanResult, error) {
	return cleanDir(dir, dataPolicy)
}

func cleanDir(dir string, pol dirPolicy) (CleanResult, error) {
	var res CleanResult
	dir = filepath.Clean(dir)
	if !filepath.IsAbs(dir) || strings.HasPrefix(dir, `\\`) {
		return res, fmt.Errorf("directory must be an absolute local path: %s", dir)
	}
	if !strings.EqualFold(filepath.Base(dir), AppDirName) {
		return res, fmt.Errorf("unexpected directory, not touched: %s", dir)
	}
	keep := func(reason string) (CleanResult, error) {
		res.Kept = append(res.Kept, reason)
		return res, nil
	}
	if err := checkAncestors(dir); err != nil {
		return keep(err.Error())
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return res, err
	}
	h, err := windows.CreateFile(p,
		windows.FILE_LIST_DIRECTORY|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES|windows.DELETE|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		res.Missing = true
		return res, nil
	}
	if err != nil {
		return keep(fmt.Sprintf("directory cannot be opened exclusively (in use or access denied): %v", err))
	}
	defer windows.CloseHandle(h)
	info, err := handleInfo(h)
	if err != nil {
		return keep(fmt.Sprintf("directory cannot be inspected: %v", err))
	}
	if err := checkDirInfo(dir, info); err != nil {
		return keep(err.Error())
	}
	trusted, err := objectTrusted(h, pol.trusted)
	if err != nil {
		return keep(fmt.Sprintf("directory security cannot be read: %v", err))
	}
	if !trusted {
		return keep("directory owner or ACL lets non-administrators modify it (possibly created by another user)")
	}

	names, err := listDir(h)
	if err != nil {
		return keep(fmt.Sprintf("directory cannot be listed: %v", err))
	}
	type opened struct {
		name string
		h    windows.Handle
	}
	var handles []opened
	defer func() {
		for _, o := range handles {
			windows.CloseHandle(o.h)
		}
	}()
	entries := make([]cleanEntry, 0, len(names))
	for _, name := range names {
		e := cleanEntry{name: name, kind: pol.classify(name)}
		if e.kind != kindUnknown {
			ch, err := openRelative(h, name, windows.DELETE|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE)
			if err != nil {
				e.err = err
			} else {
				handles = append(handles, opened{name, ch})
				ci, err := handleInfo(ch)
				if err != nil {
					e.err = err
				} else {
					e.plain = ci.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) == 0 &&
						ci.NumberOfLinks == 1
					if e.plain {
						e.trusted, e.err = objectTrusted(ch, pol.trusted)
					}
				}
			}
		}
		entries = append(entries, e)
	}
	ok, reasons := planCleanup(entries)
	if !ok {
		res.Kept = append(res.Kept, reasons...)
		return res, nil
	}
	for i := range handles {
		if err := deleteByHandle(handles[i].h); err != nil {
			res.Kept = append(res.Kept, fmt.Sprintf("%s: delete failed: %v", handles[i].name, err))
			continue
		}
		res.Deleted = append(res.Deleted, handles[i].name)
	}
	// Close the children so a deletion without POSIX semantics completes
	// before the emptiness check.
	for _, o := range handles {
		windows.CloseHandle(o.h)
	}
	handles = nil
	if len(res.Kept) > 0 {
		return res, nil
	}
	left, err := listDir(h)
	if err != nil {
		return keep(fmt.Sprintf("directory cannot be listed after cleanup: %v", err))
	}
	if len(left) > 0 {
		return keep(fmt.Sprintf("directory not empty after cleanup (%d new entries); left in place", len(left)))
	}
	if err := deleteByHandle(h); err != nil {
		return keep(fmt.Sprintf("empty directory could not be deleted: %v", err))
	}
	res.Removed = true
	return res, nil
}

// openRelative opens name inside the directory behind dir without
// following any reparse point (the name is resolved relative to the held
// directory handle, never through a path). Other processes may keep
// reading but not writing or deleting while the handle is open.
func openRelative(dir windows.Handle, name string, access uint32) (windows.Handle, error) {
	if name == "" || strings.ContainsAny(name, `\/:`) || name == "." || name == ".." {
		return windows.InvalidHandle, fmt.Errorf("invalid entry name %q", name)
	}
	us, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return windows.InvalidHandle, err
	}
	oa := windows.OBJECT_ATTRIBUTES{
		RootDirectory: dir,
		ObjectName:    us,
		Attributes:    windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
	}
	oa.Length = uint32(unsafe.Sizeof(oa))
	var iosb windows.IO_STATUS_BLOCK
	var h windows.Handle
	err = windows.NtCreateFile(&h, access, &oa, &iosb, nil, 0,
		windows.FILE_SHARE_READ, windows.FILE_OPEN,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return h, nil
}

// deleteByHandle marks the object behind h for deletion. POSIX semantics
// (Windows 10 1709+) remove the name at once even if another process still
// has the file open with FILE_SHARE_DELETE; older systems fall back to the
// classic disposition (deleted when the last handle closes).
func deleteByHandle(h windows.Handle) error {
	flags := uint32(windows.FILE_DISPOSITION_DELETE | windows.FILE_DISPOSITION_POSIX_SEMANTICS |
		windows.FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE)
	err := windows.SetFileInformationByHandle(h, windows.FileDispositionInfoEx, (*byte)(unsafe.Pointer(&flags)), uint32(unsafe.Sizeof(flags)))
	if err == nil {
		return nil
	}
	del := byte(1) // FILE_DISPOSITION_INFO.DeleteFile
	if err2 := windows.SetFileInformationByHandle(h, windows.FileDispositionInfo, &del, 1); err2 != nil {
		return fmt.Errorf("%v (extended: %v)", err2, err)
	}
	return nil
}

// listDir lists the entry names of the directory behind h (without "." and
// ".."), through the handle (FILE_FULL_DIR_INFO), restarting the scan.
func listDir(h windows.Handle) ([]string, error) {
	// FILE_FULL_DIR_INFO: NextEntryOffset@0, FileAttributes@56,
	// FileNameLength@60 (bytes), FileName@68 (UTF-16).
	const (
		offNext    = 0
		offNameLen = 60
		offName    = 68
	)
	buf := make([]uint64, 8192) // 64 KiB, 8-byte aligned
	raw := unsafe.Slice((*byte)(unsafe.Pointer(&buf[0])), len(buf)*8)
	class := uint32(windows.FileFullDirectoryRestartInfo)
	var names []string
	for {
		err := windows.GetFileInformationByHandleEx(h, class, &raw[0], uint32(len(raw)))
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			return names, nil
		}
		if err != nil {
			return nil, err
		}
		class = windows.FileFullDirectoryInfo
		for off := 0; ; {
			if off+offName > len(raw) {
				return nil, errors.New("malformed directory listing")
			}
			next := int(*(*uint32)(unsafe.Pointer(&raw[off+offNext])))
			n := int(*(*uint32)(unsafe.Pointer(&raw[off+offNameLen])))
			if n%2 != 0 || off+offName+n > len(raw) {
				return nil, errors.New("malformed directory listing")
			}
			u := unsafe.Slice((*uint16)(unsafe.Pointer(&raw[off+offName])), n/2)
			if name := string(utf16.Decode(u)); name != "." && name != ".." {
				names = append(names, name)
			}
			if next == 0 {
				break
			}
			off += next
		}
	}
}
