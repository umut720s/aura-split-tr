//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// selfImage is a read handle to the running executable, opened at startup
// for setup with FILE_SHARE_READ only. setup uses it to decide by file
// identity (not by path text) that it runs from the MSI-installed
// aurasplit.exe; while the handle is open the file cannot be written,
// renamed or deleted, so that decision stays true until setup ends.
// selfImageErr records why it could not be opened.
var (
	selfImage    *os.File
	selfImageErr error
)

var procGetMappedFileNameW = windows.NewLazySystemDLL("kernel32.dll").NewProc("K32GetMappedFileNameW")

// openSelfImage opens the path the running module was loaded from and
// verifies, by volume serial and file index, that the opened file is the
// one actually mapped as this process image (the path could have been
// re-pointed between process start and this call).
func openSelfImage() (*os.File, error) {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetModuleFileName(0, &buf[0], uint32(len(buf)))
	if err != nil {
		return nil, fmt.Errorf("module file name: %w", err)
	}
	path := windows.UTF16ToString(buf[:n])
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, fmt.Errorf("open running executable: %w", err)
	}
	f := os.NewFile(uintptr(h), path)
	opened, err := fileID(h)
	if err != nil {
		f.Close()
		return nil, err
	}
	mapped, err := mappedImageID()
	if err != nil {
		f.Close()
		return nil, err
	}
	if opened != mapped {
		f.Close()
		return nil, errors.New("the executable file on disk is not the running program (it was replaced)")
	}
	return f, nil
}

// sameFileAsImage reports whether path exists and is, by volume serial and
// file index, the file pinned by selfImage (the running image). A missing
// path is (false, nil). A link, reparse point or file with several names is
// never considered the same, so setup refuses to run from it.
func sameFileAsImage(path string) (bool, error) {
	if selfImage == nil {
		return false, errors.New("running executable was not opened")
	}
	self, err := fileID(windows.Handle(selfImage.Fd()))
	if err != nil {
		return false, err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}
	h, err := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("open %s: %w", path, err)
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return false, fmt.Errorf("file information: %w", err)
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || info.NumberOfLinks != 1 {
		return false, nil
	}
	other := fileIdentity{volume: info.VolumeSerialNumber, indexHigh: info.FileIndexHigh, indexLow: info.FileIndexLow}
	return other == self, nil
}

// fileIdentity is the volume serial number plus the NTFS file index.
type fileIdentity struct {
	volume, indexHigh, indexLow uint32
}

func fileID(h windows.Handle) (fileIdentity, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return fileIdentity{}, fmt.Errorf("file information: %w", err)
	}
	return fileIdentity{volume: info.VolumeSerialNumber, indexHigh: info.FileIndexHigh, indexLow: info.FileIndexLow}, nil
}

// mappedImageID returns the identity of the file mapped as the process
// image. GetMappedFileName follows renames of the mapped file.
func mappedImageID() (fileIdentity, error) {
	var base windows.Handle
	const unchangedRefcount = 0x2 // GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT
	if err := windows.GetModuleHandleEx(unchangedRefcount, nil, &base); err != nil {
		return fileIdentity{}, fmt.Errorf("module handle: %w", err)
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	r, _, callErr := procGetMappedFileNameW.Call(uintptr(windows.CurrentProcess()), uintptr(base),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if r == 0 {
		return fileIdentity{}, fmt.Errorf("mapped image name: %w", callErr)
	}
	device := windows.UTF16ToString(buf[:r])
	p, err := windows.UTF16PtrFromString(`\\?\GLOBALROOT` + device)
	if err != nil {
		return fileIdentity{}, err
	}
	h, err := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return fileIdentity{}, fmt.Errorf("open mapped image: %w", err)
	}
	defer windows.CloseHandle(h)
	return fileID(h)
}
