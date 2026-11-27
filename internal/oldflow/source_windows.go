//go:build windows

package oldflow

import (
	"fmt"
	"golang.org/x/sys/windows"
	"strings"
	"time"
	"unsafe"
)

type WindowsSource struct{ Manifest []string }

func imageOf(h windows.Handle) (string, error) {
	buf := make([]uint16, 32768)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:n]), nil
}

func (s WindowsSource) Processes() ([]Process, error) {
	h, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)
	e := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	err = windows.Process32First(h, &e)
	var out []Process
	for err == nil {
		if e.ProcessID != 0 {
			item := Process{PID: e.ProcessID, ParentPID: e.ParentProcessID, Name: windows.UTF16ToString(e.ExeFile[:])}
			item.SessionKnown = windows.ProcessIdToSessionId(e.ProcessID, &item.SessionID) == nil
			p, pe := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, e.ProcessID)
			if pe == nil {
				item.Image, pe = imageOf(p)
				var created, exited, kernel, user windows.Filetime
				// Creation identity remains useful even when the image is unreadable.
				te := windows.GetProcessTimes(p, &created, &exited, &kernel, &user)
				if te == nil {
					item.Started = time.Unix(0, created.Nanoseconds())
				} else if pe == nil {
					pe = te
				}
				windows.CloseHandle(p)
			}
			item.Unresolved = pe != nil
			// Preserve failures for ancestry and remembered-identity checks in Gate.
			out = append(out, item)
		}
		err = windows.Process32Next(h, &e)
	}
	if err != windows.ERROR_NO_MORE_FILES {
		return nil, err
	}
	return out, nil
}

// CloseConsented is called only after an explicit default-No interactive consent.
// The same handle is queried and terminated; no TCP tuple mutation is allowed.
func CloseConsented(entries []string) error {
	procs, err := (WindowsSource{Manifest: entries}).Processes()
	if err != nil {
		return err
	}
	for _, p := range procs {
		if !Matches(p.Image, entries) {
			continue
		}
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE, false, p.PID)
		if err != nil {
			return err
		}
		image, err := imageOf(h)
		if err == nil {
			if Matches(image, entries) && strings.EqualFold(image, p.Image) {
				err = windows.TerminateProcess(h, 1)
			} else {
				err = fmt.Errorf("süreç kimliği değişti; kapatılmadı")
			}
		}
		windows.CloseHandle(h)
		if err != nil {
			return err
		}
	}
	return nil
}
