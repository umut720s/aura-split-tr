//go:build windows

package wfp

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"golang.org/x/sys/windows"
)

// maxWaitGroup is MAXIMUM_WAIT_OBJECTS (64) minus the stop event.
const maxWaitGroup = 63

type watchedDir struct {
	h windows.Handle
	t WatchTarget
}

// platformWatch uses FindFirstChangeNotification (file and directory
// name changes) on every target. It only reads change notifications;
// nothing is opened for writing and no path is followed: discovery itself
// re-checks every component for reparse points.
//
// A target that cannot be opened is reported through fail at once; the
// others are watched. A handle that cannot be re-armed, or a failed wait
// (all handles of that wait group), is reported through fail too. When
// every wait group has ended, platformWatch returns an error so the caller
// knows nothing is watched any more.
func platformWatch(ctx context.Context, targets []WatchTarget, notify func(), fail func(WatchTarget, error)) error {
	stop, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return fmt.Errorf("create event: %w", err)
	}
	defer windows.CloseHandle(stop)
	var ws []watchedDir
	var errs []error
	for _, t := range targets {
		h, err := windows.FindFirstChangeNotification(t.Path, t.Subtree,
			windows.FILE_NOTIFY_CHANGE_FILE_NAME|windows.FILE_NOTIFY_CHANGE_DIR_NAME)
		if err != nil {
			err = fmt.Errorf("open: %w", err)
			errs = append(errs, fmt.Errorf("watch %s: %w", t.Path, err))
			fail(t, err)
			continue
		}
		ws = append(ws, watchedDir{h: h, t: t})
	}
	// Every handle that was opened (also those later dropped from a wait
	// group) is closed here, after the wait goroutines have finished.
	defer func() {
		for _, w := range ws {
			_ = windows.FindCloseChangeNotification(w.h)
		}
	}()
	if len(ws) == 0 {
		if len(errs) == 0 {
			<-ctx.Done()
			return nil
		}
		return errors.Join(errs...)
	}
	groups := (len(ws) + maxWaitGroup - 1) / maxWaitGroup
	ended := make(chan struct{}, groups)
	var wg sync.WaitGroup
	for i := 0; i < len(ws); i += maxWaitGroup {
		end := i + maxWaitGroup
		if end > len(ws) {
			end = len(ws)
		}
		group := ws[i:end]
		wg.Add(1)
		go func() {
			defer wg.Done()
			waitChanges(stop, group, notify, fail)
			ended <- struct{}{}
		}()
	}
	for left := groups; left > 0; {
		select {
		case <-ctx.Done():
			_ = windows.SetEvent(stop)
			wg.Wait()
			return nil
		case <-ended:
			left--
		}
	}
	wg.Wait()
	return errors.New("every directory watch ended")
}

// waitChanges waits on the group until stop is set. A handle that cannot
// be re-armed (its directory was deleted) is reported and dropped; a
// failed or abandoned wait reports every remaining target and ends the
// group, as does dropping the last handle.
func waitChanges(stop windows.Handle, group []watchedDir, notify func(), fail func(WatchTarget, error)) {
	hs := []windows.Handle{stop}
	ts := []WatchTarget{{}}
	for _, w := range group {
		hs = append(hs, w.h)
		ts = append(ts, w.t)
	}
	failAll := func(err error) {
		for _, t := range ts[1:] {
			fail(t, err)
		}
	}
	for len(hs) > 1 {
		ev, err := windows.WaitForMultipleObjects(hs, false, windows.INFINITE)
		if err != nil {
			failAll(fmt.Errorf("wait: %w", err))
			return
		}
		i := int(ev - windows.WAIT_OBJECT_0)
		if i == 0 {
			return // stop event
		}
		if i < 0 || i >= len(hs) {
			failAll(fmt.Errorf("wait returned %#x", ev))
			return
		}
		notify()
		if err := windows.FindNextChangeNotification(hs[i]); err != nil {
			fail(ts[i], fmt.Errorf("re-arm: %w", err))
			hs = append(hs[:i:i], hs[i+1:]...)
			ts = append(ts[:i:i], ts[i+1:]...)
		}
	}
}
