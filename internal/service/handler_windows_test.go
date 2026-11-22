//go:build windows

package service

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

// fakeSCM drives handler.Execute the way svc.Run does, without a service
// control manager: it feeds change requests and records every status.
type fakeSCM struct {
	req    chan svc.ChangeRequest
	status chan svc.Status
	mu     sync.Mutex
	seen   []svc.Status
	done   chan struct{}
}

func newFakeSCM() *fakeSCM {
	f := &fakeSCM{req: make(chan svc.ChangeRequest), status: make(chan svc.Status), done: make(chan struct{})}
	go func() {
		for {
			select {
			case s := <-f.status:
				f.mu.Lock()
				f.seen = append(f.seen, s)
				f.mu.Unlock()
			case <-f.done:
				return
			}
		}
	}()
	return f
}

func (f *fakeSCM) statuses() []svc.Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]svc.Status(nil), f.seen...)
}

func (f *fakeSCM) waitState(t *testing.T, st svc.State) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, s := range f.statuses() {
			if s.State == st {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("state %d never reported; got %+v", st, f.statuses())
}

type execResult struct {
	specific bool
	code     uint32
}

func runExecute(h *handler, f *fakeSCM) <-chan execResult {
	out := make(chan execResult, 1)
	go func() {
		s, c := h.Execute(nil, f.req, f.status)
		out <- execResult{s, c}
	}()
	return out
}

// Stop and Shutdown cancel the run context, wait for run to return and
// report StopPending with a wait hint before Execute returns success.
func TestExecuteStopCancelsRun(t *testing.T) {
	for _, cmd := range []svc.Cmd{svc.Stop, svc.Shutdown} {
		f := newFakeSCM()
		var calls atomic.Int32
		returned := make(chan struct{})
		h := &handler{run: func(ctx context.Context) error {
			calls.Add(1)
			<-ctx.Done()
			close(returned)
			return ctx.Err()
		}}
		res := runExecute(h, f)
		f.waitState(t, svc.Running)
		f.req <- svc.ChangeRequest{Cmd: cmd}
		select {
		case r := <-res:
			if r.specific || r.code != 0 {
				t.Fatalf("cmd %d: Execute = %v, %d", cmd, r.specific, r.code)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("cmd %d: Execute did not return", cmd)
		}
		select {
		case <-returned:
		default:
			t.Fatalf("cmd %d: Execute returned before run finished", cmd)
		}
		// The send completed, but the recorder may not have appended it yet.
		f.waitState(t, svc.StopPending)
		close(f.done)
		st := f.statuses()
		if len(st) != 3 || st[0].State != svc.StartPending || st[1].State != svc.Running || st[2].State != svc.StopPending {
			t.Fatalf("cmd %d: statuses %+v", cmd, st)
		}
		if st[1].Accepts != svc.AcceptStop|svc.AcceptShutdown {
			t.Fatalf("accepts %v", st[1].Accepts)
		}
		if st[2].WaitHint < uint32((stopTimeout-2*time.Second)/time.Millisecond) {
			t.Fatalf("wait hint %d shorter than the stop wait", st[2].WaitHint)
		}
		if calls.Load() != 1 {
			t.Fatalf("run called %d times", calls.Load())
		}
	}
}

func TestExecuteInterrogateEchoesStatus(t *testing.T) {
	f := newFakeSCM()
	defer close(f.done)
	h := &handler{run: func(ctx context.Context) error { <-ctx.Done(); return nil }}
	res := runExecute(h, f)
	f.waitState(t, svc.Running)
	cur := svc.Status{State: svc.Running, Accepts: svc.AcceptStop, CheckPoint: 42}
	f.req <- svc.ChangeRequest{Cmd: svc.Interrogate, CurrentStatus: cur}
	deadline := time.Now().Add(5 * time.Second)
	for {
		st := f.statuses()
		if len(st) >= 3 && st[2].CheckPoint == 42 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("interrogate not answered: %+v", st)
		}
		time.Sleep(5 * time.Millisecond)
	}
	f.req <- svc.ChangeRequest{Cmd: svc.Stop}
	<-res
}

// A panic inside run is turned into an error; it must never crash the
// service process (the supervisor retries instead).
func TestSafeRunRecoversPanic(t *testing.T) {
	err := safeRun(context.Background(), func(context.Context) error { panic("boom") })
	if err == nil || err.Error() != "panic: boom" {
		t.Fatalf("safeRun = %v", err)
	}
	want := errors.New("x")
	if err := safeRun(context.Background(), func(context.Context) error { return want }); err != want {
		t.Fatalf("safeRun = %v", err)
	}
}

// Cancellation ends the supervisor promptly and run is not restarted.
// (Run failures before cancellation write to the Application event log;
// they are not exercised here, see audit seam S-3.)
func TestSuperviseLoopStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	done := make(chan error, 1)
	go func() {
		done <- superviseLoop(ctx, func(ctx context.Context) error {
			calls.Add(1)
			<-ctx.Done()
			return errors.New("stopped")
		}, time.Hour)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("superviseLoop = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("superviseLoop did not return")
	}
	if calls.Load() != 1 {
		t.Fatalf("run called %d times", calls.Load())
	}
}
