package engine

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

type probeTransport func(*http.Request) (*http.Response, error)

func (f probeTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestStartupGrace(t *testing.T) {
	start := time.Now()
	var r ProbeResult
	for _, seconds := range []int{10, 20, 80, 89} {
		r = startupResult(r, errors.New("timeout"), start, start.Add(time.Duration(seconds)*time.Second), ProbeStartupGrace)
		if r.State != ConnConnecting || r.Failures != 0 {
			t.Fatalf("warmup: %+v", r)
		}
	}
	for i := 1; i <= 3; i++ {
		r = startupResult(r, errors.New("timeout"), start, start.Add(time.Duration(89+i)*time.Second), ProbeStartupGrace)
		want := ConnDegraded
		if i == 3 {
			want = ConnDisconnected
		}
		if r.State != want || r.Failures != i {
			t.Fatalf("normal thresholds: %+v", r)
		}
	}
	r = startupResult(ProbeResult{}, nil, start, start.Add(10*time.Second), ProbeStartupGrace)
	r = startupResult(r, errors.New("timeout"), start, start.Add(20*time.Second), ProbeStartupGrace)
	if r.State != ConnDegraded || r.Failures != 1 {
		t.Fatalf("success ends grace: %+v", r)
	}
}

func TestProberNetworkChanges(t *testing.T) {
	old := physicalNetwork
	defer func() { physicalNetwork = old }()
	synctest.Test(t, func(t *testing.T) {
		link := physicalLink{index: 1, up: true}
		physicalNetwork = func() (physicalLink, error) { return link, nil }
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var results []ProbeResult
		var calls []time.Time
		client := &http.Client{Transport: probeTransport(func(*http.Request) (*http.Response, error) {
			calls = append(calls, time.Now())
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ip=192.0.2.1\nwarp=on\n")), Header: make(http.Header)}, nil
		})}
		go runProber(ctx, client, ProbeURL, true, defaultProbeSchedule, func(r ProbeResult) { results = append(results, r) })
		synctest.Wait()
		time.Sleep(9 * time.Second)
		synctest.Wait()
		if len(calls) != 0 || results[0].State != ConnConnecting {
			t.Fatal("first probe too early")
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if len(calls) != 1 || results[len(results)-1].State != ConnVerified {
			t.Fatal("first probe missing")
		}
		link = physicalLink{}
		time.Sleep(10 * time.Second)
		synctest.Wait()
		if results[len(results)-1].State != ConnDisconnected || len(calls) != 1 || canRebuild() {
			t.Fatal("link down must report without probes or rebuilds")
		}
		time.Sleep(30 * time.Second)
		synctest.Wait()
		if len(calls) != 1 {
			t.Fatal("probe while offline")
		}
		link = physicalLink{index: 2, up: true}
		time.Sleep(10 * time.Second)
		synctest.Wait()
		if len(calls) != 2 || results[len(results)-1].State != ConnVerified || !canRebuild() {
			t.Fatal("link return must probe immediately")
		}
		link.index = 3
		time.Sleep(10 * time.Second)
		synctest.Wait()
		if len(calls) != 3 {
			t.Fatal("interface change must probe")
		}
		for i := 1; i < len(calls); i++ {
			if calls[i].Sub(calls[i-1]) < 10*time.Second {
				t.Fatal("probe not debounced")
			}
		}
		if extraProbeDelay(calls[2], calls[2].Add(time.Second)) != 9*time.Second {
			t.Fatal("debounce delay")
		}
	})
}

func TestProberGraceClock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var results []ProbeResult
		calls := 0
		client := &http.Client{Transport: probeTransport(func(*http.Request) (*http.Response, error) {
			calls++
			return nil, errors.New("offline")
		})}
		go runProber(ctx, client, ProbeURL, true, defaultProbeSchedule, func(r ProbeResult) { results = append(results, r) })
		time.Sleep(80 * time.Second)
		synctest.Wait()
		if calls != 8 || results[len(results)-1].State != ConnConnecting {
			t.Fatalf("warmup: calls=%d results=%v", calls, results)
		}
		time.Sleep(10 * time.Second)
		synctest.Wait()
		if calls != 9 || results[len(results)-1].State != ConnDegraded || results[len(results)-1].Failures != 1 {
			t.Fatal("grace boundary")
		}
		time.Sleep(30 * time.Second)
		synctest.Wait()
		if calls != 10 || results[len(results)-1].Failures != 2 {
			t.Fatal("first normal retry")
		}
		time.Sleep(60 * time.Second)
		synctest.Wait()
		if calls != 11 || results[len(results)-1].State != ConnDisconnected {
			t.Fatal("normal disconnect threshold")
		}
	})
}

func TestProberPollsDuringProbe(t *testing.T) {
	old := physicalNetwork
	defer func() { physicalNetwork = old }()
	synctest.Test(t, func(t *testing.T) {
		link := physicalLink{index: 1, up: true}
		physicalNetwork = func() (physicalLink, error) { return link, nil }
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var results []ProbeResult
		calls := 0
		client := &http.Client{Transport: probeTransport(func(*http.Request) (*http.Response, error) {
			calls++
			// A response already in flight may arrive after the link went down.
			time.Sleep(10 * time.Second)
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ip=192.0.2.1\nwarp=on\n")), Header: make(http.Header)}, nil
		})}
		schedule := defaultProbeSchedule
		schedule.first = 15 * time.Second
		go runProber(ctx, client, ProbeURL, true, schedule, func(r ProbeResult) { results = append(results, r) })
		time.Sleep(16 * time.Second)
		synctest.Wait()
		link = physicalLink{}
		time.Sleep(4 * time.Second)
		synctest.Wait()
		if calls != 1 || results[len(results)-1].State != ConnDisconnected {
			t.Errorf("link monitor blocked by probe: calls=%d results=%v", calls, results)
		}
		time.Sleep(6 * time.Second)
		synctest.Wait()
		if results[len(results)-1].State != ConnDisconnected {
			t.Fatalf("stale probe overwrote link-down state: %v", results)
		}
	})
}

func TestProberJoinsCancelledProbe(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		finished := false
		client := &http.Client{Transport: probeTransport(func(r *http.Request) (*http.Response, error) {
			<-r.Context().Done()
			finished = true
			return nil, r.Context().Err()
		})}
		done := make(chan struct{})
		var results []ProbeResult
		go func() {
			defer close(done)
			runProber(ctx, client, ProbeURL, true, defaultProbeSchedule, func(r ProbeResult) { results = append(results, r) })
		}()
		time.Sleep(11 * time.Second)
		synctest.Wait()
		cancel()
		<-done
		if !finished || len(results) != 1 || results[0].State != ConnConnecting {
			t.Fatalf("probe not joined or result reported after cancellation: finished=%v results=%v", finished, results)
		}
	})
}
