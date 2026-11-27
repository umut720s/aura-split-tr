//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"aurasplit/internal/engine"
	"aurasplit/internal/oldflow"
	"aurasplit/internal/wfp"
)

// Seams for the WFP fail-closed policy; tests replace them with fakes so
// no real WFP call is ever made by a unit test.
var (
	checkOldFlows   func([]string) (bool, string)
	newPolicy       = func() wfp.Policy { return wfp.New() }
	discoverDiscord = wfp.Discover
	tunnelLUID      = wfp.TunnelLUID
	rescanInterval  = wfp.DefaultRescanInterval
	// runWatcher watches the Discord directories (tests: no-op).
	runWatcher = func(ctx context.Context, notify func(), logf func(level, msg string)) {
		wfp.RunWatcher(ctx, wfp.WatchTargets, rescanInterval, notify, logf)
	}
)

// protection is the running WFP guard of one service (or `run`) session.
type protection struct {
	guard *wfp.Guard
	stop  func()
}

// startProtection applies the persistent policy for the Discord
// executables found now (before the tunnel starts) and keeps reconciling
// it: within about a second of a change in a Discord directory (watcher),
// every rescanInterval as a backstop, and every few seconds while
// protection is incomplete. A failed first apply is logged and retried;
// tunnel activation requires a subsequent complete apply and readback.
func startProtection(ctx context.Context, logf func(level, msg string), onChange func(wfp.Status)) *protection {
	pol := newPolicy()
	if fw, ok := pol.(*wfp.Firewall); ok {
		fw.Logf = logf
	}
	g := wfp.NewGuard(pol, discoverDiscord, logf, onChange)
	gate := &oldflow.Gate{}
	g.CheckOldFlows = func(paths []string) (bool, string) { return gate.Check(oldflow.WindowsSource{Manifest: paths}, paths) }
	if checkOldFlows != nil {
		g.CheckOldFlows = checkOldFlows
	}
	if err := g.Reconcile(); err != nil {
		if errors.Is(err, wfp.ErrIncomplete) {
			logf("WARN", "fail-closed WFP policy applied incompletely (add-only, retrying): "+err.Error())
		} else {
			logf("ERROR", "fail-closed WFP policy could not be applied (retrying): "+err.Error())
		}
	}
	loopCtx, cancel := context.WithCancel(ctx)
	kick := make(chan struct{}, 1)
	notify := func() {
		select {
		case kick <- struct{}{}:
		default:
		}
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		g.Run(loopCtx, rescanInterval, kick)
	}()
	go func() {
		defer wg.Done()
		runWatcher(loopCtx, notify, logf)
	}()
	var once sync.Once
	return &protection{guard: g, stop: func() {
		once.Do(func() {
			cancel()
			wg.Wait()
		})
	}}
}

// onTunnelUp is engine.RunOptions.OnTunnelUp: it finds the TUN adapter
// and opens the dynamic Discord permit on it.
func (p *protection) onTunnelUp() (io.Closer, error) {
	luid, err := tunnelLUID(engine.TunInterfaceName)
	if err != nil {
		p.guard.ReportFailure("AURA TUN LUID bulunamadı; koruma hazır değil")
		return nil, fmt.Errorf("find TUN interface %q: %w", engine.TunInterfaceName, err)
	}
	return p.guard.TunnelUp(luid)
}

// policyInstalled asks WFP whether the persistent policy exists.
func policyInstalled() (bool, int, error) { return newPolicy().Installed() }

// applyPolicyOnce discovers Discord and applies the persistent policy
// (used by setup before the service starts). Only a complete discovery is
// applied authoritatively; otherwise nothing is removed. The returned
// error wraps wfp.ErrIncomplete when the result does not cover every
// executable (the count is then still valid).
func applyPolicyOnce() (int, error) {
	paths, derr := discoverDiscord()
	mode := wfp.Authoritative
	if derr != nil {
		mode = wfp.AddOnly
	}
	pol := newPolicy()
	res, err := pol.Apply(paths, mode)
	if err != nil && !errors.Is(err, wfp.ErrIncomplete) {
		return 0, err
	}
	if derr != nil {
		err = errors.Join(fmt.Errorf("%w: discovery: %v", wfp.ErrIncomplete, derr), err)
	}
	if len(paths) == 0 {
		err = errors.Join(err, fmt.Errorf("%w: manifest boş", wfp.ErrIncomplete))
	}
	if rerr := wfp.VerifyPolicy(pol, paths); rerr != nil {
		err = errors.Join(err, fmt.Errorf("%w: readback: %v", wfp.ErrIncomplete, rerr))
	}
	return len(res.Covered), err
}

// removePolicy deletes every WFP object of our provider.
func removePolicy() error { return newPolicy().RemoveAll() }
