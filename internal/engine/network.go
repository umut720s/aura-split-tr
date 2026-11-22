package engine

import "time"

const networkCheckInterval = 10 * time.Second

// physicalNetwork is a read-only snapshot of the usable IPv4 default interface.
// No default route is treated as link down; table errors leave status unchanged.
type physicalLink struct {
	index uint32
	up    bool
}

var physicalNetwork = detectPhysicalNetwork

func canRebuild() bool {
	link, err := physicalNetwork()
	return err == nil && link.up
}

// startupResult excludes handshake warm-up failures from the normal thresholds.
func startupResult(prev ProbeResult, err error, started, now time.Time, grace time.Duration) ProbeResult {
	if err != nil && prev.Verified.IsZero() && now.Sub(started) < grace {
		return ProbeResult{State: ConnConnecting, Detail: probeReason(err), Time: now}
	}
	return nextResult(prev, err, now)
}

func extraProbeDelay(last, now time.Time) time.Duration {
	if last.IsZero() || now.Sub(last) >= networkCheckInterval {
		return 0
	}
	return networkCheckInterval - now.Sub(last)
}
