package engine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"
)

// resolvePeerHost resolves a WireGuard peer host name with the system
// resolver (a variable so tests never touch the network). With ipv4Only
// it returns the first IPv4 address; otherwise IPv4 is still preferred.
var resolvePeerHost = func(host string, ipv4Only bool) (netip.Addr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, err
	}
	var v6 netip.Addr
	for _, a := range addrs {
		a = a.Unmap()
		if a.Is4() {
			return a, nil
		}
		if !v6.IsValid() {
			v6 = a
		}
	}
	if !ipv4Only && v6.IsValid() {
		return v6, nil
	}
	return netip.Addr{}, errors.New("no usable address for peer host")
}

// hostIPv6 reports whether the host has usable IPv6 egress (see
// decideHostIPv6). It is evaluated when a tunnel configuration is built and
// every hostCheckInterval while a tunnel runs; a change rebuilds the
// tunnel. A variable so tests can pin it. On Windows it reads the IP
// helper tables (hostipv6_windows.go); elsewhere it is a stub that always
// reports false.
var hostIPv6 = detectHostIPv6

// hostHasIPv6 is hostIPv6 for building a configuration. If the tables
// cannot be read the answer is false: the TUN then gets no IPv6 address and
// AAAA answers are suppressed, which keeps IPv4 (the path the host is known
// to need for the WireGuard peer) working instead of risking the browser
// outage of live-test Bug 2.
func hostHasIPv6() bool {
	v6, err := hostIPv6()
	return err == nil && v6
}

// ifaceRow is the part of an interface (MIB_IF_ROW2 and its IPv4
// MIB_IPINTERFACE_ROW) the decision needs.
type ifaceRow struct {
	up       bool
	loopback bool
	alias    string
	ifType   uint32 // MIB_IF_ROW2.Type (IANA ifType)
	// IPv4 interface entry (GetIpInterfaceEntry, AF_INET). v4OK is false
	// when the interface has no IPv4 entry or it could not be read.
	v4OK        bool
	v4Connected bool
	v4Metric    uint32
}

// IANA interface types the sing-tun default-interface monitor skips.
const (
	ifTypePropVirtual      = 53 // IF_TYPE_PROP_VIRTUAL (wintun, many VPN adapters)
	ifTypeSoftwareLoopback = 24 // IF_TYPE_SOFTWARE_LOOPBACK
)

// addrRow is one unicast address (MIB_UNICASTIPADDRESS_ROW).
type addrRow struct {
	ifIndex   uint32
	addr      netip.Addr
	preferred bool // DAD state "preferred" (not tentative, duplicate or deprecated)
}

// routeRow is one route (MIB_IPFORWARD_ROW2), in route table order.
type routeRow struct {
	ifIndex uint32
	prefix  netip.Prefix
	metric  uint32 // route metric (MIB_IPFORWARD_ROW2.Metric)
}

var (
	// Teredo and 6to4 are transition mechanisms, not native IPv6 egress.
	teredoPrefix = netip.MustParsePrefix("2001::/32")
	sixToFour    = netip.MustParsePrefix("2002::/16")
	defaultV4    = netip.MustParsePrefix("0.0.0.0/0")
	defaultV6    = netip.MustParsePrefix("::/0")
)

// usableGlobalV6 reports whether a is a global unicast IPv6 address that
// can carry Internet traffic: not unique-local (fc00::/7), link-local,
// IPv4-mapped, Teredo or 6to4.
func usableGlobalV6(a netip.Addr) bool {
	if !a.Is6() || a.Is4In6() || !a.IsGlobalUnicast() || a.IsPrivate() {
		return false
	}
	return !teredoPrefix.Contains(a) && !sixToFour.Contains(a)
}

// defaultV4Interface picks the interface sing-box binds ordinary outbound
// sockets to. It mirrors the pinned sing-tun Windows default-interface
// monitor (monitor_windows.go, checkUpdate): among IPv4 routes with prefix
// length 0, in route table order, skip interfaces that are not up, are
// IF_TYPE_PROP_VIRTUAL or IF_TYPE_SOFTWARE_LOOPBACK, have no IPv4 interface
// entry or are not connected; the lowest route metric + IPv4 interface
// metric wins, the first one on a tie. ok is false when there is none
// (sing-tun: ErrNoRoute).
func defaultV4Interface(ifaces map[uint32]ifaceRow, v4routes []routeRow) (idx uint32, ok bool) {
	lowest := ^uint32(0)
	for _, r := range v4routes {
		if r.prefix != defaultV4 {
			continue
		}
		ifc, known := ifaces[r.ifIndex]
		if !known || !ifc.up {
			continue
		}
		if ifc.ifType == ifTypePropVirtual || ifc.ifType == ifTypeSoftwareLoopback {
			continue
		}
		if !ifc.v4OK || !ifc.v4Connected {
			continue
		}
		// uint32 addition wraps exactly like sing-tun's.
		if m := r.metric + ifc.v4Metric; m < lowest {
			lowest, idx, ok = m, r.ifIndex, true
		}
	}
	return idx, ok
}

// decideHostIPv6 is the pure decision (unit-tested with fake tables). The
// TUN gets IPv6 only if the interface sing-box actually uses for direct
// traffic can carry it: that is the IPv4 default-route interface chosen
// exactly as sing-tun chooses it (defaultV4Interface), because sing-box
// binds ordinary outbound sockets to that one interface for both address
// families. IPv6 is reported only if THAT interface is up, is not loopback
// and is not the AURA Split TR TUN, and has BOTH a preferred, usable global
// IPv6 address and an IPv6 default route (::/0) through it. IPv6 on any
// other adapter (a second NIC, a virtual switch, a VPN adapter), an address
// without a default route, or no IPv4 default interface at all, is not
// enough.
func decideHostIPv6(ifaces map[uint32]ifaceRow, v4routes []routeRow, addrs []addrRow, v6routes []routeRow) bool {
	idx, ok := defaultV4Interface(ifaces, v4routes)
	if !ok {
		return false
	}
	ifc := ifaces[idx]
	if !ifc.up || ifc.loopback || strings.EqualFold(ifc.alias, TunInterfaceName) {
		return false
	}
	hasAddr := false
	for _, a := range addrs {
		if a.ifIndex == idx && a.preferred && usableGlobalV6(a.addr) {
			hasAddr = true
			break
		}
	}
	if !hasAddr {
		return false
	}
	for _, r := range v6routes {
		if r.ifIndex == idx && r.prefix == defaultV6 {
			return true
		}
	}
	return false
}

// decideHostIPv6On reuses the same IPv6 decision for an explicitly pinned NIC.
func decideHostIPv6On(index int, ifaces map[uint32]ifaceRow, v4routes []routeRow, addrs []addrRow, v6routes []routeRow) bool {
	if index != 0 {
		var filtered []routeRow
		for _, r := range v4routes {
			if r.ifIndex == uint32(index) {
				filtered = append(filtered, r)
			}
		}
		v4routes = filtered
	}
	return decideHostIPv6(ifaces, v4routes, addrs, v6routes)
}
