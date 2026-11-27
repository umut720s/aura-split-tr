//go:build windows

package engine

import (
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

// detectHostIPv6 reads the IPv4 route table (to find the default interface
// the way sing-tun does), the IPv6 unicast address table, the IPv6 route
// table and the state of every interface that appears in them, then applies
// decideHostIPv6. Only read-only IP helper calls are used.
func detectHostIPv6() (bool, error) {
	return detectHostIPv6On(0)
}

func detectHostIPv6On(index int) (bool, error) {
	v4routes, err := readRoutes(windows.AF_INET)
	if err != nil {
		return false, err
	}
	addrs, err := readV6Addresses()
	if err != nil {
		return false, err
	}
	v6routes, err := readRoutes(windows.AF_INET6)
	if err != nil {
		return false, err
	}
	ifaces := map[uint32]ifaceRow{}
	add := func(idx uint32) {
		if _, done := ifaces[idx]; done {
			return
		}
		row := windows.MibIfRow2{InterfaceIndex: idx}
		if windows.GetIfEntry2Ex(windows.MibIfEntryNormalWithoutStatistics, &row) != nil {
			// Vanished meanwhile: treated as not up.
			ifaces[idx] = ifaceRow{}
			return
		}
		ifc := ifaceRow{
			up:       row.OperStatus == windows.IfOperStatusUp,
			loopback: row.Type == windows.IF_TYPE_SOFTWARE_LOOPBACK,
			alias:    windows.UTF16ToString(row.Alias[:]),
			ifType:   row.Type,
		}
		// The IPv4 interface entry, as sing-tun reads it
		// (InterfaceLUID.IPInterface(AF_INET)): Connected and Metric. The
		// input fields are Family and InterfaceLuid.
		ipif := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: row.InterfaceLuid}
		if windows.GetIpInterfaceEntry(&ipif) == nil {
			ifc.v4OK = true
			ifc.v4Connected = ipif.Connected != 0
			ifc.v4Metric = ipif.Metric
		}
		ifaces[idx] = ifc
	}
	for _, r := range v4routes {
		add(r.ifIndex)
	}
	for _, a := range addrs {
		add(a.ifIndex)
	}
	for _, r := range v6routes {
		add(r.ifIndex)
	}
	return decideHostIPv6On(index, ifaces, v4routes, addrs, v6routes), nil
}

func readV6Addresses() ([]addrRow, error) {
	var tab *windows.MibUnicastIpAddressTable
	if err := windows.GetUnicastIpAddressTable(windows.AF_INET6, &tab); err != nil {
		return nil, fmt.Errorf("read IPv6 address table: %w", err)
	}
	defer windows.FreeMibTable(unsafe.Pointer(tab))
	rows := unsafe.Slice(&tab.Table[0], tab.NumEntries)
	out := make([]addrRow, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		if r.Address.Family != windows.AF_INET6 {
			continue
		}
		out = append(out, addrRow{
			ifIndex:   r.InterfaceIndex,
			addr:      netip.AddrFrom16(r.Address.Addr),
			preferred: r.DadState == windows.IpDadStatePreferred,
		})
	}
	return out, nil
}

// readRoutes reads the route table of one address family (AF_INET or
// AF_INET6) in table order, copying every row before the table is freed.
func readRoutes(family uint16) ([]routeRow, error) {
	var tab *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(family, &tab); err != nil {
		return nil, fmt.Errorf("read route table (family %d): %w", family, err)
	}
	defer windows.FreeMibTable(unsafe.Pointer(tab))
	rows := tab.Rows()
	out := make([]routeRow, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		if r.DestinationPrefix.Prefix.Family != family {
			continue
		}
		var (
			pfx netip.Prefix
			err error
		)
		bits := int(r.DestinationPrefix.PrefixLength)
		switch family {
		case windows.AF_INET:
			sa := (*windows.RawSockaddrInet4)(unsafe.Pointer(&r.DestinationPrefix.Prefix))
			pfx, err = netip.AddrFrom4(sa.Addr).Prefix(bits)
		default:
			sa := (*windows.RawSockaddrInet6)(unsafe.Pointer(&r.DestinationPrefix.Prefix))
			pfx, err = netip.AddrFrom16(sa.Addr).Prefix(bits)
		}
		if err != nil {
			continue
		}
		out = append(out, routeRow{ifIndex: r.InterfaceIndex, prefix: pfx, metric: r.Metric})
	}
	return out, nil
}
