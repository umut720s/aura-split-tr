//go:build windows

package engine

import (
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"unsafe"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/control"
	"golang.org/x/sys/windows"
)

// Copy all metadata while the GetAdaptersAddresses backing buffer is alive.
// IP helper calls here only read tables; failures remain explicit in the log.
func readDiagnosticNICs() ([]diagnosticNIC, error) {
	size := uint32(15000)
	var buf []byte
	for {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_PREFIX|windows.GAA_FLAG_INCLUDE_GATEWAYS, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW || size <= uint32(len(buf)) {
			return nil, err
		}
	}
	if size == 0 {
		return nil, nil
	}
	v4, err4 := readRoutes(windows.AF_INET)
	v6, err6 := readRoutes(windows.AF_INET6)
	var out []diagnosticNIC
	for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); a != nil; a = a.Next {
		idx := a.IfIndex
		if idx == 0 {
			idx = a.Ipv6IfIndex
		}
		n := diagnosticNIC{NetworkInterface: adapter.NetworkInterface{Interface: control.Interface{Index: int(idx), Name: windows.UTF16PtrToString(a.FriendlyName)}}, ifType: a.IfType}
		if a.OperStatus == windows.IfOperStatusUp {
			n.Flags = net.FlagUp | net.FlagRunning
		}
		for u := a.FirstUnicastAddress; u != nil; u = u.Next {
			if addr, ok := netip.AddrFromSlice(u.Address.IP()); ok {
				if p, err := addr.Unmap().Prefix(int(u.OnLinkPrefixLength)); err == nil {
					n.Addresses = append(n.Addresses, p)
				}
			}
		}
		for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
			if addr, ok := netip.AddrFromSlice(d.Address.IP()); ok {
				addr = addr.Unmap()
				if addr.Is6() && addr.IsLinkLocalUnicast() {
					addr = addr.WithZone(strconv.FormatUint(uint64(a.Ipv6IfIndex), 10))
				}
				n.DNSServers = append(n.DNSServers, addr.String())
			}
		}
		for g := a.FirstGatewayAddress; g != nil; g = g.Next {
			if addr, ok := netip.AddrFromSlice(g.Address.IP()); ok {
				n.Gateways = append(n.Gateways, addr.Unmap())
			}
		}
		for j, family := range []uint16{windows.AF_INET, windows.AF_INET6} {
			f := &n.v4
			routes, routeErr := v4, err4
			familyIdx := a.IfIndex
			if j == 1 {
				f, routes, routeErr, familyIdx = &n.v6, v6, err6, a.Ipv6IfIndex
			}
			f.defaults(familyIdx, routes, routeErr == nil)
			row := windows.MibIpInterfaceRow{Family: family, InterfaceLuid: a.Luid}
			if windows.GetIpInterfaceEntry(&row) == nil {
				f.known, f.metric = true, row.Metric
				f.forwarding, f.weakSend, f.weakReceive = row.ForwardingEnabled != 0, row.WeakHostSend != 0, row.WeakHostReceive != 0
			}
		}
		out = append(out, n)
	}
	runtime.KeepAlive(buf)
	return out, nil
}
