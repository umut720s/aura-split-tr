package engine

import "golang.org/x/sys/windows"

func detectPhysicalNetwork() (physicalLink, error) {
	routes, err := readRoutes(windows.AF_INET)
	if err != nil {
		return physicalLink{}, err
	}
	ifaces := map[uint32]ifaceRow{}
	for _, r := range routes {
		if r.prefix != defaultV4 {
			continue
		}
		if _, ok := ifaces[r.ifIndex]; ok {
			continue
		}
		row := windows.MibIfRow2{InterfaceIndex: r.ifIndex}
		if err := windows.GetIfEntry2Ex(windows.MibIfEntryNormalWithoutStatistics, &row); err != nil {
			return physicalLink{}, err
		}
		if row.Type == ifTypePropVirtual || row.Type == ifTypeSoftwareLoopback || windows.UTF16ToString(row.Alias[:]) == TunInterfaceName {
			continue
		}
		ip := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: row.InterfaceLuid}
		if err := windows.GetIpInterfaceEntry(&ip); err != nil {
			return physicalLink{}, err
		}
		ifaces[r.ifIndex] = ifaceRow{up: row.OperStatus == windows.IfOperStatusUp,
			ifType: row.Type, v4OK: true, v4Connected: ip.Connected != 0, v4Metric: ip.Metric}
	}
	idx, up := defaultV4Interface(ifaces, routes)
	return physicalLink{index: idx, up: up}, nil
}
