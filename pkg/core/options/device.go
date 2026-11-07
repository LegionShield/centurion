package options

import (
	"github.com/LegionShield/legion-subdomain/v2/pkg/core/gologger"
	"github.com/LegionShield/legion-subdomain/v2/pkg/device"
)

// GetDeviceConfig
func GetDeviceConfig(dnsServer []string) *device.EtherTable {
	ether, err := device.AutoGetDevicesImproved(dnsServer)
	if err != nil {
		gologger.Fatalf("Auto-detect outbound NIC failed: %v\n", err)
	}

	device.PrintDeviceInfo(ether)
	return ether
}

// GetDeviceConfigs
//
//   -
//   -
func GetDeviceConfigs(ethNames []string, dnsServer []string) []*device.EtherTable {
	if len(ethNames) == 0 {
		ether := GetDeviceConfig(dnsServer)
		return []*device.EtherTable{ether}
	}

	var results []*device.EtherTable
	for _, name := range ethNames {
		et, err := device.GetInterfaceByName(name, dnsServer)
		if err != nil {
			gologger.Warningf("Skipping NIC %s: %v\n", name, err)
			continue
		}
		device.PrintDeviceInfo(et)
		results = append(results, et)
	}

	if len(results) == 0 {
		gologger.Fatalf("No usable NIC, check --eth argument\n")
	}
	return results
}
