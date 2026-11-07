package main

import (
	"fmt"
	"github.com/LegionShield/legion-subdomain/v2/pkg/device"

	"github.com/LegionShield/legion-subdomain/v2/pkg/core/gologger"
	"github.com/urfave/cli/v2"
)

var deviceCommand = &cli.Command{
	Name:  "device",
	Usage: "List all available NICs on the system",
	Flags: []cli.Flag{},
	Action: func(c *cli.Context) error {
		deviceNames, deviceMap := device.GetAllIPv4Devices()

		if len(deviceNames) == 0 {
			gologger.Warningf("No usable IPv4 NIC found\n")
			return nil
		}

		gologger.Infof("Found %d available NIC(s):\n", len(deviceNames))

		for i, name := range deviceNames {
			ip := deviceMap[name]
			gologger.Infof("[%d] NIC: %s\n", i+1, name)
			gologger.Infof("    IP: %s\n", ip.String())
			fmt.Println("")
		}
		ether, err := device.AutoGetDevices([]string{"1.1.1.1", "8.8.8.8"})
		if err != nil {
			gologger.Errorf("Failed to get NIC info: %s\n", err.Error())
			return nil
		}
		device.PrintDeviceInfo(ether)
		return nil
	},
}
