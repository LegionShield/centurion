package main

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/LegionShield/legion-subdomain/v2/pkg/core/gologger"
	"github.com/LegionShield/legion-subdomain/v2/pkg/device"
	"github.com/LegionShield/legion-subdomain/v2/pkg/privileges"
	"github.com/google/gopacket/pcap"
	"github.com/urfave/cli/v2"
)

var doctorCommand = &cli.Command{
	Name:  "doctor",
	Usage: "Diagnose pcap permissions, NICs, routes, and resolvers",
	Flags: []cli.Flag{
		&cli.StringSliceFlag{
			Name:    "resolver",
			Aliases: []string{"r"},
			Value:   cli.NewStringSlice("1.1.1.1", "8.8.8.8"),
			Usage:   "resolvers to probe",
		},
	},
	Action: func(c *cli.Context) error {
		runDoctor(c.StringSlice("resolver"))
		return nil
	},
}

type diagCheck struct {
	name   string
	ok     bool
	detail string
	fix    string
}

func runDoctor(resolvers []string) {
	var checks []diagCheck

	// 1. Privileges
	if privileges.IsPrivileged() {
		checks = append(checks, diagCheck{
			name: "Privileges", ok: true, detail: "root or CAP_NET_RAW",
		})
	} else {
		fix := "sudo " + os.Args[0]
		if runtime.GOOS == "linux" {
			fix = fmt.Sprintf("sudo setcap cap_net_raw,cap_net_admin=eip %s", os.Args[0])
		}
		checks = append(checks, diagCheck{
			name: "Privileges", ok: false,
			detail: "not root / no CAP_NET_RAW",
			fix:    fix,
		})
	}

	// 2. pcap library
	pcapDevices, pcapErr := pcap.FindAllDevs()
	if pcapErr != nil {
		checks = append(checks, diagCheck{
			name: "pcap library", ok: false,
			detail: pcapErr.Error(),
			fix:    "Linux: apt install libpcap-dev  |  Windows: install npcap  |  macOS: xcode-select --install",
		})
	} else {
		checks = append(checks, diagCheck{
			name:   "pcap library",
			ok:     true,
			detail: fmt.Sprintf("%d device(s) visible", len(pcapDevices)),
		})
	}

	// 3. IPv4 NICs
	nicNames, _ := device.GetAllIPv4Devices()
	if len(nicNames) == 0 {
		checks = append(checks, diagCheck{
			name: "IPv4 NICs", ok: false,
			detail: "no usable IPv4 NIC found",
			fix:    "ip link set <name> up  OR  check network adapter status",
		})
	} else {
		checks = append(checks, diagCheck{
			name:   "IPv4 NICs",
			ok:     true,
			detail: fmt.Sprintf("%d NIC(s): %v", len(nicNames), nicNames),
		})
	}

	// 4. Default route NIC + pcap open + MAC resolution
	nic, nicErr := device.GetDefaultRouteInterface()
	if nicErr != nil {
		fix := "run with sudo / add CAP_NET_RAW"
		if runtime.GOOS == "linux" {
			fix = fmt.Sprintf("sudo setcap cap_net_raw,cap_net_admin=eip %s", os.Args[0])
		}
		checks = append(checks, diagCheck{
			name: "Default route NIC", ok: false,
			detail: nicErr.Error(),
			fix:    fix,
		})
	} else {
		checks = append(checks, diagCheck{
			name: "Default route NIC",
			ok:   true,
			detail: fmt.Sprintf("%s  src=%s  gw_mac=%s",
				nic.Device, nic.SrcIp, nic.DstMac.String()),
		})
	}

	// 5. Resolver connectivity
	for _, r := range resolvers {
		start := time.Now()
		_, err := device.LookUpIP("one.one.one.one", r)
		elapsed := time.Since(start)
		if err != nil {
			checks = append(checks, diagCheck{
				name:   fmt.Sprintf("Resolver %s", r),
				ok:     false,
				detail: err.Error(),
				fix:    fmt.Sprintf("dig @%s one.one.one.one  — check connectivity or firewall", r),
			})
		} else {
			checks = append(checks, diagCheck{
				name:   fmt.Sprintf("Resolver %s", r),
				ok:     true,
				detail: fmt.Sprintf("RTT ~%dms", elapsed.Milliseconds()),
			})
		}
	}

	// Print results
	fmt.Println()
	allOK := true
	for _, ch := range checks {
		sym := "✓"
		if !ch.ok {
			sym = "✗"
			allOK = false
		}
		fmt.Printf("  %s  %-32s  %s\n", sym, ch.name, ch.detail)
		if !ch.ok && ch.fix != "" {
			fmt.Printf("     %-32s  → %s\n", "", ch.fix)
		}
	}
	fmt.Println()

	if allOK {
		gologger.Infof("All checks passed — ready to scan\n")
	} else {
		gologger.Warningf("Some checks failed — fix the issues above before scanning\n")
		if runtime.GOOS != "windows" {
			os.Exit(1)
		}
	}
}
