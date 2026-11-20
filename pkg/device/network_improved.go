package device

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/LegionShield/legion-subdomain/v2/pkg/core/gologger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func isZeroMAC(mac net.HardwareAddr) bool {
	if len(mac) == 0 {
		return true
	}
	for _, b := range mac {
		if b != 0 {
			return false
		}
	}
	return true
}

func GetDefaultRouteInterface() (*EtherTable, error) {
	var defaultInterface string
	var gatewayIP net.IP

	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("route", "print", "0.0.0.0")
		output, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("failed to run route command: %v", err)
		}

		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "0.0.0.0") && strings.Contains(line, "0.0.0.0") {
				fields := strings.Fields(line)
				if len(fields) >= 5 {
					gatewayIP = net.ParseIP(fields[2])
					localIP := net.ParseIP(fields[3])
					if localIP != nil {
						interfaces, _ := pcap.FindAllDevs()
						for _, iface := range interfaces {
							for _, addr := range iface.Addresses {
								if addr.IP.Equal(localIP) {
									defaultInterface = iface.Name
									break
								}
							}
							if defaultInterface != "" {
								break
							}
						}
					}
					break
				}
			}
		}

	case "linux":
		cmd := exec.Command("ip", "route", "show", "default")
		output, err := cmd.Output()
		if err != nil {
			cmd = exec.Command("route", "-n")
			output, err = cmd.Output()
			if err != nil {
				return nil, fmt.Errorf("failed to get route info: %v", err)
			}
		}

		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "default") || strings.HasPrefix(line, "0.0.0.0") {
				fields := strings.Fields(line)
				if len(fields) >= 5 {
					if fields[0] == "default" && len(fields) >= 5 {
						gatewayIP = net.ParseIP(fields[2])
						defaultInterface = fields[4]
					} else if fields[0] == "0.0.0.0" {
						gatewayIP = net.ParseIP(fields[1])
						defaultInterface = fields[len(fields)-1]
					}
					break
				}
			}
		}

	case "darwin":
		cmd := exec.Command("route", "get", "default")
		output, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("failed to get route info: %v", err)
		}

		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "gateway:") {
				parts := strings.Split(line, ":")
				if len(parts) >= 2 {
					gatewayIP = net.ParseIP(strings.TrimSpace(parts[1]))
				}
			} else if strings.HasPrefix(line, "interface:") {
				parts := strings.Split(line, ":")
				if len(parts) >= 2 {
					defaultInterface = strings.TrimSpace(parts[1])
				}
			}
		}
	}

	if defaultInterface == "" || gatewayIP == nil {
		return nil, fmt.Errorf("could not get default route info")
	}

	gologger.Infof("Found default route NIC: %s, gateway: %s\n", defaultInterface, gatewayIP.String())

	etherTable, err := getInterfaceDetails(defaultInterface, gatewayIP)
	if err != nil {
		return nil, err
	}

	return etherTable, nil
}

func getInterfaceDetails(deviceName string, gatewayIP net.IP) (*EtherTable, error) {
	interfaces, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("failed to get NIC list: %v", err)
	}

	var srcIP net.IP
	var srcMAC net.HardwareAddr

	var nicAddrs []net.IP
	for _, iface := range interfaces {
		if iface.Name == deviceName {
			for _, addr := range iface.Addresses {
				if addr.IP.To4() != nil && !addr.IP.IsLoopback() {
					nicAddrs = append(nicAddrs, addr.IP)
				}
			}
			break
		}
	}

	if conn, dialErr := net.Dial("udp", gatewayIP.String()+":53"); dialErr == nil {
		defer conn.Close()
		if localIP := conn.LocalAddr().(*net.UDPAddr).IP.To4(); localIP != nil {
			for _, ip := range nicAddrs {
				if ip.Equal(localIP) {
					srcIP = localIP
					break
				}
			}
		}
	}

	if srcIP == nil && len(nicAddrs) > 0 {
		srcIP = nicAddrs[0]
	}

	if srcIP == nil {
		return nil, fmt.Errorf("could not get IP address for NIC %s", deviceName)
	}

	iface, err := net.InterfaceByName(deviceName)
	if err == nil && iface.HardwareAddr != nil {
		srcMAC = iface.HardwareAddr
	} else {
		// Windows NPF names (e.g. \Device\NPF_{GUID}) are rejected by net.InterfaceByName
		if candidates, err2 := net.Interfaces(); err2 == nil {
			for _, candidate := range candidates {
				addrs, _ := candidate.Addrs()
				for _, addr := range addrs {
					var ip net.IP
					switch v := addr.(type) {
					case *net.IPNet:
						ip = v.IP
					case *net.IPAddr:
						ip = v.IP
					}
					if ip != nil && ip.Equal(srcIP) {
						srcMAC = candidate.HardwareAddr
						break
					}
				}
				if srcMAC != nil {
					break
				}
			}
		}
		if srcMAC == nil {
			srcMAC, _ = getMACAddress(deviceName)
		}
	}

	if srcMAC == nil {
		return nil, fmt.Errorf("could not get MAC address for NIC %s", deviceName)
	}
	if isZeroMAC(srcMAC) {
		return nil, fmt.Errorf("NIC %s has zero MAC address (virtual or unconfigured interface)", deviceName)
	}

	gatewayMAC, err := resolveGatewayMAC(deviceName, srcIP, srcMAC, gatewayIP)
	if err != nil {
		return nil, fmt.Errorf("gateway MAC resolution failed for %s: %v — run as root or grant CAP_NET_RAW", deviceName, err)
	}
	if isZeroMAC(gatewayMAC) {
		return nil, fmt.Errorf("gateway returned zero MAC for NIC %s — cannot build valid Ethernet frames", deviceName)
	}

	etherTable := &EtherTable{
		SrcIp:  srcIP,
		Device: deviceName,
		SrcMac: SelfMac(srcMAC),
		DstMac: SelfMac(gatewayMAC),
	}

	gologger.Infof("NIC config: IP=%s, MAC=%s, Gateway MAC=%s\n",
		srcIP.String(), srcMAC.String(), gatewayMAC.String())

	return etherTable, nil
}

func resolveGatewayMAC(deviceName string, srcIP net.IP, srcMAC net.HardwareAddr, gatewayIP net.IP) (net.HardwareAddr, error) {
	handle, err := pcap.OpenLive(deviceName, 2048, true, time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to open NIC: %v", err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter(fmt.Sprintf("arp and arp[6:2] = 2 and src host %s", gatewayIP.String()))
	if err != nil {
		gologger.Debugf("Failed to set BPF filter: %v\n", err)
	}

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress:    gatewayIP.To4(),
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err = gopacket.SerializeLayers(buffer, opts, eth, arp)
	if err != nil {
		return nil, fmt.Errorf("failed to build ARP packet: %v", err)
	}

	outgoingPacket := buffer.Bytes()
	err = handle.WritePacketData(outgoingPacket)
	if err != nil {
		return nil, fmt.Errorf("failed to send ARP request: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("ARP response timeout")
		case packet := <-packetSource.Packets():
			if packet == nil {
				continue
			}

			if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
				arpReply, ok := arpLayer.(*layers.ARP)
				if ok && arpReply.Operation == layers.ARPReply {
					if net.IP(arpReply.SourceProtAddress).Equal(gatewayIP) {
						return net.HardwareAddr(arpReply.SourceHwAddress), nil
					}
				}
			}
		}
	}
}

func getMACAddress(deviceName string) (net.HardwareAddr, error) {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("getmac", "/v")
		output, err := cmd.Output()
		if err != nil {
			return nil, err
		}
		_ = output

	case "linux", "darwin":
		cmd := exec.Command("ifconfig", deviceName)
		output, err := cmd.Output()
		if err != nil {
			return nil, err
		}

		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "ether") || strings.Contains(line, "HWaddr") {
				fields := strings.Fields(line)
				for i, field := range fields {
					if field == "ether" || field == "HWaddr" {
						if i+1 < len(fields) {
							mac, err := net.ParseMAC(fields[i+1])
							if err == nil {
								return mac, nil
							}
						}
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("could not get MAC address")
}

func GetInterfaceByName(name string, userDNS []string) (*EtherTable, error) {
	gologger.Infof("Getting config for NIC %s...\n", name)

	gatewayIP, err := GetDefaultGatewayIP()
	if err != nil {
		gologger.Warningf("Default gateway failed, falling back to DNS probe: %v\n", err)
		et, err2 := AutoGetDevices(userDNS)
		if err2 != nil {
			return nil, fmt.Errorf("NIC %s config probe failed: %v", name, err2)
		}
		et.Device = name
		return et, nil
	}

	etherTable, err := getInterfaceDetails(name, gatewayIP)
	if err != nil {
		gologger.Warningf("NIC %s ARP probe failed: %v, reusing gateway MAC from default route\n", name, err)

		defaultEther, err2 := GetDefaultRouteInterface()
		if err2 != nil {
			return nil, fmt.Errorf("could not get full config for NIC %s: %v", name, err)
		}

		iface, err2 := net.InterfaceByName(name)
		if err2 != nil {
			return nil, fmt.Errorf("NIC %s not found: %v", name, err2)
		}
		addrs, _ := iface.Addrs()
		var srcIP net.IP
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.To4() != nil && !ip.IsLoopback() {
				srcIP = ip.To4()
				break
			}
		}
		if srcIP == nil {
			srcIP = defaultEther.SrcIp
		}

		if isZeroMAC(iface.HardwareAddr) {
			return nil, fmt.Errorf("NIC %s has zero MAC address (virtual or unconfigured interface)", name)
		}
		return &EtherTable{
			SrcIp:  srcIP,
			Device: name,
			SrcMac: SelfMac(iface.HardwareAddr),
			DstMac: defaultEther.DstMac,
		}, nil
	}

	return etherTable, nil
}

func GetDefaultGatewayIP() (net.IP, error) {
	switch runtime.GOOS {
	case "linux":
		// primary: ip route show default
		cmd := exec.Command("ip", "route", "show", "default")
		output, err := cmd.Output()
		if err == nil {
			for _, line := range strings.Split(string(output), "\n") {
				fields := strings.Fields(line)
				// "default via <gateway> dev <iface> ..."
				if len(fields) >= 3 && fields[0] == "default" && fields[1] == "via" {
					ip := net.ParseIP(fields[2])
					if ip != nil && ip.To4() != nil && !ip.IsUnspecified() {
						return ip, nil
					}
				}
			}
		}
		// fallback: route -n (older distros, BusyBox, some containers)
		cmd = exec.Command("route", "-n")
		output, err = cmd.Output()
		if err == nil {
			for _, line := range strings.Split(string(output), "\n") {
				fields := strings.Fields(line)
				// "0.0.0.0  <gateway>  0.0.0.0  UG  ..."
				if len(fields) >= 3 && fields[0] == "0.0.0.0" {
					ip := net.ParseIP(fields[1])
					if ip != nil && ip.To4() != nil && !ip.IsUnspecified() {
						return ip, nil
					}
				}
			}
		}
		gologger.Warningf("Could not determine default gateway from routing table — VPN, tunnel or multi-route setup may require --eth <name>\n")
		return nil, fmt.Errorf("could not parse default gateway (tried ip route and route -n)")

	case "darwin":
		cmd := exec.Command("route", "get", "default")
		output, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("route get default failed: %v", err)
		}
		for _, line := range strings.Split(string(output), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "gateway:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					ip := net.ParseIP(strings.TrimSpace(parts[1]))
					if ip != nil && ip.To4() != nil && !ip.IsUnspecified() {
						return ip, nil
					}
				}
			}
		}
		return nil, fmt.Errorf("could not parse default gateway")

	case "windows":
		cmd := exec.Command("route", "print", "0.0.0.0")
		output, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("route print failed: %v", err)
		}
		for _, line := range strings.Split(string(output), "\n") {
			fields := strings.Fields(line)
			// expect: "0.0.0.0  0.0.0.0  <gateway>  <local-ip>  <metric>"
			if len(fields) >= 5 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
				ip := net.ParseIP(fields[2])
				if ip != nil && ip.To4() != nil && !ip.IsUnspecified() {
					return ip, nil
				}
			}
		}
		gologger.Warningf("Could not determine default gateway — VPN or multiple default routes may require --eth <name>\n")
		return nil, fmt.Errorf("could not parse default gateway")
	}
	return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
}

func AutoGetDevicesImproved(userDNS []string) (*EtherTable, error) {
	gologger.Infof("Trying to get NIC info via default route...\n")

	etherTable, routeErr := GetDefaultRouteInterface()
	if routeErr == nil {
		if validateErr := validateInterface(etherTable); validateErr == nil {
			gologger.Infof("Successfully got NIC info via default route\n")
			return etherTable, nil
		} else {
			gologger.Warningf("NIC validation failed: %v, trying DNS probe\n", validateErr)
		}
	} else {
		gologger.Warningf("Default route method failed: %v, trying DNS probe\n", routeErr)
	}

	return AutoGetDevices(userDNS)
}

func validateInterface(etherTable *EtherTable) error {
	handle, err := pcap.OpenLive(etherTable.Device, 1024, false, time.Second)
	if err != nil {
		return fmt.Errorf("pcap open failed on %s: %v", etherTable.Device, err)
	}
	defer handle.Close()

	if err = handle.SetBPFFilter("udp"); err != nil {
		return fmt.Errorf("BPF filter failed on %s: %v", etherTable.Device, err)
	}
	return nil
}
