package device

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"

	"github.com/LegionShield/legion-subdomain/v2/pkg/core"
	"github.com/LegionShield/legion-subdomain/v2/pkg/core/gologger"
	"github.com/LegionShield/legion-subdomain/v2/pkg/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func GetAllIPv4Devices() ([]string, map[string]net.IP) {
	devices, err := pcap.FindAllDevs()
	deviceNames := []string{}
	deviceMap := make(map[string]net.IP)

	if err != nil {
		gologger.Fatalf("Failed to get network devices: %s\n", err.Error())
		return deviceNames, deviceMap
	}

	for _, d := range devices {
		for _, address := range d.Addresses {
			ip := address.IP
			if ip.To4() != nil {
				deviceMap[d.Name] = ip
				deviceNames = append(deviceNames, d.Name)
			}
		}
	}

	return deviceNames, deviceMap
}

func ValidDNS(dns string) bool {
	if dns == "" {
		return false
	}
	_, err := LookUpIP("www.baidu.com", dns)
	if err != nil {
		return false
	}
	return true
}

func AutoGetDevices(userDNS []string) (*EtherTable, error) {
	var validDNS []string

	// 1.
	if len(userDNS) > 0 {
		for _, dns := range userDNS {

			if ValidDNS(dns) {
				validDNS = append(validDNS, dns)
			} else {
				gologger.Warningf("User-provided DNS server invalid: %s\n", dns)
			}
		}
	}

	// 2.
	if len(validDNS) == 0 {
		gologger.Infof("Trying to get system DNS servers...\n")
		systemDNS, err := utils.GetSystemDefaultDNS()
		if err == nil && len(systemDNS) > 0 {
			for _, dns := range systemDNS {
				if ValidDNS(dns) {
					validDNS = append(validDNS, dns)
				} else {
					gologger.Debugf("System DNS server invalid: %s\n", dns)
				}
			}
		} else {
			gologger.Warningf("Failed to get system DNS: %v\n", err)
		}
	}

	if len(validDNS) == 0 {
		return nil, fmt.Errorf("no valid DNS found, cannot proceed")
	}

	gologger.Infof("Using DNS servers for test: %v\n", validDNS)
	return AutoGetDevicesWithDNS(validDNS), nil
}

// AutoGetDevicesWithDNS
func AutoGetDevicesWithDNS(validDNS []string) *EtherTable {
	deviceNames, _ := GetAllIPv4Devices()
	if len(deviceNames) == 0 {
		gologger.Fatalf("No usable IPv4 NIC found\n")
		return nil
	}

	domain := core.RandomStr(6) + ".baidu.com"
	signal := make(chan *EtherTable)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	activeDeviceCount := 0
	for _, deviceName := range deviceNames {
		gologger.Infof("Testing connectivity of NIC %s...\n", deviceName)
		go testDeviceConnectivity(ctx, deviceName, domain, signal)
		activeDeviceCount++
	}
	return waitForDeviceTest(signal, domain, validDNS, 30)
}

func testDeviceConnectivity(ctx context.Context, deviceName string, domain string, signal chan<- *EtherTable) {
	var (
		snapshot_len int32         = 2048
		promiscuous  bool          = true
		timeout      time.Duration = 500 * time.Millisecond
	)

	handle, err := pcap.OpenLive(deviceName, snapshot_len, promiscuous, timeout)
	if err != nil {
		gologger.Debugf("Cannot open NIC %s: %s\n", deviceName, err.Error())
		return
	}
	defer handle.Close()

	err = handle.SetBPFFilter("udp port 53")
	if err != nil {
		gologger.Debugf("Failed to set filter %s: %s\n", deviceName, err.Error())
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
			var udp layers.UDP
			var dns layers.DNS
			var eth layers.Ethernet
			var ipv4 layers.IPv4

			parser := gopacket.NewDecodingLayerParser(
				layers.LayerTypeEthernet, &eth, &ipv4, &udp, &dns)

			data, _, err := handle.ReadPacketData()
			if err != nil {
				if errors.Is(err, pcap.NextErrorTimeoutExpired) {
					continue
				}
				continue
			}

			var decoded []gopacket.LayerType
			err = parser.DecodeLayers(data, &decoded)
			if err != nil {
				continue
			}

			dnsFound := false
			for _, layerType := range decoded {
				if layerType == layers.LayerTypeDNS {
					dnsFound = true
					break
				}
			}
			if !dnsFound {
				continue
			}

			if !dns.QR {
				continue
			}

			for _, q := range dns.Questions {
				questionName := string(q.Name)
				gologger.Debugf("DNS response received on %s, domain: %s\n", deviceName, questionName)
				if questionName == domain || questionName == domain+"." {
					etherTable := EtherTable{
						SrcIp:  ipv4.DstIP,
						Device: deviceName,
						SrcMac: SelfMac(eth.DstMAC),
						DstMac: SelfMac(eth.SrcMAC),
					}
					signal <- &etherTable
					return
				}
			}
		}
	}
}

func waitForDeviceTest(signal <-chan *EtherTable, domain string, dnsServers []string, timeout int) *EtherTable {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	count := 0
	dnsIndex := 0

	for {
		select {
		case result := <-signal:
			gologger.Infof("Successfully detected outbound NIC: %s\n", result.Device)
			return result
		case <-ticker.C:
			currentDNS := dnsServers[dnsIndex]
			dnsIndex = (dnsIndex + 1) % len(dnsServers)

			go func(server string) {
				ip, err := LookUpIP(domain, server)
				if err != nil {
					gologger.Debugf("DNS query failed (%s): %s\n", server, err.Error())
				} else if ip != nil {
					gologger.Debugf("DNS query OK (%s): %s -> %s\n", server, domain, ip.String())
				}
			}(currentDNS)

			fmt.Print(".")
			count++

			if count >= timeout {
				gologger.Fatalf("Timed out detecting NIC, try specifying --eth manually\n")
				return nil
			}
		}
	}
}

// LookUpIP
func LookUpIP(fqdn, serverAddr string) (net.IP, error) {
	var m dns.Msg
	client := dns.Client{}
	client.Timeout = time.Second
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeA)
	r, _, err := client.Exchange(&m, serverAddr+":53")

	if err != nil {
		return nil, err
	}

	if r == nil || len(r.Answer) == 0 {
		return nil, fmt.Errorf("no DNS reply")
	}

	for _, ans := range r.Answer {
		if a, ok := ans.(*dns.A); ok {
			return a.A, nil
		}
	}

	return nil, fmt.Errorf("no A record")
}
