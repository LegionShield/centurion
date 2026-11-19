package runner

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/LegionShield/legion-subdomain/v2/pkg/core/gologger"
	"github.com/LegionShield/legion-subdomain/v2/pkg/runner/result"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func parseDNSName(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	
	var result []byte
	i := 0
	
	for i < len(raw) {
		length := int(raw[i])
		
		// 0x00
		if length == 0 {
			break
		}
		
		// 0xC0
		if length >= 0xC0 {
			break
		}
		
		if len(result) > 0 {
			result = append(result, '.')
		}
		
		i++
		
		if i+length > len(raw) {
			break
		}
		
		result = append(result, raw[i:i+length]...)
		i += length
	}
	
	return string(result)
}

func dnsRecord2String(rr layers.DNSResourceRecord) (string, error) {
	if rr.Class == layers.DNSClassIN {
		switch rr.Type {
		case layers.DNSTypeA, layers.DNSTypeAAAA:
			if rr.IP != nil {
				return rr.IP.String(), nil
			}
		case layers.DNSTypeNS:
			if rr.NS != nil {
				ns := parseDNSName(rr.NS)
				if ns != "" {
					return "NS " + ns, nil
				}
			}
		case layers.DNSTypeCNAME:
			if rr.CNAME != nil {
				cname := parseDNSName(rr.CNAME)
				if cname != "" {
					return "CNAME " + cname, nil
				}
			}
		case layers.DNSTypePTR:
			if rr.PTR != nil {
				ptr := parseDNSName(rr.PTR)
				if ptr != "" {
					return "PTR " + ptr, nil
				}
			}
		case layers.DNSTypeTXT:
			if rr.TXT != nil {
				return "TXT " + string(rr.TXT), nil
			}
		}
	}
	return "", errors.New("dns record error")
}

var decoderPool = sync.Pool{
	New: func() interface{} {
		var eth layers.Ethernet
		var ipv4 layers.IPv4
		var ipv6 layers.IPv6
		var udp layers.UDP
		var dns layers.DNS
		parser := gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet, &eth, &ipv4, &ipv6, &udp, &dns)

		return &decodingContext{
			parser:  parser,
			eth:     &eth,
			ipv4:    &ipv4,
			ipv6:    &ipv6,
			udp:     &udp,
			dns:     &dns,
			decoded: make([]gopacket.LayerType, 0, 5),
		}
	},
}

type decodingContext struct {
	parser  *gopacket.DecodingLayerParser
	eth     *layers.Ethernet
	ipv4    *layers.IPv4
	ipv6    *layers.IPv6
	udp     *layers.UDP
	dns     *layers.DNS
	decoded []gopacket.LayerType
}

func (r *Runner) processPacket(data []byte, dnsChanel chan<- layers.DNS) {
	dc := decoderPool.Get().(*decodingContext)
	defer decoderPool.Put(dc)

	dc.decoded = dc.decoded[:0]

	err := dc.parser.DecodeLayers(data, &dc.decoded)
	if err != nil {
		return
	}

	if !dc.dns.QR {
		return
	}

	if dc.dns.ID != r.dnsID {
		return
	}

	if len(dc.dns.Questions) == 0 {
		return
	}

	atomic.AddUint64(&r.receiveCount, 1)

	select {
	case dnsChanel <- *dc.dns:
	}
}

func (r *Runner) recvChanelForIface(ctx context.Context, wg *sync.WaitGroup, iface *netInterface) {
	defer wg.Done()
	var (
		snapshotLen = 65536
		timeout     = 5 * time.Second
		err         error
	)
	inactive, err := pcap.NewInactiveHandle(iface.etherInfo.Device)
	if err != nil {
		gologger.Errorf("Failed to create capture handle [%s]: %v", iface.etherInfo.Device, err)
		return
	}
	err = inactive.SetSnapLen(snapshotLen)
	if err != nil {
		gologger.Errorf("Failed to set capture length [%s]: %v", iface.etherInfo.Device, err)
		return
	}
	defer inactive.CleanUp()

	if err = inactive.SetTimeout(timeout); err != nil {
		gologger.Errorf("Failed to set timeout [%s]: %v", iface.etherInfo.Device, err)
		return
	}

	err = inactive.SetImmediateMode(true)
	if err != nil {
		gologger.Errorf("Failed to set immediate mode [%s]: %v", iface.etherInfo.Device, err)
		return
	}

	handle, err := inactive.Activate()
	if err != nil {
		gologger.Errorf("Failed to activate capture [%s]: %v", iface.etherInfo.Device, err)
		return
	}
	defer handle.Close()

	err = handle.SetBPFFilter(fmt.Sprintf("udp and src port 53 and dst port %d", iface.listenPort))
	if err != nil {
		gologger.Errorf("Failed to set BPF filter [%s]: %v", iface.etherInfo.Device, err)
		return
	}

	dnsChanel := make(chan layers.DNS, 10000)

	processorCount := runtime.NumCPU() * 2
	var processorWg sync.WaitGroup
	processorWg.Add(processorCount)

	for i := 0; i < processorCount; i++ {
		go func() {
			defer processorWg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case dns, ok := <-dnsChanel:
					if !ok {
						return
					}

					subdomain := string(dns.Questions[0].Name)
					r.statusDB.Del(subdomain)
					if dns.ANCount > 0 {
						atomic.AddUint64(&r.successCount, 1)
						var answers []string
						for _, v := range dns.Answers {
							answer, err := dnsRecord2String(v)
							if err != nil {
								continue
							}
							answers = append(answers, answer)
						}
						r.resultChan <- result.Result{
							Subdomain: subdomain,
							Answers:   answers,
						}
					}
				}
			}
		}()
	}

	packetChan := make(chan []byte, 10000)

	go func() {
		for {
			data, _, err := handle.ReadPacketData()
			if err != nil {
				if errors.Is(err, pcap.NextErrorTimeoutExpired) {
					continue
				}
				return
			}

			select {
			case <-ctx.Done():
				return
			case packetChan <- data:
			}
		}
	}()

	parserCount := runtime.NumCPU() * 2
	var parserWg sync.WaitGroup
	parserWg.Add(parserCount)

	for i := 0; i < parserCount; i++ {
		go func() {
			defer parserWg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case data, ok := <-packetChan:
					if !ok {
						return
					}
					r.processPacket(data, dnsChanel)
				}
			}
		}()
	}

	<-ctx.Done()

	close(packetChan)
	close(dnsChanel)

	parserWg.Wait()
	processorWg.Wait()
}
