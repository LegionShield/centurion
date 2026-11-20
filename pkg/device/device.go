package device

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	kserrors "github.com/LegionShield/legion-subdomain/v2/pkg/core/errors"
	"github.com/LegionShield/legion-subdomain/v2/pkg/core/gologger"
	"github.com/google/gopacket/pcap"
	"gopkg.in/yaml.v3"
)

type EtherTable struct {
	SrcIp  net.IP  `yaml:"src_ip"`
	Device string  `yaml:"device"`
	SrcMac SelfMac `yaml:"src_mac"`
	DstMac SelfMac `yaml:"dst_mac"`
}

func ReadConfig(filename string) (*EtherTable, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var ether EtherTable
	err = yaml.Unmarshal(data, &ether)
	if err != nil {
		return nil, err
	}
	return &ether, nil
}

func (e *EtherTable) SaveConfig(filename string) error {
	data, err := yaml.Marshal(e)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0666)
}

func isWSL() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return false
	}
	version := strings.ToLower(string(data))
	return strings.Contains(version, "microsoft") || strings.Contains(version, "wsl")
}

func isDeviceUp(devicename string) bool {
	iface, err := net.InterfaceByName(devicename)
	if err != nil {
		return false
	}
	return iface.Flags&net.FlagUp != 0
}

func PcapInit(devicename string) (*pcap.Handle, error) {
	inactive, err := pcap.NewInactiveHandle(devicename)
	if err != nil {
		return nil, fmt.Errorf("failed to create pcap handle on %s: %w", devicename, err)
	}
	defer inactive.CleanUp()

	if err = inactive.SetSnapLen(65536); err != nil {
		return nil, fmt.Errorf("pcap: SetSnapLen failed on %s: %w", devicename, err)
	}

	if err = inactive.SetTimeout(-1 * time.Second); err != nil {
		return nil, fmt.Errorf("pcap: SetTimeout failed on %s: %w", devicename, err)
	}

	if runtime.GOOS == "darwin" {
		bufferSize := 2 * 1024 * 1024
		if err = inactive.SetBufferSize(bufferSize); err != nil {
			gologger.Warningf("pcap: SetBufferSize skipped on %s: %v\n", devicename, err)
		} else {
			gologger.Debugf("pcap: BPF buffer = %dMB on %s\n", bufferSize/(1024*1024), devicename)
		}
	}

	if err = inactive.SetImmediateMode(true); err != nil {
		gologger.Debugf("pcap: SetImmediateMode skipped on %s: %v\n", devicename, err)
	}

	handle, err := inactive.Activate()
	if err != nil {
		errMsg := err.Error()

		if strings.Contains(errMsg, "not up") {
			var solution string
			if isWSL() {
				solution = fmt.Sprintf(
					"NIC %s is not up (WSL/WSL2 environment detected)\n\n"+
						"Solution:\n"+
						"  1. Bring up the NIC: sudo ip link set %s up\n"+
						"  2. Or use another NIC: legion-subdomain --eth <nic-name>\n"+
						"  3. List available NICs: ip link show\n"+
						"  4. WSL2 usually uses eth0, try: --eth eth0\n",
					devicename, devicename,
				)
			} else {
				solution = fmt.Sprintf(
					"NIC %s is not up\n\n"+
						"Solution:\n"+
						"  1. Linux:   sudo ip link set %s up\n"+
						"  2. Or use another NIC: legion-subdomain --eth <nic-name>\n"+
						"  3. List available NICs: ip link show or ifconfig -a\n",
					devicename, devicename,
				)
			}
			gologger.Errorf(solution)
			return nil, fmt.Errorf("%w: %s", kserrors.ErrDeviceNotActive, devicename)
		}

		if strings.Contains(errMsg, "permission denied") || strings.Contains(errMsg, "Operation not permitted") {
			solution := fmt.Sprintf(
				"Permission denied, cannot access NIC %s\n\n"+
					"Solution:\n"+
					"  Run: sudo %s [args...]\n",
				devicename, os.Args[0],
			)
			gologger.Errorf(solution)
			return nil, fmt.Errorf("%w: %s", kserrors.ErrPermissionDenied, devicename)
		}

		if strings.Contains(errMsg, "No such device") || strings.Contains(errMsg, "doesn't exist") {
			solution := fmt.Sprintf(
				"NIC %s not found\n\n"+
					"Solution:\n"+
					"  1. List available NICs:\n"+
					"     Linux/WSL: ip link show\n"+
					"     macOS:     ifconfig -a\n"+
					"  2. Use the correct NIC name: legion-subdomain --eth <nic-name>\n"+
					"  3. Common NIC names:\n"+
					"     Linux: eth0, ens33, wlan0\n"+
					"     macOS: en0, en1\n"+
					"     WSL2:  eth0\n",
				devicename,
			)
			gologger.Errorf(solution)
			return nil, fmt.Errorf("%w: %s", kserrors.ErrDeviceNotFound, devicename)
		}

		return nil, fmt.Errorf("pcap init failed on %s: %s", devicename, errMsg)
	}

	return handle, nil
}
