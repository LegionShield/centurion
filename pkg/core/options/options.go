package options

import (
	device2 "github.com/LegionShield/legion-subdomain/v2/pkg/device"
	"strconv"

	"github.com/LegionShield/legion-subdomain/v2/pkg/core/gologger"
	"github.com/LegionShield/legion-subdomain/v2/pkg/runner/outputter"
	"github.com/LegionShield/legion-subdomain/v2/pkg/runner/processbar"
)

type OptionMethod string

const (
	VerifyType OptionMethod = "verify"
	EnumType   OptionMethod = "enum"
	TestType   OptionMethod = "test"
)

type Options struct {
	Rate               int64
	Domain             chan string
	Resolvers          []string
	Silent             bool
	TimeOut            int
	Retry              int
	Method             OptionMethod
	Writer             []outputter.Output
	ProcessBar         processbar.ProcessBar
	EtherInfo          *device2.EtherTable
	EtherInfos         []*device2.EtherTable
	SpecialResolvers   map[string][]string
	WildcardFilterMode string
	WildIps            []string
	Predict            bool
}

func (opt *Options) AllEtherInfos() []*device2.EtherTable {
	if len(opt.EtherInfos) > 0 {
		return opt.EtherInfos
	}
	if opt.EtherInfo != nil {
		return []*device2.EtherTable{opt.EtherInfo}
	}
	return nil
}

func Band2Rate(bandWith string) int64 {
	suffix := string(bandWith[len(bandWith)-1])
	rate, _ := strconv.ParseInt(string(bandWith[0:len(bandWith)-1]), 10, 64)
	switch suffix {
	case "G":
		fallthrough
	case "g":
		rate *= 1000000000
	case "M":
		fallthrough
	case "m":
		rate *= 1000000
	case "K":
		fallthrough
	case "k":
		rate *= 1000
	default:
		gologger.Fatalf("unknown bandwith suffix '%s' (supported suffixes are G,M and K)\n", suffix)
	}
	packSize := int64(80)
	rate = rate / packSize
	return rate
}
func GetResolvers(resolvers []string) []string {
	var rs []string
	if resolvers != nil {
		for _, resolver := range resolvers {
			rs = append(rs, resolver)
		}
	} else {
		defaultDns := []string{
			"1.1.1.1",
			"8.8.8.8",
			"180.76.76.76",
			"180.184.1.1",
			"180.184.2.2",
		}
		rs = defaultDns
	}
	return rs
}

func (opt *Options) Check() {
	if opt.Silent {
		gologger.MaxLevel = gologger.Silent
	}
}
