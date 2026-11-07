package options

import (
	"testing"

	"github.com/LegionShield/legion-subdomain/v2/pkg/core/gologger"
	"github.com/LegionShield/legion-subdomain/v2/pkg/device"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- Band2Rate ----

func TestBand2Rate_Megabits(t *testing.T) {
	rate := Band2Rate("1m")
	// 1_000_000 bytes/s ÷ 80 bytes/packet = 12500 pps
	assert.Equal(t, int64(1_000_000/80), rate)
}

func TestBand2Rate_Kilobits(t *testing.T) {
	rate := Band2Rate("100k")
	assert.Equal(t, int64(100_000/80), rate)
}

func TestBand2Rate_Gigabits(t *testing.T) {
	rate := Band2Rate("1g")
	assert.Equal(t, int64(1_000_000_000/80), rate)
}

func TestBand2Rate_UpperCase(t *testing.T) {
	assert.Equal(t, Band2Rate("1m"), Band2Rate("1M"))
	assert.Equal(t, Band2Rate("1k"), Band2Rate("1K"))
	assert.Equal(t, Band2Rate("1g"), Band2Rate("1G"))
}

func TestBand2Rate_LargeValue(t *testing.T) {
	rate := Band2Rate("10m")
	assert.Equal(t, int64(10_000_000/80), rate)
}

// ---- GetResolvers ----

func TestGetResolvers_DefaultWhenNil(t *testing.T) {
	rs := GetResolvers(nil)
	require.NotEmpty(t, rs)
	assert.Contains(t, rs, "8.8.8.8")
	assert.Contains(t, rs, "1.1.1.1")
}

func TestGetResolvers_CustomList(t *testing.T) {
	custom := []string{"223.5.5.5", "119.29.29.29"}
	rs := GetResolvers(custom)
	assert.Equal(t, custom, rs)
}

func TestGetResolvers_EmptySliceReturnsEmpty(t *testing.T) {
	// 空 slice（非 nil）原样返回，不填充默认值
	rs := GetResolvers([]string{})
	assert.Empty(t, rs)
}

func TestGetResolvers_SingleEntry(t *testing.T) {
	rs := GetResolvers([]string{"114.114.114.114"})
	require.Len(t, rs, 1)
	assert.Equal(t, "114.114.114.114", rs[0])
}

// ---- Options.AllEtherInfos ----

func TestAllEtherInfos_NilBoth(t *testing.T) {
	opt := &Options{}
	assert.Nil(t, opt.AllEtherInfos())
}

func TestAllEtherInfos_FallbackToSingleEtherInfo(t *testing.T) {
	single := &device.EtherTable{Device: "eth0"}
	opt := &Options{EtherInfo: single}
	result := opt.AllEtherInfos()
	require.Len(t, result, 1)
	assert.Equal(t, single, result[0])
}

func TestAllEtherInfos_PreferEtherInfosOverSingle(t *testing.T) {
	single := &device.EtherTable{Device: "eth0"}
	multi := []*device.EtherTable{
		{Device: "eth1"},
		{Device: "eth2"},
	}
	opt := &Options{
		EtherInfo:  single,
		EtherInfos: multi,
	}
	result := opt.AllEtherInfos()
	require.Len(t, result, 2)
	assert.Equal(t, "eth1", result[0].Device)
	assert.Equal(t, "eth2", result[1].Device)
}

func TestAllEtherInfos_MultipleCards(t *testing.T) {
	cards := []*device.EtherTable{
		{Device: "eth0"},
		{Device: "eth1"},
		{Device: "eth2"},
	}
	opt := &Options{EtherInfos: cards}
	result := opt.AllEtherInfos()
	assert.Len(t, result, 3)
}

// ---- Options.Check ----

func TestCheck_SilentSetsLogLevel(t *testing.T) {
	prev := gologger.MaxLevel
	defer func() { gologger.MaxLevel = prev }()

	opt := &Options{Silent: true}
	opt.Check()
	assert.Equal(t, gologger.Silent, gologger.MaxLevel)
}

func TestCheck_NonSilentKeepsLevel(t *testing.T) {
	prev := gologger.MaxLevel
	defer func() { gologger.MaxLevel = prev }()

	gologger.MaxLevel = gologger.Info
	opt := &Options{Silent: false}
	opt.Check()
	assert.Equal(t, gologger.Info, gologger.MaxLevel)
}
