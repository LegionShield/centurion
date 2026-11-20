package runner

import (
	"strings"
	"testing"

	"github.com/LegionShield/legion-subdomain/v2/pkg/core/options"
	"github.com/LegionShield/legion-subdomain/v2/pkg/runner/outputter"
	"github.com/LegionShield/legion-subdomain/v2/pkg/runner/outputter/output"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- selectDNSServer (pure logic, no network) --------------------------------

func makeRunner(resolvers []string, special map[string][]string) *Runner {
	r := &Runner{
		options: &options.Options{
			Resolvers:        resolvers,
			SpecialResolvers: special,
		},
	}
	return r
}

func TestSelectDNSServer_ReturnsFromDefaultPool(t *testing.T) {
	r := makeRunner([]string{"1.1.1.1", "8.8.8.8"}, nil)
	got := r.selectDNSServer("sub.example.com")
	assert.Contains(t, []string{"1.1.1.1", "8.8.8.8"}, got)
}

func TestSelectDNSServer_EmptyResolvers(t *testing.T) {
	r := makeRunner([]string{}, nil)
	got := r.selectDNSServer("sub.example.com")
	assert.Equal(t, "", got)
}

func TestSelectDNSServer_SpecialExactMatch(t *testing.T) {
	r := makeRunner(
		[]string{"1.1.1.1"},
		map[string][]string{"example.com": {"9.9.9.9"}},
	)
	got := r.selectDNSServer("example.com")
	assert.Equal(t, "9.9.9.9", got)
}

func TestSelectDNSServer_SpecialSuffixMatch(t *testing.T) {
	r := makeRunner(
		[]string{"1.1.1.1"},
		map[string][]string{"example.com": {"9.9.9.9"}},
	)
	got := r.selectDNSServer("sub.example.com")
	assert.Equal(t, "9.9.9.9", got)
}

func TestSelectDNSServer_NoFalseSuffix(t *testing.T) {
	// "evilexample.com" must NOT match the ".example.com" rule.
	r := makeRunner(
		[]string{"1.1.1.1"},
		map[string][]string{"example.com": {"9.9.9.9"}},
	)
	got := r.selectDNSServer("evilexample.com")
	assert.Equal(t, "1.1.1.1", got)
}

func TestSelectDNSServer_LongestSuffixWins(t *testing.T) {
	r := makeRunner(
		[]string{"1.1.1.1"},
		map[string][]string{
			"example.com":     {"short.ns"},
			"sub.example.com": {"long.ns"},
		},
	)
	got := r.selectDNSServer("deep.sub.example.com")
	assert.Equal(t, "long.ns", got)
}

func TestSelectDNSServer_FallsBackWhenNoSpecialMatch(t *testing.T) {
	r := makeRunner(
		[]string{"1.1.1.1"},
		map[string][]string{"other.com": {"9.9.9.9"}},
	)
	got := r.selectDNSServer("example.com")
	assert.Equal(t, "1.1.1.1", got)
}

// ---- runner.New() error paths (no pcap/network needed) ----------------------

func TestRunnerNew_EmptyResolvers(t *testing.T) {
	w, _ := output.NewScreenOutput(true)
	opt := &options.Options{
		Rate:      1000,
		Domain:    make(chan string),
		Resolvers: []string{},
		Silent:    true,
		TimeOut:   3,
		Retry:     1,
		Method:    options.VerifyType,
		Writer:    []outputter.Output{w},
	}
	_, err := New(opt)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "resolver"),
		"expected resolver-related error, got: %v", err)
}

func TestRunnerNew_NilNIC_AllDeadResolvers(t *testing.T) {
	// 192.0.2.x is TEST-NET-1 (RFC 5737) — guaranteed unreachable.
	// runner.New() must fail fast with a clear message before touching pcap.
	w, _ := output.NewScreenOutput(true)
	opt := &options.Options{
		Rate:      1000,
		Domain:    make(chan string),
		Resolvers: []string{"192.0.2.1", "192.0.2.2"},
		Silent:    true,
		TimeOut:   3,
		Retry:     1,
		Method:    options.VerifyType,
		Writer:    []outputter.Output{w},
	}
	_, err := New(opt)
	require.Error(t, err)
	assert.True(t,
		strings.Contains(err.Error(), "reachable") || strings.Contains(err.Error(), "resolver"),
		"expected no-reachable-resolver error, got: %v", err)
}
