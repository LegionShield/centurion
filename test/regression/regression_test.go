//go:build regression
// +build regression

// Package regression contains end-to-end regression tests for legion-subdomain.
//
// These tests require:
//   - Root / CAP_NET_RAW privileges (pcap)
//   - Network access to public DNS resolvers
//
// Run with:
//
//	sudo go test ./test/regression/... -tags regression -v -timeout 120s
package regression

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/LegionShield/legion-subdomain/v2/pkg/core/options"
	"github.com/LegionShield/legion-subdomain/v2/pkg/runner"
	"github.com/LegionShield/legion-subdomain/v2/pkg/runner/outputter"
	output2 "github.com/LegionShield/legion-subdomain/v2/pkg/runner/outputter/output"
	processbar2 "github.com/LegionShield/legion-subdomain/v2/pkg/runner/processbar"
	"github.com/LegionShield/legion-subdomain/v2/pkg/runner/result"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================
// Shared helpers
// ============================================================

// collectOutput is a thread-safe output collector for tests.
type collectOutput struct {
	results []result.Result
}

func (c *collectOutput) WriteDomainResult(r result.Result) error {
	c.results = append(c.results, r)
	return nil
}
func (c *collectOutput) Close() error { return nil }

// runVerify runs a verify scan over the given domains and returns results.
func runVerify(t *testing.T, domains []string, timeoutSec int) []result.Result {
	t.Helper()
	eth := options.GetDeviceConfig(options.GetResolvers(nil))
	require.NotNil(t, eth, "failed to detect network device")

	col := &collectOutput{}
	screen, err := output2.NewScreenOutputNoWidth(true)
	require.NoError(t, err)

	domainChan := make(chan string, len(domains))
	for _, d := range domains {
		domainChan <- d
	}
	close(domainChan)

	opt := &options.Options{
		Rate:       options.Band2Rate("1m"),
		Domain:     domainChan,
		Resolvers:  options.GetResolvers(nil),
		Silent:     true,
		TimeOut:    timeoutSec,
		Retry:      3,
		Method:     options.VerifyType,
		Writer:     []outputter.Output{col, screen},
		ProcessBar: &processbar2.FakeScreenProcess{},
		EtherInfo:  eth,
	}
	opt.Check()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec+10)*time.Second)
	defer cancel()

	r, err := runner.New(opt)
	require.NoError(t, err)
	r.RunEnumeration(ctx)
	r.Close()
	return col.results
}

// runEnum runs an enum scan with a small wordlist and returns results.
func runEnum(t *testing.T, domain string, words []string, timeoutSec int) []result.Result {
	t.Helper()
	eth := options.GetDeviceConfig(options.GetResolvers(nil))
	require.NotNil(t, eth, "failed to detect network device")

	col := &collectOutput{}
	screen, err := output2.NewScreenOutputNoWidth(true)
	require.NoError(t, err)

	domainChan := make(chan string, len(words))
	for _, w := range words {
		domainChan <- w + "." + domain
	}
	close(domainChan)

	opt := &options.Options{
		Rate:       options.Band2Rate("1m"),
		Domain:     domainChan,
		Resolvers:  options.GetResolvers(nil),
		Silent:     true,
		TimeOut:    timeoutSec,
		Retry:      3,
		Method:     options.EnumType,
		Writer:     []outputter.Output{col, screen},
		ProcessBar: &processbar2.FakeScreenProcess{},
		EtherInfo:  eth,
	}
	opt.Check()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec+10)*time.Second)
	defer cancel()

	r, err := runner.New(opt)
	require.NoError(t, err)
	r.RunEnumeration(ctx)
	r.Close()
	return col.results
}

// ============================================================
// Regression: verify subcommand
// ============================================================

// TestRegression_Verify_KnownGoodDomains checks that well-known stable domains resolve.
func TestRegression_Verify_KnownGoodDomains(t *testing.T) {
	knownGood := []string{
		"www.baidu.com",
		"dns.google",
	}

	results := runVerify(t, knownGood, 10)

	resolved := make(map[string]bool)
	for _, r := range results {
		resolved[r.Subdomain] = true
		assert.NotEmpty(t, r.Answers, "domain %s should have answers", r.Subdomain)
	}

	for _, d := range knownGood {
		assert.True(t, resolved[d], "expected %s to be resolved", d)
	}
}

// TestRegression_Verify_NonExistentDomain checks that NXDOMAIN entries are NOT returned.
func TestRegression_Verify_NonExistentDomain(t *testing.T) {
	nxDomains := []string{
		"this-domain-does-absolutely-not-exist-legion-subdomain-test.com",
		"aaaabbbbcccc-nxdomain-legion-subdomain.org",
	}

	results := runVerify(t, nxDomains, 10)
	for _, r := range results {
		t.Errorf("NXDOMAIN %s was unexpectedly resolved: %v", r.Subdomain, r.Answers)
	}
}

// TestRegression_Verify_MixedDomains checks accuracy on a mixed set.
func TestRegression_Verify_MixedDomains(t *testing.T) {
	domains := []string{
		"www.baidu.com",
		"this-is-nxdomain-legion-subdomain-regression.example.invalid",
	}

	results := runVerify(t, domains, 10)

	resolved := make(map[string]bool)
	for _, r := range results {
		resolved[r.Subdomain] = true
	}

	assert.True(t, resolved["www.baidu.com"], "www.baidu.com should resolve")
	assert.False(t, resolved["this-is-nxdomain-legion-subdomain-regression.example.invalid"],
		"NXDOMAIN should not appear in results")
}

// TestRegression_Verify_ResultFields checks that result fields are correctly populated.
func TestRegression_Verify_ResultFields(t *testing.T) {
	results := runVerify(t, []string{"www.baidu.com"}, 10)
	require.NotEmpty(t, results, "expected at least one result for www.baidu.com")

	r := results[0]
	assert.Equal(t, "www.baidu.com", r.Subdomain)
	assert.NotEmpty(t, r.Answers, "answers should not be empty")
	for _, ans := range r.Answers {
		assert.NotEmpty(t, ans, "each answer should be non-empty string")
	}
}

// ============================================================
// Regression: enum subcommand
// ============================================================

// TestRegression_Enum_CommonSubdomains enumerates known-existing subdomains of baidu.com.
func TestRegression_Enum_CommonSubdomains(t *testing.T) {
	// Small wordlist; "www" is guaranteed to resolve under baidu.com
	words := []string{"www", "news", "map"}

	results := runEnum(t, "baidu.com", words, 15)

	resolved := make(map[string]bool)
	for _, r := range results {
		resolved[r.Subdomain] = true
		assert.NotEmpty(t, r.Answers, "enum result %s should have answers", r.Subdomain)
	}

	assert.True(t, resolved["www.baidu.com"], "www.baidu.com must appear in enum results")
}

// TestRegression_Enum_NoFalsePositives checks that nonsense words don't resolve.
func TestRegression_Enum_NoFalsePositives(t *testing.T) {
	words := []string{
		"zzznobodyregisteredthisxyz123",
		"legion-subdomain-regression-test-abc987",
	}

	results := runEnum(t, "baidu.com", words, 10)
	assert.Empty(t, results, "nonsense subdomains should not resolve")
}

// ============================================================
// Regression: CLI binary (smoke tests)
// ============================================================

// binaryPath returns the path to the legion-subdomain binary, or skips the test.
func binaryPath(t *testing.T) string {
	t.Helper()
	// Try current directory first (typical for CI after go build)
	if _, err := exec.LookPath("./legion-subdomain"); err == nil {
		return "./legion-subdomain"
	}
	path, err := exec.LookPath("legion-subdomain")
	if err != nil {
		t.Skip("legion-subdomain binary not found; run: go build -o legion-subdomain ./cmd/legion-subdomain")
	}
	return path
}

// TestRegression_CLI_Version checks `legion-subdomain --version` exits 0 and prints version.
func TestRegression_CLI_Version(t *testing.T) {
	bin := binaryPath(t)
	out, err := exec.Command(bin, "--version").CombinedOutput()
	assert.NoError(t, err, "legion-subdomain --version should exit 0, output: %s", string(out))
	assert.NotEmpty(t, string(out))
}

// TestRegression_CLI_SubcommandHelp checks that all subcommands display help.
func TestRegression_CLI_SubcommandHelp(t *testing.T) {
	bin := binaryPath(t)
	subcommands := []string{"enum", "verify", "test", "device"}
	for _, sub := range subcommands {
		t.Run(sub, func(t *testing.T) {
			out, _ := exec.Command(bin, sub, "--help").CombinedOutput()
			// cli/v2 exits non-zero for --help but must print usage text
			assert.NotEmpty(t, string(out), "%s --help should print usage", sub)
			assert.True(t, strings.Contains(string(out), sub),
				"%s --help output should mention the subcommand name", sub)
		})
	}
}

// TestRegression_CLI_Silent checks that --silent suppresses the banner (fix #79).
func TestRegression_CLI_Silent(t *testing.T) {
	bin := binaryPath(t)
	cmd := exec.Command(bin, "verify",
		"--domain", "www.baidu.com",
		"--silent",
		"--timeout", "8",
		"--retry", "1",
		"--bandwidth", "1m",
	)
	out, _ := cmd.CombinedOutput()
	outStr := string(out)

	// ASCII art banner must not appear
	assert.False(t, strings.Contains(outStr, "legion-subdomain") && strings.Contains(outStr, "___"),
		"ASCII banner should be suppressed with --silent, got:\n%s", outStr)

	// Version log line must not appear
	assert.False(t, strings.Contains(outStr, "Current Version"),
		"version line should be suppressed with --silent, got:\n%s", outStr)
}

// TestRegression_CLI_ShortSilentAlias checks that -s works as alias for --silent (fix #79).
func TestRegression_CLI_ShortSilentAlias(t *testing.T) {
	bin := binaryPath(t)
	cmd := exec.Command(bin, "verify",
		"--domain", "www.baidu.com",
		"-s",
		"--timeout", "8",
		"--retry", "1",
		"--bandwidth", "1m",
	)
	out, _ := cmd.CombinedOutput()
	outStr := string(out)

	assert.False(t, strings.Contains(outStr, "Current Version"),
		"-s alias should suppress output, got:\n%s", outStr)
}
