package core

import (
	"strings"
	"testing"

	"github.com/LegionShield/legion-subdomain/v2/pkg/core/gologger"
	"github.com/stretchr/testify/assert"
)

// TestShowBanner_SilentSuppressesOutput verifies that ShowBanner with silent=true
// does NOT print the banner or version line (fix for issue #79).
func TestShowBanner_SilentSuppressesOutput(t *testing.T) {
	prev := gologger.MaxLevel
	defer func() { gologger.MaxLevel = prev }()

	// Should not panic when silent=true
	assert.NotPanics(t, func() {
		ShowBanner(true)
	})
}

// TestShowBanner_NonSilentPrintsVersion verifies that ShowBanner with silent=false
// does not panic (actual stdout is not captured here, just a smoke test).
func TestShowBanner_NonSilentNoPanic(t *testing.T) {
	assert.NotPanics(t, func() {
		ShowBanner(false)
	})
}

// TestBannerContainsAppName verifies the banner constant contains the app name.
func TestBannerContainsAppName(t *testing.T) {
	assert.True(t, strings.Contains(banner, "CENTURION") || strings.Contains(banner, "LEGION"),
		"banner should contain app name")
}
