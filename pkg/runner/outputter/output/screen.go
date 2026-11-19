package output

import (
	"strings"

	"github.com/LegionShield/legion-subdomain/v2/pkg/core"
	"github.com/LegionShield/legion-subdomain/v2/pkg/core/gologger"
	"github.com/LegionShield/legion-subdomain/v2/pkg/runner/result"
)

type ScreenOutput struct {
	windowsWidth int
	silent       bool
	onlyDomain   bool
}

func NewScreenOutput(silent bool, onlyDomain ...bool) (*ScreenOutput, error) {
	windowsWidth := core.GetWindowWith()
	s := new(ScreenOutput)
	s.windowsWidth = windowsWidth
	s.silent = silent
	if len(onlyDomain) > 0 {
		s.onlyDomain = onlyDomain[0]
	}
	return s, nil
}

func (s *ScreenOutput) WriteDomainResult(domain result.Result) error {
	var msg string
	
	if s.onlyDomain {
		msg = domain.Subdomain
	} else {
		var domains []string = []string{domain.Subdomain}
		for _, item := range domain.Answers {
			domains = append(domains, item)
		}
		msg = strings.Join(domains, " => ")
	}
	
	if !s.silent {
		// Pad to terminal width to overwrite any progress-bar remnants,
		// but do NOT prefix with \r — that would corrupt piped output
		// (e.g. `legion-subdomain ... --od --silent | httpx`).
		screenWidth := s.windowsWidth - len(msg) - 1
		if screenWidth < 0 {
			screenWidth = 0
		}
		gologger.Silentf("%s% *s\n", msg, screenWidth, "")
	} else {
		// silent=true: plain domain-per-line, no control characters.
		// This is the canonical pipe-friendly mode (--od --silent | httpx).
		gologger.Silentf("%s\n", msg)
	}
	return nil
}

func (s *ScreenOutput) Close() error {
	return nil
}
