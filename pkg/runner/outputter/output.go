package outputter

import (
	"github.com/LegionShield/legion-subdomain/v2/pkg/runner/result"
)

type Output interface {
	WriteDomainResult(domain result.Result) error
	Close() error
}
