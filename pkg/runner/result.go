package runner

import (
	"context"
	"sync"

	kserrors "github.com/LegionShield/legion-subdomain/v2/pkg/core/errors"
	"github.com/LegionShield/legion-subdomain/v2/pkg/core/predict"
	"github.com/LegionShield/legion-subdomain/v2/pkg/runner/result"
)

// handleResult
func (r *Runner) handleResult(predictChan chan string) {
	isWildCard := r.options.WildcardFilterMode != "none"
	var wg sync.WaitGroup
	var predictSignal bool = false

	for res := range r.resultChan {
		if isWildCard {
			if checkWildIps(r.options.WildIps, res.Answers) {
				continue
			}
		}

		for _, out := range r.options.Writer {
			_ = out.WriteDomainResult(res)
		}

		if r.options.Predict {
			wg.Add(1)
			go func(domain string) {
				defer wg.Done()
				r.predict(res, predictChan)
				if !predictSignal {
					r.predictLoadDone <- struct{}{}
					predictSignal = true
				}
			}(res.Subdomain)
		}
	}
	wg.Wait()
}

// predict
func (r *Runner) predict(res result.Result, predictChan chan string) error {
	if r.domainChan == nil {
		return kserrors.ErrDomainChanNil
	}
	_, err := predict.PredictDomains(res.Subdomain, predictChan)
	if err != nil {
		return err
	}
	return nil
}

// handleResultWithContext
func (r *Runner) handleResultWithContext(ctx context.Context, wg *sync.WaitGroup, predictChan chan string) {
	defer wg.Done()
	isWildCard := r.options.WildcardFilterMode != "none"
	var predictWg sync.WaitGroup
	var predictSignal bool = false

	for {
		select {
		case <-ctx.Done():
			predictWg.Wait()
			return
		case res, ok := <-r.resultChan:
			if !ok {
				predictWg.Wait()
				return
			}
			if isWildCard {
				if checkWildIps(r.options.WildIps, res.Answers) {
					continue
				}
			}

			for _, out := range r.options.Writer {
				_ = out.WriteDomainResult(res)
			}

			if r.options.Predict {
				predictWg.Add(1)
				go func(domain string) {
					defer predictWg.Done()
					r.predict(res, predictChan)
					if !predictSignal {
						r.predictLoadDone <- struct{}{}
						predictSignal = true
					}
				}(res.Subdomain)
			}
		}
	}
}

// checkWildIps
func checkWildIps(wildIps []string, ip []string) bool {
	for _, w := range wildIps {
		for _, i := range ip {
			if w == i {
				return true
			}
		}
	}
	return false
}
