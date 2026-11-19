package runner

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/LegionShield/legion-subdomain/v2/pkg/runner/statusdb"
)

func (r *Runner) retry(ctx context.Context) {
	t := time.NewTicker(200 * time.Millisecond)
	defer t.Stop()

	const batchSize = 100
	retryDomains := make([]string, 0, batchSize)

	lastScanEmpty := false

	workerCount := 4
	retryDomainCh := make(chan string, batchSize*2)
	var wg sync.WaitGroup
	wg.Add(workerCount)

	for i := 0; i < workerCount; i++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case domain, ok := <-retryDomainCh:
					if !ok {
						return
					}
					r.domainChan <- domain
				}
			}
		}()
	}

	dnsBatches := make(map[string][]string)

	for {
		select {
		case <-ctx.Done():
			close(retryDomainCh)
			wg.Wait()
			return
		case <-t.C:
			currentLength := r.statusDB.Length()
			if lastScanEmpty && currentLength == 0 {
				continue
			}

			now := time.Now()
			retryDomains = retryDomains[:0]

			for k := range dnsBatches {
				dnsBatches[k] = dnsBatches[k][:0]
			}

			r.statusDB.Scan(func(key string, v statusdb.Item) error {
				if r.maxRetryCount > 0 && v.Retry > r.maxRetryCount {
					r.statusDB.Del(key)
					atomic.AddUint64(&r.failedCount, 1)
					return nil
				}

				if int64(now.Sub(v.Time).Seconds()) >= r.timeoutSeconds {
					retryDomains = append(retryDomains, key)

					dns := r.selectDNSServer(key)
					if _, ok := dnsBatches[dns]; !ok {
						dnsBatches[dns] = make([]string, 0, batchSize)
					}
					dnsBatches[dns] = append(dnsBatches[dns], key)
				}
				return nil
			})

			lastScanEmpty = len(retryDomains) == 0

			if len(retryDomains) > 0 {
				for _, domain := range retryDomains {
					select {
					case retryDomainCh <- domain:
					default:
						r.domainChan <- domain
					}
				}
			}
		}
	}
}
