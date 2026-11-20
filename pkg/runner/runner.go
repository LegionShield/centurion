package runner

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/LegionShield/legion-subdomain/v2/pkg/core"
	"github.com/LegionShield/legion-subdomain/v2/pkg/core/gologger"
	"github.com/LegionShield/legion-subdomain/v2/pkg/core/options"
	"github.com/LegionShield/legion-subdomain/v2/pkg/device"
	"github.com/LegionShield/legion-subdomain/v2/pkg/runner/processbar"
	"github.com/LegionShield/legion-subdomain/v2/pkg/runner/result"
	"github.com/LegionShield/legion-subdomain/v2/pkg/runner/statusdb"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/phayes/freeport"
	"go.uber.org/ratelimit"
)

type netInterface struct {
	etherInfo     *device.EtherTable
	pcapHandle    *pcap.Handle
	listenPort    int
	templateCache sync.Map
}

type Runner struct {
	statusDB        *statusdb.StatusDb
	options         *options.Options
	rateLimiter     ratelimit.Limiter
	ifaces          []*netInterface
	successCount    uint64
	sendCount       uint64
	attemptCount    uint64
	receiveCount    uint64
	failedCount     uint64
	domainChan      chan string
	resultChan      chan result.Result
	dnsID           uint16
	queryTypes      []layers.DNSType
	maxRetryCount   int
	timeoutSeconds  int64
	initialLoadDone chan struct{}
	predictLoadDone chan struct{}
	startTime       time.Time
	stopSignal      chan struct{}
}

func init() {
	rand.New(rand.NewSource(time.Now().UnixNano()))
}

func New(opt *options.Options) (*Runner, error) {
	version := pcap.Version()
	r := new(Runner)
	gologger.Infof(version)
	r.options = opt
	r.statusDB = statusdb.CreateMemoryDB()

	if len(opt.Resolvers) == 0 {
		return nil, fmt.Errorf("no DNS resolvers configured: provide at least one resolver with -r")
	}
	gologger.Infof("Default DNS servers: %s\n", core.SliceToString(opt.Resolvers))
	if len(opt.SpecialResolvers) > 0 {
		var keys []string
		for k := range opt.SpecialResolvers {
			keys = append(keys, k)
		}
		gologger.Infof("Special DNS servers: %s\n", core.SliceToString(keys))
	}

	allEthers := opt.AllEtherInfos()
	if len(allEthers) == 0 {
		return nil, fmt.Errorf("no NIC config available — use --eth to specify an interface or run with root/CAP_NET_RAW")
	}

	r.ifaces = make([]*netInterface, 0, len(allEthers))
	for _, ether := range allEthers {
		handle, err := device.PcapInit(ether.Device)
		if err != nil {
			return nil, err
		}
		freePort, err := freeport.GetFreePort()
		if err != nil {
			handle.Close()
			return nil, err
		}
		gologger.Infof("NIC %s listening on port: %d\n", ether.Device, freePort)
		r.ifaces = append(r.ifaces, &netInterface{
			etherInfo:  ether,
			pcapHandle: handle,
			listenPort: freePort,
		})
	}

	cpuLimit := float64(runtime.NumCPU() * 10000)
	rateLimit := int(math.Min(cpuLimit, float64(opt.Rate)))

	if runtime.GOOS == "darwin" && rateLimit > 50000 {
		gologger.Warningf("Mac platform detected: current rate %d pps may cause buffer issues\n", rateLimit)
		gologger.Warningf("Suggestion: use -b to limit bandwidth (e.g. -b 5m) or lower the rate\n")
		gologger.Warningf("Note: Mac BPF buffer optimized to 2MB, but rate < 50000 pps recommended\n")
	}

	r.rateLimiter = ratelimit.New(rateLimit)
	gologger.Infof("Rate limit: %d pps\n", rateLimit)

	r.domainChan = make(chan string, 50000)
	r.resultChan = make(chan result.Result, 5000)
	r.stopSignal = make(chan struct{})

	r.dnsID = 0x2021 // legion-subdomain
	r.queryTypes = []layers.DNSType{layers.DNSTypeA}
	if opt.QueryAAAA {
		r.queryTypes = append(r.queryTypes, layers.DNSTypeAAAA)
	}
	r.maxRetryCount = opt.Retry
	r.timeoutSeconds = int64(opt.TimeOut)
	r.initialLoadDone = make(chan struct{})
	r.predictLoadDone = make(chan struct{})
	r.startTime = time.Now()
	return r, nil
}

func (r *Runner) selectDNSServer(domain string) string {
	dnsServers := r.options.Resolvers
	specialDNSServers := r.options.SpecialResolvers

	if len(specialDNSServers) > 0 {
		// sort suffixes longest-first so the most specific rule wins deterministically
		suffixes := make([]string, 0, len(specialDNSServers))
		for suffix := range specialDNSServers {
			suffixes = append(suffixes, suffix)
		}
		sort.Slice(suffixes, func(i, j int) bool {
			return len(suffixes[i]) > len(suffixes[j])
		})
		for _, suffix := range suffixes {
			// exact match or proper label boundary (.example.com, not evilexample.com)
			if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
				dnsServers = specialDNSServers[suffix]
				break
			}
		}
	}

	if len(dnsServers) == 0 {
		gologger.Warningf("no DNS resolvers available for domain %s\n", domain)
		return ""
	}
	idx := getRandomIndex() % len(dnsServers)
	return dnsServers[idx]
}

func getRandomIndex() int {
	return int(rand.Int31())
}

func (r *Runner) updateStatusBar() {
	if r.options.ProcessBar != nil {
		queueLength := r.statusDB.Length()
		elapsedSeconds := int(time.Since(r.startTime).Seconds())
		data := &processbar.ProcessData{
			SuccessIndex: r.successCount,
			SendIndex:    r.sendCount,
			AttemptIndex: r.attemptCount,
			QueueLength:  queueLength,
			RecvIndex:    r.receiveCount,
			FaildIndex:   r.failedCount,
			Elapsed:      elapsedSeconds,
		}
		r.options.ProcessBar.WriteData(data)
	}
}

func (r *Runner) loadDomainsFromSource(wg *sync.WaitGroup) {
	defer wg.Done()
	for domain := range r.options.Domain {
		r.domainChan <- domain
	}
	r.initialLoadDone <- struct{}{}
}

func (r *Runner) monitorProgress(ctx context.Context, cancelFunc context.CancelFunc, wg *sync.WaitGroup) {
	var initialLoadCompleted bool = false
	var initialLoadPredict bool = false
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	defer wg.Done()
	for {
		select {
		case <-ticker.C:
			r.updateStatusBar()
			if initialLoadCompleted && initialLoadPredict {
				queueLength := r.statusDB.Length()
				if queueLength <= 0 {
					gologger.Printf("\n")
					gologger.Infof("Scan complete")
					cancelFunc()
					return
				}
			}
		case <-r.initialLoadDone:
			go r.retry(ctx)
			initialLoadCompleted = true
		case <-r.predictLoadDone:
			initialLoadPredict = true
		case <-ctx.Done():
			return
		}
	}
}

func (r *Runner) processPredictedDomains(ctx context.Context, wg *sync.WaitGroup, predictChan chan string) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case domain := <-predictChan:
			r.domainChan <- domain
		}
	}
}

// RunEnumeration runs the full scan pipeline until all domains have been
// sent, retried, and their results collected (or the context is cancelled).
//
// Goroutine topology (multi-NIC A1 pattern):
//
//	loadDomainsFromSource ──► domainChan ──┬──► sendCycleForIface(iface0) ──► pcap(iface0)
//	                                        ├──► sendCycleForIface(iface1) ──► pcap(iface1)
//	                                        └──► ...
//	                                                  │
//	                                             statusDB (sharded 64-bucket)
//	                                                  │
//	                              retry() (200 ms tick) ──► re-inject timed-out
//	                                                  │
//	                          recvChanelForIface(iface0) ──► dnsChanel ──► handleResultWithContext
//	                          recvChanelForIface(iface1) ──► dnsChanel ──► handleResultWithContext
//	                                                             │
//	                                                       resultChan
//	                                                             │
//	                                                     outputter.Output
func (r *Runner) RunEnumeration(ctx context.Context) {
	ctx, cancelFunc := context.WithCancel(ctx)
	defer cancelFunc()

	wg := &sync.WaitGroup{}
	wg.Add(3 + len(r.ifaces)*2)

	for _, iface := range r.ifaces {
		go r.recvChanelForIface(ctx, wg, iface)
		go r.sendCycleForIface(ctx, wg, iface)
	}

	go r.monitorProgress(ctx, cancelFunc, wg)

	predictChan := make(chan string, 1000)
	if r.options.Predict {
		wg.Add(1)
		go r.processPredictedDomains(ctx, wg, predictChan)
	} else {
		r.predictLoadDone <- struct{}{}
	}

	go r.handleResultWithContext(ctx, wg, predictChan)

	go r.loadDomainsFromSource(wg)

	wg.Wait()

	close(predictChan)
	close(r.resultChan)
	close(r.domainChan)
}

func (r *Runner) Close() {
	for _, iface := range r.ifaces {
		if iface.pcapHandle != nil {
			iface.pcapHandle.Close()
		}
	}

	if r.statusDB != nil {
		r.statusDB.Close()
	}

	for _, out := range r.options.Writer {
		err := out.Close()
		if err != nil {
			gologger.Errorf("Failed to close output: %v", err)
		}
	}

	if r.options.ProcessBar != nil {
		r.options.ProcessBar.Close()
	}
}

// SuccessCount returns the number of domains that resolved successfully.
// Call this after Close() to determine whether to use a non-zero exit code.
func (r *Runner) SuccessCount() uint64 {
	return atomic.LoadUint64(&r.successCount)
}
