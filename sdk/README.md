# LΞGION Go SDK

Simple, powerful Go SDK for integrating legion-subdomain subdomain scanning into your applications.

## 📦 Installation

```bash
go get github.com/LegionShield/legion-subdomain/v2/sdk
```

> **Note:** Requires root / `CAP_NET_RAW` privilege (raw packet capture via pcap).

## 🚀 Quick Start

### Basic Enumeration (blocking)

```go
package main

import (
    "errors"
    "fmt"
    "log"

    "github.com/LegionShield/legion-subdomain/v2/sdk"
)

func main() {
    scanner := sdk.NewScanner(sdk.DefaultConfig)

    results, err := scanner.Enum("example.com")
    if err != nil {
        switch {
        case errors.Is(err, sdk.ErrPermissionDenied):
            log.Fatal("run with sudo or grant CAP_NET_RAW")
        case errors.Is(err, sdk.ErrDeviceNotFound):
            log.Fatal("network device not found")
        default:
            log.Fatal(err)
        }
    }

    for _, r := range results {
        fmt.Printf("%s [%s] %v\n", r.Domain, r.Type, r.Records)
    }
}
```

### Streaming (real-time callback)

```go
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

err := scanner.EnumStream(ctx, "example.com", func(r sdk.Result) {
    fmt.Printf("%s => %v\n", r.Domain, r.Records)
})
```

### Verify Mode

```go
domains := []string{"www.example.com", "mail.example.com", "api.example.com"}

results, err := scanner.Verify(domains)
for _, r := range results {
    fmt.Printf("✓ %s [%s] %v\n", r.Domain, r.Type, r.Records)
}

// Streaming verify
err = scanner.VerifyStream(ctx, domains, func(r sdk.Result) {
    fmt.Printf("%s is alive\n", r.Domain)
})
```

## ⚙️ Configuration

```go
scanner := sdk.NewScanner(&sdk.Config{
    // Bandwidth cap, e.g. "5m", "10m", "100m" (default: "5m")
    Bandwidth: "10m",

    // Retry count per domain; -1 = infinite (default: 3)
    Retry: 5,

    // DNS resolvers; nil = built-in defaults
    Resolvers: []string{"8.8.8.8", "1.1.1.1"},

    // Single network interface; "" = auto-detect
    Device: "",

    // Multiple interfaces for parallel sending (takes precedence over Device)
    Devices: []string{"eth0", "eth1"},

    // Wordlist file for Enum; "" = built-in list
    Dictionary: "/path/to/subdomains.txt",

    // Enable AI-powered subdomain prediction
    Predict: true,

    // Wildcard filter: "none" (default), "basic", "advanced"
    WildcardFilter: "advanced",

    // Suppress progress output
    Silent: true,

    // Inject custom output sinks (implement outputter.Output)
    ExtraWriters: []outputter.Output{myWriter},
})
```

### DefaultConfig

```go
var DefaultConfig = &sdk.Config{
    Bandwidth:      "5m",
    Retry:          3,
    WildcardFilter: "none",
}
```

> **Timeout is not configurable.** The scanner uses a dynamic RTT-based timeout
> (RFC 6298 EWMA, α=0.125, β=0.25) bounded between 1 s and 10 s.
> This eliminates the need for manual tuning.

## 📐 API Reference

### Types

```go
// Config holds scanner settings.
type Config struct {
    Bandwidth      string
    Retry          int
    Resolvers      []string
    Device         string             // single NIC (backward-compat)
    Devices        []string           // multi-NIC parallel sending
    Dictionary     string
    Predict        bool
    WildcardFilter string
    Silent         bool
    ExtraWriters   []outputter.Output // custom sinks
}

// Result is a single resolved subdomain.
type Result struct {
    Domain  string   // e.g. "www.example.com"
    Type    string   // "A", "CNAME", "NS", "PTR", "TXT", "AAAA"
    Records []string // resolved values
}
```

### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `NewScanner` | `(config *Config) *Scanner` | Create scanner; nil uses DefaultConfig |
| `Enum` | `(domain string) ([]Result, error)` | Blocking subdomain enumeration |
| `EnumWithContext` | `(ctx, domain) ([]Result, error)` | Enum with context (timeout/cancel) |
| `EnumStream` | `(ctx, domain, func(Result)) error` | Streaming enumeration via callback |
| `Verify` | `(domains []string) ([]Result, error)` | Blocking domain verification |
| `VerifyWithContext` | `(ctx, domains) ([]Result, error)` | Verify with context |
| `VerifyStream` | `(ctx, domains, func(Result)) error` | Streaming verification via callback |

### Sentinel Errors

```go
sdk.ErrPermissionDenied  // CAP_NET_RAW / root required
sdk.ErrDeviceNotFound    // no matching network interface
sdk.ErrDeviceNotActive   // interface is down
sdk.ErrPcapInit          // pcap handle initialisation failed
sdk.ErrDomainChanNil     // internal: nil domain channel
```

## 🔌 Custom Output Sink (ExtraWriters)

```go
import "github.com/LegionShield/legion-subdomain/v2/pkg/runner/result"

type MyWriter struct{}

func (w *MyWriter) WriteDomainResult(r result.Result) error {
    fmt.Printf("custom: %s => %v\n", r.Subdomain, r.Answers)
    return nil
}
func (w *MyWriter) Close() error { return nil }

scanner := sdk.NewScanner(&sdk.Config{
    Bandwidth:    "5m",
    ExtraWriters: []outputter.Output{&MyWriter{}},
})
```

## 🌐 Multi-NIC Parallel Sending

```go
scanner := sdk.NewScanner(&sdk.Config{
    Bandwidth: "20m",
    Devices:   []string{"eth0", "eth1"}, // two NICs, shared domain channel
})
```

Each interface spawns an independent `sendCycleForIface` goroutine competing
on the same `domainChan`, naturally load-balancing without extra scheduling logic.

## 📋 Examples

See [`examples/simple/main.go`](./examples/simple/main.go) and
[`examples/advanced/main.go`](./examples/advanced/main.go).

```bash
# Run simple example (requires root)
cd sdk/examples/simple
sudo go run main.go

# Run advanced example
cd sdk/examples/advanced
sudo go run main.go
```
