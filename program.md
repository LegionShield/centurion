# LΞGION — Agent Program

> This file is the project context and task guide for AI Agents. The agent should read this file in full before starting any work.
> Similar to autoresearch's `program.md`, this defines the project's "research organization logic".

---

## Project Overview

**LΞGION** is a stateless subdomain enumeration tool. The core idea comes from Masscan: bypass the kernel network stack and send/receive raw DNS packets directly at the NIC level, with a lightweight built-in state table for retransmission, achieving extremely fast scanning.

Current version **v2.5**, module path `github.com/LegionShield/legion-subdomain/v2`, requires Go 1.23+.

---

## Code Map (required reading)

```
cmd/legion-subdomain/          CLI entry point, 4 subcommands: enum / verify / test / device
pkg/
  options/options.go     core config struct Options (control panel for all features)
  runner/runner.go       main scan loop, RunEnumeration() starts 5 concurrent goroutines
  runner/send.go         send: template cache + batch send + exponential backoff retry
  runner/recv.go         recv: BPF filter + CPU*2 parallel parse + CPU*2 parallel process
  runner/statusdb/db.go  64-shard lock state table, tracks send status and retry count
  runner/mempool.go      global sync.Pool, reuses DNS structs to reduce GC
  runner/result.go       result processing + predict trigger
  runner/wildcard.go     wildcard DNS filtering logic
  runner/outputter/      Output interface + txt/json/csv/jsonl/screen implementations
  device/                NIC initialization (pcap), builds EtherTable
  sdk/sdk.go             Go SDK wrapper (Enum / Verify / *WithContext)
  ns/ns.go               NS record lookup (--ns mode helper)
internal/
  predict/generator.go   prediction generator based on regular.cfg + regular.dict
  assets/data/           built-in wordlists subdomain.txt / subnext.txt
docs/
  OUTPUT_FORMATS.md      complete output format documentation
```

---

## Core Data Flow

```
Domain input (chan string)
    │
    ▼
loadDomainsFromSource  ──►  domainChan
                                │
                    ┌───────────┘
                    ▼
            sendCycleWithContext
             (template cache + batch send)
                    │
                    ▼
             statusdb register {Domain, Dns, Time, Retry}
                    │
      ┌─────────────┴──────────────────────────────────┐
      ▼                                                 ▼
 recvChan → packetChan → dnsChan → resultChan     monitorProgress
                                       │             + retry()
                                       ▼
                              handleResultWithContext
                                       │
                          ┌────────────┴──────────────┐
                          ▼                            ▼
                   Output.WriteDomainResult()    predict() → predictChan
```

---

## Key Metrics (use these to measure whether a change is effective)

| Metric | Current Baseline | Target Direction |
|--------|-----------------|-----------------|
| **Detection Rate** | 100k domains ~30s (5M bandwidth, 4 cores) | continue improving throughput at same bandwidth |
| **Miss Rate** | nearly identical to massdns results | reduce misses caused by timeout |
| **False Positive Rate** | near 0 after wildcard filtering | advanced mode covers more wildcard scenarios |
| **Memory Usage** | low memory even at millions of domains | avoid introducing new large heap allocations |
| **SDK Usability** | NewScanner(config).Enum(domain) 3-line integration | any change must not break SDK interface compatibility |

After each modification, run the following commands to verify no regression:

```bash
# unit tests (no NIC required)
go test ./...

# integration tests (require NIC privileges)
sudo go test ./test/ -v -run Integration

# send rate benchmark
sudo ./legion-subdomain test
```

---

## Current Priority Tasks (Roadmap)

Listed from highest to lowest priority. The agent should process in order, focusing on one task at a time.

**Roadmap maintenance rules (agent may edit this file directly)**:
- Complete a task → change `[ ]` to `[x]`, record result in `agent-log.md`
- Discover a new issue or improvement → append it under the appropriate priority level, noting the source
- Determine a task is no longer necessary → change `[ ]` to `[~]` and add a note in parentheses explaining why
- **Items requiring user decisions are not held here** — write them to the `[PENDING DECISION]` block in `agent-log.md` for the user to handle after reviewing the log

### P0 — Detection Efficiency

- [x] **Dynamic timeout adaptation**: RTT EWMA sliding average, internal upper bound fixed at 10s, always enabled
- [x] **Receive-side backpressure control**: packetChan dual-watermark monitoring (80% trigger / 50% recovery), send side sleeps 5ms on backpressure
- [x] **Batch retransmission merge**: group by DNS server for batch send(), remove channel relay layer, reuse slice/map to reduce GC

### P1 — Developer Integration

- [x] **Streaming result callback**: EnumStream/VerifyStream, streamCollector real-time callback, unbuffered
- [x] **Custom Output integration**: Config.ExtraWriters []outputter.Output, appended after internal writers
- [x] **Typed errors**: pkg/core/errors package, ErrPermissionDenied/ErrDeviceNotFound/ErrDeviceNotActive/ErrPcapInit/ErrDomainChanNil, re-exported from sdk
- [x] **dev.md rewrite**: architecture diagram, goroutine table, SDK/Options field table, error handling, backpressure docs, build commands

### P1.5 — Toolchain Integration Compatibility Audit

> Reference the "Tool Integration Compatibility Matrix" section and verify each integration scenario is actually functional.

- [x] **httpx pipeline**: remove \r prefix from screen.go, --od --silent outputs clean domain\n
- [x] **JSONL downstream compatibility**: bufio replaces Sync(), parseAnswers() shared parsing, stable field names domain/type/records
- [x] **Exit code semantics**: os.Exit(1) when SuccessCount()==0, documented in faq.md

### P2 — Documentation

- [x] **docs/quickstart.md**: installation, first scan, common flags table, output formats, troubleshooting
- [x] **docs/api.md**: complete SDK API reference, Config/Result/Scanner methods, error handling, custom sink
- [x] **docs/best-practices.md**: bandwidth selection table, DNS resolver guide, wildcard DNS, pipeline output, large-scale scanning
- [x] **docs/faq.md**: sudo/CAP_NET_RAW, NIC errors, macOS BPF, WSL2, wildcard DNS, httpx garbled output, exit codes
- [x] **inline comments**: RunEnumeration goroutine topology diagram, sendCycleWithContext batch+backpressure notes

### P3 — Engineering Health

- [x] **`simple` binary missing**: confirmed as build artifact, added to .gitignore, updated examples to fix API
- [x] **CI matrix**: ci.yml five-platform matrix (Linux amd64/arm64, macOS amd64/arm64, Windows amd64) + lint job
- [x] **Version automation**: Version changed to var, build.yml/build.sh inject git tag via ldflags

---

## Modification Constraints

1. **Do not rename existing fields in `Options` in `pkg/options/options.go`**: downstream user code depends on this struct; field renames are breaking changes
2. **Do not modify existing field and method signatures in `Config`, `Scanner`, `Result` in `pkg/sdk/sdk.go`**: public SDK API, must remain backward compatible
3. **The `Output` interface may only be extended, not modified**: existing `WriteDomainResult` and `Close` signatures are immutable
4. **All platform files (`*_darwin.go`, `*_linux.go`, `*_windows.go`) must be updated in sync**
5. **Go rules**: no `++`/`--`, strings use backticks or double quotes (Go convention), interface definitions only in `pkg/`

---

## Getting Started (Agent first run)

```bash
# 1. check project status
git status
go build ./...

# 2. run existing tests to confirm baseline passes
go test ./pkg/... -v

# 3. check for missing docs (files referenced in README but not yet created)
ls docs/

# 4. pick the highest-priority incomplete Roadmap item, create a branch, start implementing
# focus on one task at a time; run go test ./... after completion to confirm no regression
```

---

## Test Standards (internal network environment)

> **Current environment is internal — do not send large batches of external DNS requests.**

After implementing each feature, the agent must run the following tests to verify correct parameter behavior, no crashes, and no obvious bugs:

```bash
# compile check (no privileges needed, fastest check)
go build ./...

# unit tests (no NIC needed, all pass is the admission criteria)
go test ./... -timeout 30s

# local lightweight smoke tests (only a few domains, no large-scale scanning)
# build binary
go build -o legion-subdomain_dev ./cmd/legion-subdomain

# verify mode: verify 1 known domain, check -d / -o / --oy / --silent / --np flags
sudo ./legion-subdomain_dev verify -d www.baidu.com --timeout 5 --retry 2 -b 1m --np
sudo ./legion-subdomain_dev verify -d www.baidu.com --oy jsonl --silent
sudo ./legion-subdomain_dev verify -d www.baidu.com -o /tmp/ksub_test.txt && cat /tmp/ksub_test.txt

# enum mode: enumerate 1 domain with a small wordlist of no more than 10 lines, verify basic flow doesn't crash
sudo ./legion-subdomain_dev enum -d baidu.com --timeout 5 --retry 1 -b 1m --np -f subdomain.dic

# test mode: test local NIC send rate, no external traffic
sudo ./legion-subdomain_dev test

# device mode: list available NICs
sudo ./legion-subdomain_dev device
```

**Test checklist**:
- Each CLI flag covered at least once, confirm no panic or unexpected output
- Output file format is correct (txt one entry per line, jsonl one valid JSON per line)
- `--silent` mode produces no extra output, `--np` mode produces no domain printing
- Delete temp files after testing: `rm -f /tmp/ksub_test* legion-subdomain_dev`

---

## Branch Management

> **main branch is read-only — all feature changes go on separate branches.**

For each Roadmap task, follow this workflow:

```bash
# 1. create a feature branch from main, naming format: feature/<short-description>
git checkout main
git checkout -b feature/dynamic-timeout      # P0 example
git checkout -b feature/stream-sdk           # P1 example
git checkout -b docs/quickstart              # P2 example
git checkout -b fix/simple-binary            # P3 example

# 2. implement the feature, commit granularity: one commit per logical unit
git add .
git commit -m "feat(runner): add RTT sliding window for dynamic timeout"

# 3. run full tests on the branch after completing the feature
go test ./... -timeout 30s

# 4. record branch conclusions in the run log (see below), do not merge to main
# main branch merges are decided manually
```

**Branch naming prefix conventions**:

| Prefix | Purpose |
|--------|---------|
| `feature/` | new feature implementation (Roadmap P0/P1) |
| `docs/` | documentation additions (Roadmap P2) |
| `fix/` | bug fixes (Roadmap P3 or issues found in smoke testing) |
| `refactor/` | refactoring (no external behavior change) |
| `exp/` | experimental changes (may not be kept) |

---

## Run Log Standards

After completing each task, the agent must append a record to `agent-log.md` in the project root. Create the file if it doesn't exist.

**Record format**:

```markdown
## [YYYY-MM-DD] <branch-name> — <task summary>

**Goal**: which Roadmap item this corresponds to
**Changed files**: list of modified files
**Test results**:
- go test ./... → PASS / FAIL (include error summary)
- smoke tests: list commands executed and output summary
**Conclusion**: whether the change is effective, any new issues introduced, next step suggestions

<!-- if there are items requiring user decisions, append the following block; omit if none -->
### [PENDING DECISION]
```

**Notes**:
- The `[PENDING DECISION]` block is the agent's only communication channel with the user. The agent does not stop work to wait for a reply — it records the item and continues to the next task.
- When the user reviews `agent-log.md`, searching `[PENDING DECISION]` finds all pending items. Check `[x]` or reply below the item, and the agent reads and acts on it next run.
- Typical pending decision scenarios: accepting a breaking API change, introducing a new external dependency, whether a feature is worth implementing, a potential security or performance risk requiring human confirmation.

**Example**:

```markdown
## [2026-03-17] feature/dynamic-timeout — Dynamic timeout adaptation

**Goal**: P0 dynamic timeout adaptation
**Changed files**: pkg/runner/runner.go, pkg/runner/send.go, pkg/options/options.go
**Test results**:
- go test ./... → PASS
- smoke test: `sudo ./legion-subdomain_dev verify -d www.baidu.com --timeout 5 --retry 2`
  output: `www.baidu.com => 110.242.68.66`, elapsed ~2s, normal
**Conclusion**: RTT sliding average calculation works correctly, timeout converges early in low-latency scenarios, no misses.
  Recommend reusing RTT data in the P0 backpressure control task.

### [PENDING DECISION]
      If the new version should enable dynamic timeout by default, the default value must change to true — this is a behavior change, please confirm.
      Option A: default false, user enables explicitly with --dynamic-timeout (conservative)
      Option B: default true, --no-dynamic-timeout can disable (aggressive, affects existing scripts)
```

---

## Output Format Quick Reference

| Format | Write timing | Use case |
|--------|-------------|---------|
| `txt` | real-time (per result) | manual review, pipeline grep |
| `json` | once after completion | offline analysis, scripting |
| `csv` | once after completion | Excel/database import |
| `jsonl` | real-time streaming | pipeline chains (httpx/nuclei), monitoring systems |
| screen | real-time colored (stdout) | interactive terminal |

---

## Tool Integration Compatibility Matrix

> When auditing P1.5 tasks, use this as a checklist. Each entry gives expected behavior, verification command, and current status.

### ProjectDiscovery Toolchain

| Tool | Integration method | Expected behavior | Key flags | Current status |
|------|--------------------|-------------------|-----------|---------------|
| **httpx** | stdout pipe | one domain per line, httpx probes automatically | `--od --silent` | pending verification |
| **nuclei** | stdout pipe or temp file | domains as targets, templates scan normally | `--od` + nuclei `-l /dev/stdin` | pending verification |
| **naabu** | stdout pipe | domain list as port scan input | `--od` + naabu `-iL -` | pending verification |
| **dnsx** | stdout pipe | legion-subdomain initial filter → dnsx multi-record deep query | `--od --silent` + dnsx `-a -cname` | pending verification |
| **subfinder** | subfinder → legion-subdomain stdin | subfinder discovers domains → legion-subdomain verify confirms alive | legion-subdomain `v --stdin` | pending verification |
| **alterx** | alterx → legion-subdomain stdin | permutation generation → batch verification, large input no packet loss | legion-subdomain `v --stdin -b 10m` | pending verification |
| **katana** | legion-subdomain → katana | subdomain list as crawl seeds | `--od` + katana `-list -` | pending verification |
| **chaos** | chaos → legion-subdomain verify | chaos dataset import for alive verification | legion-subdomain `v -f chaos_output.txt` | pending verification |

### Verification commands reference (use small wordlist internally, no large-batch requests)

```bash
# 1. httpx integration: enumerate → HTTP probe
sudo ./legion-subdomain_dev enum -d baidu.com -f subdomain.dic --od --silent | httpx -silent -title

# 2. dnsx integration: legion-subdomain initial filter → dnsx multi-type query
sudo ./legion-subdomain_dev verify -d www.baidu.com --od --silent | dnsx -a -cname -resp

# 3. naabu integration: enumerate → port scan
sudo ./legion-subdomain_dev enum -d baidu.com -f subdomain.dic --od --silent | naabu -silent -p 80,443

# 4. subfinder → legion-subdomain: two-phase discovery
subfinder -d baidu.com -silent | sudo ./legion-subdomain_dev verify --stdin --silent --od

# 5. alterx → legion-subdomain: permutation verification
echo 'www.baidu.com' | alterx -silent | sudo ./legion-subdomain_dev verify --stdin --np

# 6. JSONL stream filter then pass to httpx
sudo ./legion-subdomain_dev enum -d baidu.com -f subdomain.dic --oy jsonl --silent \
  | jq -r 'select(.type=="A") | .domain' \
  | httpx -silent

# 7. nuclei vulnerability scan
sudo ./legion-subdomain_dev enum -d baidu.com -f subdomain.dic --od --silent \
  | nuclei -l /dev/stdin -t technologies/ -silent
```

### Integration verification checklist

- **`--od` output must be pure single-column domains** — no `=>` arrows, no IPs, no blank lines; downstream tools will fail to parse otherwise
- **`--silent` must suppress progress bar and banner** — only result lines, otherwise pipeline data is polluted
- **`--stdin` must handle EOF correctly** — after subfinder/alterx finishes, legion-subdomain should exit normally and not hang
- **Exit codes**: results present exits 0, no results exits non-0, so shell `&&` chains short-circuit correctly
- **JSONL field names** must be stable (`domain`, `type`, `records`, `timestamp`), jq scripts depend on this convention

---

## Integration Quick Reference

```bash
# full recon chain: subdomain enumeration → HTTP probe → vulnerability scan
sudo ./legion-subdomain enum -d example.com -f subdomain.dic --od --silent \
  | httpx -silent \
  | nuclei -l /dev/stdin -silent

# two-phase discovery: subfinder broad scan → legion-subdomain alive filter
subfinder -d example.com -silent \
  | sudo ./legion-subdomain verify --stdin --od --silent

# streaming filter (A records only) then port scan
sudo ./legion-subdomain enum -d example.com --oy jsonl --silent \
  | jq -r 'select(.type=="A") | .domain' \
  | naabu -silent -p 80,443,8080,8443

# Go SDK minimal integration
scanner := sdk.NewScanner(sdk.DefaultConfig)
results, err := scanner.Enum('example.com')
```

---

*`program.md` is maintained jointly by the agent and the user: Roadmap entries are updated autonomously by the agent; items requiring human judgment are written to the `[PENDING DECISION]` block in `agent-log.md`.*
