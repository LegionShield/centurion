# ⚠️ SCARICO DI RESPONSABILITÀ / DISCLAIMER

> **SOLO USO AUTORIZZATO — AUTHORIZED USE ONLY**
>
> CENTURION è uno strumento di ricognizione di rete sviluppato **esclusivamente per scopi legittimi**:
> test di sicurezza su sistemi di cui si è proprietari o per i quali si dispone di **autorizzazione scritta esplicita**, attività di bug bounty nei limiti del programma, audit interni e ricerca accademica.
>
> L'utilizzo di questo strumento su sistemi, domini o infrastrutture **senza il consenso del proprietario** costituisce un reato perseguibile penalmente in Italia ai sensi dell'**art. 615-ter c.p.** (accesso abusivo a sistema informatico) e in molte altre giurisdizioni.
>
> L'autore declina **ogni responsabilità** per usi illeciti, danni diretti o indiretti derivanti dall'impiego di questo software. Utilizzando CENTURION accetti integralmente queste condizioni.
>
> ---
>
> CENTURION is a network reconnaissance tool developed **for legitimate purposes only**:
> security testing on systems you own or have **explicit written authorization** for, bug bounty programs within their defined scope, internal audits, and academic research.
>
> Using this tool against systems, domains, or infrastructure **without the owner's consent** is a criminal offence under Italian law (art. 615-ter c.p.) and equivalent statutes in most jurisdictions.
>
> The author accepts **no liability** for unlawful use or any direct/indirect damage arising from the use of this software. By using CENTURION you fully accept these terms.

---

# Quick Start Guide

## Prerequisites

| Requirement | Notes |
|---|---|
| OS | Linux, macOS, Windows |
| Privileges | **root** or `CAP_NET_RAW` — raw packet capture requires elevated access |
| libpcap / npcap | Linux: `libpcap-dev`; macOS: built-in; Windows: [Npcap](https://npcap.com) |
| Go (build only) | 1.23+ |

---

## Installation

### Download pre-built binary (recommended)

Visit [Releases](https://github.com/LegionShield/legion-subdomain/releases) and download the binary for your platform.

```bash
# Linux x86_64
curl -L https://github.com/LegionShield/legion-subdomain/releases/latest/download/legion-subdomain_linux_amd64 \
     -o /usr/local/bin/legion-subdomain
chmod +x /usr/local/bin/legion-subdomain
```

### Build from source

```bash
git clone https://github.com/LegionShield/legion-subdomain.git
cd legion-subdomain
# Inject version via ldflags (recommended)
go build -ldflags "-X github.com/LegionShield/legion-subdomain/v2/pkg/core/conf.Version=v2.x.y" \
    -o legion-subdomain ./cmd/legion-subdomain
```

---

## Your first scan

### 1 — Check available network interfaces

```bash
sudo ./legion-subdomain device
```

### 2 — Test maximum packet rate

```bash
sudo ./legion-subdomain test
```

### 3 — Enumerate subdomains (built-in wordlist)

```bash
sudo ./legion-subdomain enum -d example.com
```

Sample output:

```
www.example.com => 93.184.216.34
mail.example.com => 93.184.216.50
api.example.com => 93.184.216.51
```

### 4 — Verify a domain list

```bash
sudo ./legion-subdomain verify -f domains.txt -o output.txt
```

---

## Common workflows

### Pipe to httpx for HTTP probing

```bash
sudo ./legion-subdomain enum -d example.com --only-domain --silent | httpx -silent
```

### Save as JSONL for streaming processing

```bash
sudo ./legion-subdomain enum -d example.com --format jsonl -o result.jsonl
```

### Batch enumeration of multiple root domains

```bash
sudo ./legion-subdomain enum --domain-list roots.txt -b 10m --format jsonl -o all.jsonl
```

### Predict + advanced wildcard filter

```bash
sudo ./legion-subdomain enum -d example.com --predict --wildcard-filter advanced -o result.txt
```

### Multi-NIC parallel sending

```bash
sudo ./legion-subdomain enum -d example.com --interface eth0 --interface eth1 -b 20m
```

---

## Platform notes

### Linux

```bash
# Grant CAP_NET_RAW instead of running as root (optional)
sudo setcap cap_net_raw+ep ./legion-subdomain

./legion-subdomain enum -d example.com
```

### macOS

macOS uses BPF with smaller default buffers. Keep bandwidth conservative:

```bash
sudo ./legion-subdomain enum -d example.com -b 5m
```

### WSL / WSL2

```bash
./legion-subdomain enum -d example.com --interface eth0
```

### Windows

1. Install [Npcap](https://npcap.com/) (WinPcap is not supported)
2. Run as Administrator

```bat
.\legion-subdomain.exe enum -d example.com
```

---

## Next steps

- [API Reference](./api.md)
- [Best Practices](./best-practices.md)
- [FAQ](./faq.md)
- [SDK README](../sdk/README.md)
