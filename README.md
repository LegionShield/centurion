# CΞNTURIΩN by LΞGION — Subdomain Enumeration Tool

[![License](https://img.shields.io/github/license/LegionShield/legion-subdomain)](https://github.com/LegionShield/legion-subdomain/blob/main/LICENSE)

centurion by legion — enumerazione subdomain *stateless*:
velocità altissima, consumo di memoria bassissimo. Lavora direttamente sulla scheda di rete
con raw socket (bypassa lo stack del kernel) e un meccanismo di ritrasmissione affidabile.

Supporta **Windows**, **Linux** e **macOS**.

Autore: **LΞGION** ([@LegionShield](https://github.com/LegionShield))

> **Credito obbligatorio**  
> Questo progetto è di **LΞGION / LegionShield**.  
> Qualsiasi fork, copia o redistribuzione deve mantenere il nome **CΞNTURIΩN** e il credito a LΞGION.  
> Rimuovere il branding o prendersi il merito è vietato dalla licenza.

## Tools by LΞGION

| Tool | Tipo | Repo |
|------|------|------|
| **CΞNTURIΩN** | Subdomain enumeration (raw socket) | [LegionShield/centurion](https://github.com/LegionShield/centurion) |
| **CΞNSUS** | Advanced SQL Injection Cheatsheet | [LegionShield/census](https://github.com/LegionShield/census) |

---

## Perché CΞNTURIΩN

- **Velocità** — ~7× massdns, ~10× dnsx sullo stesso dizionario
- **Poca RAM** — object pool + memory pool globali
- **Timeout dinamico** — EWMA su RTT reale (RFC 6298), niente tuning a mano
- **Multi-NIC** — più schede di rete in parallelo con `--interface`
- **SDK streaming** — API `EnumStream` / `VerifyStream` per elaborare i risultati in tempo reale
- **Cross-platform** — Windows / Linux / macOS

### Confronto prestazioni

**Ambiente:** Linux x86-64, 4 core, 8 GB RAM, link 5 Mbit/s, resolver pubblici (8.8.8.8, 1.1.1.1 × 4), banda impostata a `-b 5m`, dizionario da 100k voci, dominio reale con ~1400 subdomini attivi.  
**Metrica:** tempo wall-clock da avvio a ultimo risultato; "Trovati" = risposte DNS con almeno un record A ricevuto dal receiver pcap, non il contatore di pacchetti inviati.  
**Nota:** i numeri dipendono fortemente da latenza dei resolver, perdita pacchetti e banda disponibile. Su reti con RTT > 20ms o perdita > 1% i tempi divergono. Riprodurre con `--silent --format jsonl -o out.jsonl` e contare le righe di output come misura indipendente.

| Tool | Metodo | Tempo | Trovati |
|------|--------|-------|---------|
| **CΞNTURIΩN** | pcap raw socket | **~30 sec** | 1397 |
| massdns | pcap/socket | ~3 min 29 sec | 1396 |
| dnsx | socket | ~5 min 26 sec | 1396 |

---

## Installazione

### Dipendenze

- **Windows:** installa [Npcap](https://npcap.com/)
- **Linux:** di solito già ok; se serve `libpcap-dev`
- **macOS:** libpcap di sistema, nessuna installazione extra

### Build da sorgente

```bash
git clone https://github.com/LegionShield/legion-subdomain.git
cd legion-subdomain
go build -ldflags "-X github.com/LegionShield/legion-subdomain/v2/pkg/core/conf.Version=v2.x.y" \
    -o centurion ./cmd/legion-subdomain
```

Oppure:

```bash
go install github.com/LegionShield/legion-subdomain/v2/cmd/legion-subdomain@latest
```

> Serve root / privilegi `CAP_NET_RAW` per catturare i pacchetti raw.

---

## Uso

```
centurion [global options] <command> [command options]
```

| Comando | Alias | Cosa fa |
|---------|-------|---------|
| `enum` | `e` | Brute-force subdomain con dizionario |
| `verify` | `v` | Verifica se una lista di domini risolve |
| `test` | | Test velocità massima di invio della NIC |
| `device` | | Elenca le interfacce di rete disponibili |
| `help` | `h` | Aiuto |

Flag globali: `--help` / `-h`, `--version` / `-v`

### Modalità verify

| Flag | Descrizione |
|------|-------------|
| `--domain`, `-d` | Dominio target (ripetibile) |
| `--filename`, `-f` | File con lista domini |
| `--stdin` | Legge da stdin |
| `--bandwidth`, `-b` | Limite banda (es. `5m`, `10m`, default `3m`) |
| `--resolvers`, `-r` | Resolver DNS custom |
| `--output`, `-o` | File di output |
| `--format` | `txt` (default), `json`, `csv`, `jsonl` |
| `--silent`, `-s` | Niente banner/log, solo risultati |
| `--only-domain`, `--od` | Solo nomi dominio, senza IP/record |
| `--retry` | Tentativi (`-1` = infinito, default `3`) |
| `--timeout` | Timeout query DNS in secondi (default `6`) |
| `--interface`, `-e` | Interfaccia di rete (ripetibile) |
| `--wildcard-filter` | `none` / `basic` / `advanced` |
| `--predict` | Predizione subdomain correlati |
| `--quiet`, `-q` | Nessun output a schermo (solo file) |
| `--color`, `-c` | Output colorato |

```bash
./centurion v -d www.example.com -d mail.example.com
./centurion v -f domains.txt -o output.txt
cat domains.txt | ./centurion v --stdin -b 10m -s --od | httpx -silent
./centurion v -f domains.txt --wildcard-filter advanced --format jsonl -o output.jsonl
./centurion v -f domains.txt --interface eth0 --interface eth1
```

### Modalità enum

| Flag | Descrizione |
|------|-------------|
| `--filename`, `-f` | Dizionario (se omesso usa quello integrato) |
| `--domain-list`, `--ds` | File con root domain da enumerare in batch |
| `--use-ns-records` | Usa i NS del dominio come resolver aggiuntivi |
| `--aaaa` | Invia anche query AAAA (IPv6); di default solo query A. Il trasporto DNS rimane IPv4 — il resolver deve avere un indirizzo IPv4 raggiungibile. |

```bash
./centurion e -d example.com
./centurion e -d example.com -f subdomains.txt -o result.txt
./centurion e -d example.com --predict --wildcard-filter advanced
./centurion e --domain-list roots.txt -b 10m --format jsonl -o result.jsonl
./centurion e -d example.com -s --od | httpx -silent
```

### test / device

```bash
./centurion test
./centurion device
```

---

## Funzionalità

### Timeout dinamico
EWMA su RTT reale (RFC 6298), range 1s–10s. Niente tuning a mano.

### Multi-NIC
```bash
./centurion e -d example.com --interface eth0 --interface eth1 -b 20m
```

### Prediction (`--predict`)
Genera pattern correlati dai subdomain trovati.

### Filtro wildcard
- `none` — nessuno (default)
- `basic` — toglie IP wildcard evidenti
- `advanced` — rilevamento multi-dimensionale

### Formati di output

| Formato | Descrizione | Ideale per |
|---------|-------------|------------|
| `txt` | `domain => record`, real-time | lettura umana |
| `json` | JSON completo a fine run | parsing |
| `csv` | tabella CSV a fine run | analisi |
| `jsonl` | una riga JSON per risultato | pipe / tool chain |

---

## Esempi di integrazione

```bash
./centurion e -d example.com -s --od | httpx -silent
./centurion e -d example.com -s --od | nuclei -l /dev/stdin
./centurion e -d example.com --format jsonl | jq -r 'select(.type=="A") | .domain'
./centurion e --domain-list roots.txt -s --od | sort -u > all_subs.txt
```

---

## Note piattaforma

**macOS** — buffer BPF piccolo: tieni banda bassa (`-b 1m` / `2m`).  
**Windows** — serve Npcap (modalità WinPcap-compatible).  
**Linux** — `sudo setcap cap_net_raw,cap_net_admin=eip ./centurion` oppure root.

---

## Licenza

MIT — Copyright (c) 2026 LΞGION / LegionShield  
Tool: **CΞNTURIΩN** · Autore: **LΞGION**
