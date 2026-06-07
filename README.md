<div align="center">

```
██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗
██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝
██████╔╝██████╔╝███████╗██║     ██║   ██║██║   ██║   ██║
██╔══██╗██╔══██╗╚════██║██║     ██║   ██║██║   ██║   ██║
██████╔╝██████╔╝███████║╚██████╗╚██████╔╝╚██████╔╝   ██║
╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝
```

**bbscout** — bug bounty recon & AI triage pipeline

![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)
![License](https://img.shields.io/badge/license-MIT-green?style=flat)
![Status](https://img.shields.io/badge/status-active-brightgreen?style=flat)

</div>

---

A modular bug bounty automation CLI written in Go. Chains industry-standard recon tools into a single pipeline, then uses local AI (Ollama) to triage captured HTTP traffic and surface actionable findings.

## Pipeline

```
recon → crawl → scan → [manual exploration via Caido] → triage → report
```

| Stage | What it does | Tools |
|---|---|---|
| **recon** | Subdomain discovery, DNS resolution, port scan, live host detection | subfinder, assetfinder, crt.sh, dnsx, naabu, httpx, gowitness |
| **crawl** | URL discovery, JS endpoint extraction, historical URL collection | katana, gau, waybackurls |
| **scan** | Template-based vulnerability scanning, subdomain takeover detection | nuclei, subzy |
| **triage** | AI-powered HTTP traffic analysis with heuristic pre-filtering | Ollama (local LLM) |

## Installation

### Prerequisites

Install the required tools:

```bash
# ProjectDiscovery tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# Other tools
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/sensepost/gowitness@latest
go install -v github.com/PentestPad/subzy@latest

# Update nuclei templates
nuclei -update-templates
```

Install Ollama for AI triage:
```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen3:latest
```

### Build bbscout

```bash
git clone https://github.com/Cypher-CP0/bbscout
cd bbscout
go build -o bbscout .
```

### Configuration

Edit `config/config.yaml`:

```yaml
output_dir: "./output"

tools:
  subfinder:   "subfinder"
  assetfinder: "assetfinder"
  dnsx:        "dnsx"
  naabu:       "naabu"
  httpx:       "httpx"
  gowitness:   "gowitness"
  katana:      "katana"
  gau:         "gau"
  waybackurls: "waybackurls"
  nuclei:      "/home/user/go/bin/nuclei"  # use full path if not in PATH
  subzy:       "subzy"

nuclei:
  templates: "~/.local/nuclei-templates"
  severity:  "medium,high,critical"

ollama:
  host:  "http://localhost:11434"
  model: "qwen3:latest"
```

## Usage

### Recon

Discover subdomains, resolve DNS, scan ports, probe live hosts:

```bash
# full recon pipeline
./bbscout recon --target example.com

# skip screenshots (faster)
./bbscout recon --target example.com --skip-screenshots

# skip port scanning
./bbscout recon --target example.com --skip-ports

# custom ports
./bbscout recon --target example.com --ports 80,443,8080,8443
```

**Output:**
```
output/example.com/
├── subdomains-all.txt     — all discovered subdomains
├── resolved.txt           — DNS-resolved hosts
├── resolved-hosts.txt     — plain hostnames
├── live.txt               — live HTTP services
├── httpx.json             — full httpx output with tech fingerprinting
└── screenshots/           — gowitness screenshots
```

### Crawl

Discover URLs, JS endpoints, and historical paths:

```bash
# full crawl (katana + gau + waybackurls)
./bbscout crawl --target example.com

# custom depth
./bbscout crawl --target example.com --depth 5

# skip historical tools (faster)
./bbscout crawl --target example.com --skip-wayback --skip-gau
```

**Output:**
```
output/example.com/
├── katana-urls.txt        — active JS crawl findings
├── gau-urls.txt           — historical URLs (Wayback, CommonCrawl, OTX)
├── wayback-urls.txt       — Wayback Machine URLs
├── urls-all.txt           — merged + deduplicated
└── urls-interesting.txt   — static assets filtered out
```

### Scan

Run nuclei templates and check for subdomain takeovers:

```bash
# full scan against live hosts
./bbscout scan --target example.com

# high/critical only (faster)
./bbscout scan --target example.com --severity high,critical

# scan crawled URLs instead of live hosts (deeper surface)
./bbscout scan --target example.com --urls

# skip subdomain takeover check
./bbscout scan --target example.com --skip-subzy

# custom rate limit
./bbscout scan --target example.com --rate-limit 50
```

**Output:**
```
output/example.com/
├── nuclei-findings.json   — nuclei vulnerability findings
└── subzy-findings.txt     — subdomain takeover candidates
```

### Triage

AI-powered analysis of HTTP traffic captured via Caido or Burp Suite:

```bash
# basic triage
./bbscout triage --input export.json --target example.com

# higher concurrency (faster, needs more RAM)
./bbscout triage --input export.json --target example.com --concurrency 8

# lower scoring threshold (more entries reach Ollama)
./bbscout triage --input export.json --target example.com --threshold 1

# use a different model
./bbscout triage --input export.json --target example.com --model deepseek-r1:14b

# custom report path
./bbscout triage --input export.json --target example.com --output ./report.md
```

**How triage works:**

1. Parses Caido JSON export (base64-decoded request/response pairs)
2. Filters known noise — analytics domains, CDNs, tracking pixels, static assets
3. Heuristic scoring — each entry scored on signals like auth headers, request body, numeric IDs in path, API endpoint patterns. Entries below threshold skip Ollama entirely
4. Ollama analysis — surviving entries sent to local LLM with security-focused system prompt
5. Report generated — findings ranked by severity, saved as markdown

**Heuristic scoring signals:**

| Signal | Score |
|---|---|
| Auth header / session cookie | +4 |
| Has request body | +3 |
| POST / PUT / DELETE | +2 |
| Numeric ID or UUID in path | +2 |
| `/api/` or `/v1/` pattern | +2 |
| Sensitive keyword (admin, token, debug) | +2 |
| Interesting query param (id, user_id) | +1 |
| JSON response | +1 |
| 301/302 redirect | -4 |
| 304 Not Modified | -5 |
| 204 No Content | -3 |
| Static file extension | -4 |

**Output:**
```
output/example.com/
└── triage-report.md       — AI triage report ranked by severity
```

### Full Pipeline

```bash
./bbscout recon  --target example.com
./bbscout crawl  --target example.com --skip-wayback
./bbscout scan   --target example.com --severity high,critical

# capture traffic manually via Caido, then:
./bbscout triage --input caido-export.json --target example.com --concurrency 8
```

## Remote Ollama (Cloud GPU)

For multi-model triage or running larger models, point bbscout at a remote Ollama instance:

```yaml
# config/config.yaml
ollama:
  host: "http://your-gpu-server-ip:11434"
  model: "deepseek-r1:14b"
```

Recommended: Azure for Students ($100 free credit) → NC4as T4 v3 instance.

SSH tunnel (more secure than open port):
```bash
ssh -L 11434:localhost:11434 user@your-gpu-server -N &
# keep host as http://localhost:11434 in config
```

## Workflow

```
1. recon     → find subdomains and live hosts you didn't know existed
2. crawl     → discover endpoints, API paths, historical URLs
3. scan      → automated checks for known vulns and takeovers
4. explore   → manually browse interesting hosts through Caido (authenticated)
5. triage    → AI rates your captured traffic, surfaces findings worth investigating
6. verify    → manually confirm flagged findings in Caido/Burp
7. report    → write and submit
```

The key insight: recon/crawl/scan gives you **breadth** (what exists). Caido + triage gives you **depth** (what's actually vulnerable). Neither replaces the other.

## Project Structure

```
bbscout/
├── main.go
├── config/
│   └── config.yaml
├── cmd/
│   ├── root.go       — cobra setup, config loading, ASCII banner
│   ├── recon.go      — recon pipeline command
│   ├── crawl.go      — crawl pipeline command
│   ├── scan.go       — scan pipeline command
│   ├── triage.go     — triage command with heuristic scoring
│   └── report.go     — report stub
└── internal/
    ├── recon/        — subfinder, assetfinder, crtsh, dnsx, naabu, httpx, gowitness
    ├── crawl/        — katana, gau, waybackurls, merge/dedup/filter utilities
    ├── scan/         — nuclei, subzy
    └── triage/
        ├── har.go    — Caido JSON parser
        ├── ollama.go — Ollama REST client + security-focused prompt
        ├── scorer.go — heuristic pre-filter (skips boring entries before Ollama)
        └── report.go — markdown report + terminal summary
```

## Responsible Use

- Only test targets you have explicit permission to test
- Respect bug bounty program scope and rules
- Do not run aggressive scans against production systems without authorization
- Rate limit appropriately — `--rate-limit 50` for sensitive targets

## License

MIT