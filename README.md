# OSINT Framework

A production-quality, modular, cross-platform open-source intelligence (OSINT) framework written entirely in Go (1.26+). Designed for collecting publicly available information in a structured, concurrent, and extensible manner.

## Features

- **Modular Architecture**: Every OSINT capability is encapsulated in its own package with clean interfaces.
- **Concurrent Execution**: Worker pools with context cancellation, configurable timeouts, and rate limiting support.
- **Rich Terminal UI**: Interactive dashboard built with BubbleTea and Lipgloss featuring tabs, lists, spinners, and keyboard shortcuts.
- **Multiple Export Formats**: JSON, CSV, Markdown, and HTML reports.
- **Structured Logging**: Built on `log/slog` with configurable levels (debug, info, warn, error).
- **Caching**: In-memory TTL cache to avoid redundant requests.
- **Cross-Platform**: Native compilation for Linux, Windows, and macOS with zero CGO dependencies.
- **Optional API Integrations**: Graceful degradation when API keys for VirusTotal, Shodan, Censys, IPinfo, etc., are not configured.

## Project Structure

```
cmd/
    osint/              # CLI entry point
internal/
    config/             # YAML configuration loader
    logger/             # Structured logging setup
    cache/              # TTL in-memory cache
    output/             # Export engines (JSON, CSV, MD, HTML)
    runner/             # Worker pool and task orchestration
    tui/                # BubbleTea dashboard
    modules/
        domain/         # DNS, WHOIS, RDAP, ASN
        web/            # HTTP headers, tech detection, robots, sitemap
        ssl/            # Certificate and TLS analysis
        ip/             # GeoIP, reverse DNS, ASN
        email/          # Syntax validation, MX, SPF, DMARC, Gravatar
        username/       # Social platform availability checks
        github/         # Public profile and repository enumeration
        file/           # Hashing, entropy, metadata extraction
pkg/
    types/              # Common result structures
    interfaces/         # Module contract definitions
configs/
    config.yaml         # Runtime configuration and API keys
assets/
docs/
```

## Installation

```bash
# Clone the repository
git clone https://github.com/osintfw/osint.git
cd osint

# Download dependencies
go mod tidy

# Build a single static binary
go build -o osint cmd/osint/main.go

# (Optional) Install to $GOPATH/bin
go install ./cmd/osint
```

## Configuration

Edit `configs/config.yaml` to set concurrency limits, logging preferences, and optional API keys:

```yaml
concurrency:
  workers: 10
  timeout: 30
  retries: 3

logging:
  level: "info"
  format: "json"

api_keys:
  ipinfo: "YOUR_IPINFO_TOKEN"
  virustotal: "YOUR_VT_KEY"
  shodan: "YOUR_SHODAN_KEY"
```

## Usage

### CLI Examples

```bash
# Domain reconnaissance (DNS, WHOIS, RDAP)
./osint domain example.com

# IP reconnaissance (GeoIP, Reverse DNS, ASN)
./osint ip 8.8.8.8

# Email analysis (MX, SPF, DMARC, Gravatar)
./osint email test@example.com

# Username availability across platforms
./osint username johndoe

# URL analysis (web headers + SSL certificate)
./osint url https://example.com

# File analysis (hashes, entropy, EXIF)
./osint file ./image.jpg

# Export results to HTML
./osint domain example.com -f html -o report.html

# Load and re-export a previous JSON report
./osint report results.json -f markdown -o report.md
```

### Interactive TUI

Launch the dashboard for a keyboard-driven experience:

```bash
./osint tui
```

**Keyboard Shortcuts:**
- `Tab` / `←` / `→` — Switch tabs
- `↑` / `↓` — Navigate module list
- `/` — Focus target input
- `Enter` — Run scan
- `q` / `Ctrl+C` — Quit

## Modules

| Module      | Capabilities                                                               |
|-------------|----------------------------------------------------------------------------|
| **Domain**  | A/AAAA/MX/TXT/NS/CAA records, reverse DNS, WHOIS, RDAP, ASN              |
| **Web**     | HTTP headers, security headers, redirect chain, tech stack, Open Graph,    |
|             | robots.txt, sitemap.xml, cookies                                         |
| **SSL**     | Certificate chain, issuer, SAN, fingerprints, expiration, TLS version, |
|             | cipher suites                                                            |
| **IP**      | Reverse DNS, GeoIP (ip-api / ipinfo), ASN lookup via Team Cymru          |
| **Email**   | Syntax validation, MX records, SPF, DMARC, Gravatar hash                 |
| **Username**| Availability checks on GitHub, GitLab, Twitter, Reddit, Instagram, etc.   |
| **GitHub**  | Public profile, repositories, followers, organizations, languages        |
| **File**    | SHA256/SHA1/MD5, MIME type, Shannon entropy, EXIF, PDF/Office detection   |

## Development

```bash
# Run tests
go test ./...

# Run with debug logging
./osint domain example.com -c configs/config.yaml

# Format code
go fmt ./...

# Run linter
golangci-lint run
```

## Architecture

- **Clean Architecture**: `pkg/` defines contracts and types; `internal/` implements business logic.
- **Dependency Injection**: Modules accept configuration and context explicitly.
- **Interfaces**: Every module can satisfy the `Module` interface for programmatic use.
- **Concurrency**: The `runner` package manages worker pools and enforces global timeouts via `context.Context`.
- **Extensibility**: Adding a new module requires implementing a single function and wiring it into `cmd/osint/main.go`.

## Roadmap

- [ ] Certificate Transparency (crt.sh) module
- [ ] Wayback Machine integration
- [ ] URLScan.io API support
- [ ] VirusTotal file/URL lookup
- [ ] Shodan host search
- [ ] Censys host search
- [ ] GreyNoise IP reputation
- [ ] AbuseIPDB reputation checks
- [ ] Full metadata extraction for Office documents
- [ ] Passive DNS history
- [ ] Subdomain enumeration

## License

MIT License. See `LICENSE` for details.

## Disclaimer

This tool is intended for legal open-source intelligence gathering and security research on assets you own or have explicit permission to investigate. Users are responsible for complying with all applicable laws and service terms of use.
The skeleton of this project and the readme were build using AI, all code was handchecked by me and im still fixing some issues please wait for further commits.
