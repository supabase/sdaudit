# sdaudit

A comprehensive systemd auditing tool for analyzing unit files, detecting misconfigurations, security issues, and performance problems.

## Features

- **40+ Built-in Rules** across security, reliability, performance, and best practices
- **Multiple Output Formats** - Text, JSON, and SARIF (for GitHub Security integration)
- **Interactive TUI** - Explore scan results with a terminal user interface
- **Boot Analysis** - Analyze boot time and identify slow services
- **Dependency Analysis** - Detect circular dependencies and missing units
- **Security Scoring** - Aggregate security analysis using systemd-analyze

## Installation

### Using Nix (recommended)

```bash
nix build github:samrose/sdaudit
# or run directly
nix run github:samrose/sdaudit -- scan
```

### From Source

```bash
git clone https://github.com/samrose/sdaudit
cd sdaudit
go build -o sdaudit ./cmd/sdaudit
```

## Usage

### Full System Scan

```bash
# Scan all systemd units
sdaudit scan

# Output as JSON
sdaudit scan -f json

# Output as SARIF (for GitHub Security)
sdaudit scan -f sarif > results.sarif

# Filter by severity
sdaudit scan -s high

# Filter by category
sdaudit scan -c security

# Launch interactive TUI
sdaudit scan --tui
```

### Check Specific Unit Files

```bash
# Validate a unit file before deployment
sdaudit check ./my-service.service

# Check multiple files
sdaudit check /etc/systemd/system/*.service
```

### Boot Analysis

```bash
# Analyze boot time and identify slow services
sdaudit boot

# JSON output
sdaudit boot -f json
```

### Dependency Analysis

```bash
# Analyze all dependencies
sdaudit deps

# Analyze specific unit
sdaudit deps nginx.service
```

### Security Scoring

```bash
# Get security scores for all services
sdaudit security

# Score specific service
sdaudit security nginx.service
```

### List Available Rules

```bash
sdaudit list-rules
```

## Rule Categories

### Security Rules (SEC001-SEC015)

| ID | Rule | Severity |
|----|------|----------|
| SEC001 | NoNewPrivileges not set | High |
| SEC002 | PrivateTmp not enabled | Medium |
| SEC003 | ProtectSystem not set or weak | High |
| SEC004 | ProtectHome not enabled | Medium |
| SEC005 | Service running as root without hardening | Critical |
| SEC006 | CapabilityBoundingSet too permissive | High |
| SEC007 | PrivateDevices not set | Medium |
| SEC008 | ProtectKernelTunables not enabled | Medium |
| SEC009 | ProtectKernelModules not enabled | Medium |
| SEC010 | ProtectControlGroups not enabled | Low |
| SEC011 | RestrictSUIDSGID not set | Medium |
| SEC012 | RestrictNamespaces not configured | Medium |
| SEC013 | SystemCallFilter not configured | High |
| SEC014 | MemoryDenyWriteExecute not set | Medium |
| SEC015 | LockPersonality not set | Low |

### Reliability Rules (REL001-REL010)

| ID | Rule | Severity |
|----|------|----------|
| REL001 | Restart policy not configured | High |
| REL002 | RestartSec too short | Medium |
| REL003 | Missing WantedBy or RequiredBy | Medium |
| REL004 | Potential circular dependency | Critical |
| REL005 | After without Requires or Wants | Low |
| REL006 | StartLimitBurst not configured | Medium |
| REL007 | Missing ExecStop for graceful shutdown | Low |
| REL008 | KillMode set to none | High |
| REL009 | Dependency on missing unit | High |
| REL010 | BindsTo without After | Medium |

### Performance Rules (PERF001-PERF005)

| ID | Rule | Severity |
|----|------|----------|
| PERF001 | Boot-critical service not optimized | Low |
| PERF002 | Excessive ExecStartPre commands | Low |
| PERF003 | Consider Type=notify for readiness | Info |
| PERF004 | Type=simple may block dependencies | Info |
| PERF005 | TimeoutStartSec excessively long | Low |

### Best Practice Rules (BP001-BP010)

| ID | Rule | Severity |
|----|------|----------|
| BP001 | Full override in /etc instead of drop-in | Info |
| BP002 | Deprecated directive used | Medium |
| BP003 | ExecStart not using absolute path | Medium |
| BP004 | Missing Documentation directive | Info |
| BP005 | Environment variables in unit file | Info |
| BP006 | Hardcoded paths instead of specifiers | Info |
| BP007 | WorkingDirectory not set | Info |
| BP008 | Missing Description | Info |
| BP009 | User or Group may not exist | High |
| BP010 | Type=oneshot without RemainAfterExit | Low |

## Output Formats

### Text (default)

Human-readable output with colored severity levels.

### JSON

Structured output for scripting and automation:

```json
{
  "version": "1.0.0",
  "timestamp": "2026-01-21T12:00:00Z",
  "summary": {
    "total_units": 150,
    "total_issues": 42,
    "rules_checked": 40,
    "by_severity": {"critical": 2, "high": 10, "medium": 15, "low": 10, "info": 5},
    "by_category": {"security": 20, "reliability": 12, "performance": 5, "bestpractice": 5}
  },
  "issues": [...]
}
```

### SARIF

Static Analysis Results Interchange Format for integration with GitHub Security:

```bash
sdaudit scan -f sarif > results.sarif
gh api repos/{owner}/{repo}/code-scanning/sarifs -X POST -F sarif=@results.sarif
```

## Interactive TUI

Launch the interactive terminal UI to explore scan results:

```bash
sdaudit scan --tui
```

### Keybindings

| Key | Action |
|-----|--------|
| `j/k` or arrows | Navigate |
| `Enter` | Select/expand |
| `Esc` | Go back |
| `d` | Dashboard view |
| `i` | Issues list |
| `/` | Filter/search |
| `?` | Help |
| `q` | Quit |

## CI/CD Integration

### GitHub Actions

```yaml
- name: Validate systemd units
  run: |
    sdaudit check ./deploy/systemd/*.service \
      --format sarif \
      > results.sarif

- uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

### Exit Codes

- `0` - No issues found (or only info-level issues)
- `1` - Issues found at configured severity threshold
- `2` - Error during execution

## Development

### Prerequisites

- Go 1.22+
- Nix (optional, for reproducible builds)

### Building

```bash
# With Go
go build -o sdaudit ./cmd/sdaudit

# With Nix
nix build
```

### Testing

```bash
# Run tests
go test ./...

# With Nix
nix flake check
```

### Linting

```bash
golangci-lint run ./...
```

## Architecture

```
sdaudit/
├── cmd/sdaudit/          # CLI entrypoint
├── internal/
│   ├── analyzer/         # Core analysis engine
│   ├── reporter/         # Output formatters (text, json, sarif)
│   ├── rules/            # Rule definitions
│   │   ├── security/     # Security rules (SEC*)
│   │   ├── reliability/  # Reliability rules (REL*)
│   │   ├── performance/  # Performance rules (PERF*)
│   │   └── bestpractice/ # Best practice rules (BP*)
│   └── tui/              # Terminal UI (Bubbletea)
├── pkg/types/            # Shared types
└── testdata/             # Test fixtures
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

### Adding New Rules

1. Create a new file in the appropriate category directory (e.g., `internal/rules/security/`)
2. Implement the `Rule` interface
3. Register the rule in the `init()` function
4. Add tests in `testdata/`

## Acknowledgments

- Built with [Cobra](https://github.com/spf13/cobra) for CLI
- TUI powered by [Bubbletea](https://github.com/charmbracelet/bubbletea) and [Lipgloss](https://github.com/charmbracelet/lipgloss)
- Inspired by systemd-analyze and various systemd hardening guides
