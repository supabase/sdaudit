# sdaudit Design Document

**Date:** 2026-01-20
**Status:** Approved

## Overview

**sdaudit** is a comprehensive systemd auditing tool for Ubuntu 24.04. It analyzes unit files, running services, and system configuration to detect misconfigurations, security issues, and performance problems.

### Target Users

- **Sysadmins** managing production servers - audit existing systems, catch misconfigurations before outages
- **DevOps engineers** writing new services - validate unit files before deployment, integrate into CI/CD

### Tech Stack

- **Language:** Go
- **CLI Framework:** Cobra
- **TUI:** Bubbletea + Lipgloss
- **Testing:** Go standard library + teatest for TUI

---

## CLI Interface

### Commands

```
sdaudit scan [flags]           # Full system audit
sdaudit check <unit-file>      # Check specific unit file(s)
sdaudit boot                   # Boot time analysis
sdaudit deps [unit]            # Dependency analysis
sdaudit security [unit]        # Security scoring (wraps systemd-analyze security)
```

### Key Flags

```
--format, -f      Output format: text (default), json, sarif
--severity, -s    Minimum severity: critical, high, medium, low, info
--category, -c    Filter by category: security, performance, reliability, bestpractice
--tags, -t        Filter by tags (comma-separated)
--tui             Launch interactive TUI after scan
--config          Path to config file
--quiet, -q       Only output issues (no progress)
--no-color        Disable colored output
```

### Example Usage

```bash
sdaudit scan                              # Full audit, text output
sdaudit scan -f json | jq                 # JSON for scripting
sdaudit scan -f sarif > results.sarif     # For GitHub Security
sdaudit check ./my-service.service        # Validate before deploy
sdaudit scan --tui                        # Interactive exploration
sdaudit scan -s high -c security          # Only high+ security issues
```

---

## Architecture

### Project Structure

```
sdaudit/
├── cmd/
│   └── sdaudit/
│       └── main.go              # CLI entrypoint (cobra)
├── internal/
│   ├── analyzer/
│   │   ├── analyzer.go          # Orchestrates analysis
│   │   ├── systemd.go           # systemd-analyze wrapper
│   │   └── parser.go            # Unit file parser
│   ├── rules/
│   │   ├── registry.go          # Rule registration & discovery
│   │   ├── rule.go              # Rule interface definition
│   │   ├── security/            # Security rules
│   │   ├── performance/         # Performance rules
│   │   ├── reliability/         # Reliability rules
│   │   └── bestpractice/        # Best practice rules
│   ├── reporter/
│   │   ├── text.go              # Human-readable output
│   │   ├── json.go              # JSON output
│   │   └── sarif.go             # SARIF output
│   └── tui/
│       ├── app.go               # Bubbletea app
│       ├── views/               # TUI views/components
│       └── styles.go            # Lipgloss styles
├── pkg/
│   └── types/                   # Shared types (Issue, Severity, etc.)
└── rules.go                     # Rule auto-registration via init()
```

### Rule Interface

```go
type Rule interface {
    ID() string                    // e.g., "SEC001"
    Name() string                  // e.g., "NoNewPrivileges not set"
    Description() string           // Detailed explanation
    Category() Category            // Security, Performance, etc.
    Severity() Severity            // Critical, High, Medium, Low, Info
    Tags() []string                // Flexible filtering tags
    Check(ctx *Context) []Issue    // Run the check
    Suggestion() string            // How to fix
    References() []string          // Documentation links
}
```

Rules self-register via `init()` functions, so adding a new rule is just creating a new file.

---

## Rule Categories

### Security Rules (SEC)

| ID | Rule | Severity |
|----|------|----------|
| SEC001 | `NoNewPrivileges=` not set | High |
| SEC002 | `PrivateTmp=` not enabled | Medium |
| SEC003 | `ProtectSystem=` not set or weak | High |
| SEC004 | `ProtectHome=` not enabled | Medium |
| SEC005 | Service running as root without justification | Critical |
| SEC006 | `CapabilityBoundingSet=` too permissive | High |
| SEC007 | `SecureBits=` not configured | Medium |
| SEC008 | Writable `/etc` or `/usr` paths | Critical |
| SEC009 | `PrivateDevices=` not set for non-device services | Medium |
| SEC010 | `ProtectKernelTunables=` not enabled | Medium |
| SEC011 | `ProtectKernelModules=` not enabled | Medium |
| SEC012 | `ProtectControlGroups=` not enabled | Low |
| SEC013 | `RestrictSUIDSGID=` not set | Medium |
| SEC014 | `RestrictNamespaces=` too permissive | Medium |
| SEC015 | `SystemCallFilter=` not configured | High |

### Performance Rules (PERF)

| ID | Rule | Severity |
|----|------|----------|
| PERF001 | Service in critical boot path but not optimized | Medium |
| PERF002 | Excessive `ExecStartPre=` commands | Low |
| PERF003 | Missing `Type=notify` for long-running services | Low |
| PERF004 | Blocking `Type=simple` when `forking` appropriate | Medium |
| PERF005 | `TimeoutStartSec=` excessively long | Low |

### Reliability Rules (REL)

| ID | Rule | Severity |
|----|------|----------|
| REL001 | `Restart=` not configured for critical service | High |
| REL002 | `RestartSec=` too short (restart loops) | Medium |
| REL003 | Missing `WantedBy=` or `RequiredBy=` | Medium |
| REL004 | Circular dependency detected | Critical |
| REL005 | `After=` without corresponding `Requires=` or `Wants=` | Low |
| REL006 | `StartLimitBurst=` / `StartLimitIntervalSec=` not set | Medium |
| REL007 | Missing `ExecStop=` for services needing graceful shutdown | Medium |
| REL008 | `KillMode=` set to `none` | High |
| REL009 | Dependency on removed/masked unit | Critical |
| REL010 | Socket activation without `Accept=` consideration | Low |
| REL011 | `BindsTo=` without `After=` | Medium |
| REL012 | Orphaned units (no dependency chain to target) | Low |

### Best Practice Rules (BP)

| ID | Rule | Severity |
|----|------|----------|
| BP001 | Unit file in `/etc` overriding `/lib` without reason | Info |
| BP002 | Deprecated directives used | Medium |
| BP003 | `ExecStart=` using absolute path without validation | Low |
| BP004 | Missing `Documentation=` directive | Info |
| BP005 | Environment variables in unit file (use `EnvironmentFile=`) | Low |
| BP006 | Hardcoded paths that should use `%` specifiers | Low |
| BP007 | `WorkingDirectory=` not set | Info |
| BP008 | Missing `Description=` | Info |
| BP009 | `User=`/`Group=` referencing non-existent user | High |
| BP010 | Using `Type=oneshot` without `RemainAfterExit=` | Low |

---

## systemd-analyze Integration

### Boot Analysis

```go
type BootAnalysis struct {
    TotalTime     time.Duration
    KernelTime    time.Duration
    InitrdTime    time.Duration
    UserspaceTime time.Duration
    Units         []UnitTiming    // from `blame`
    CriticalChain []ChainLink     // from `critical-chain`
}
```

**Derived checks:**
- Flag units taking >5s in critical chain
- Identify units blocking boot unnecessarily
- Detect services that could be socket-activated

### Dependency Analysis

```go
type DependencyGraph struct {
    Units map[string]*UnitNode
    Edges []DependencyEdge    // from `systemd-analyze dot`
}
```

**Derived checks:**
- Circular dependency detection
- Orphaned units (unreachable from any target)
- Missing dependencies (unit references non-existent unit)
- Ordering issues (`After=` without `Requires=`)

### Security Scoring

Wraps `systemd-analyze security <unit>` and parses the exposure score (0-10) plus individual checks. Enhanced by:
- Aggregating scores across all services
- Flagging services above threshold (default: 5.0)
- Cross-referencing with our own SEC rules for detailed suggestions

### Unit Verification

Wraps `systemd-analyze verify <unit>` to catch:
- Syntax errors
- Unknown directives
- Invalid values

### Dependency Regression Check

```go
type RegressionReport struct {
    Baseline      string              // Path or timestamp of baseline
    Current       string              // Current snapshot identifier
    AddedUnits    []string            // New units appeared
    RemovedUnits  []string            // Units no longer present
    AddedEdges    []DependencyEdge    // New dependencies
    RemovedEdges  []DependencyEdge    // Removed dependencies
    CyclesIntroduced [][]string       // New circular dependencies
    OrderingChanges  []OrderingDiff   // Changes in boot ordering
}
```

**CLI Commands:**

```bash
sdaudit deps --save baseline.dot          # Save current state as baseline
sdaudit deps --diff baseline.dot          # Compare current against baseline
sdaudit deps --diff before.dot after.dot  # Compare two snapshots
```

**Output Example:**

```
Dependency Regression: baseline.dot → current

+ Added units (3):
    my-new-service.service
    my-new-service.socket
    backup-timer.timer

- Removed units (1):
    legacy-daemon.service

+ Added dependencies (2):
    nginx.service → my-new-service.service (Wants)
    my-new-service.socket → my-new-service.service (Triggers)

⚠ Ordering changes (1):
    postgresql.service now starts AFTER redis.service (was concurrent)
```

---

## TUI Design

The TUI uses Bubbletea for the framework and Lipgloss for styling.

### Main Views

**1. Dashboard (default)**
```
┌─ sdaudit ──────────────────────────────────────────────────────┐
│ System: ubuntu-server-01          Scanned: 2024-01-20 14:32   │
│                                   [r] to rescan                │
├────────────────────────────────────────────────────────────────┤
│  CRITICAL  2  ██                                               │
│  HIGH     12  ██████████                                       │
│  MEDIUM   34  ████████████████████████████                     │
│  LOW      18  ███████████████                                  │
│  INFO      8  ███████                                          │
├────────────────────────────────────────────────────────────────┤
│ Categories:  Security (28)  Reliability (19)  Performance (15)│
│              Best Practice (12)                                │
├────────────────────────────────────────────────────────────────┤
│ [i]ssues  [u]nits  [b]oot  [d]eps  [s]ecurity  [f]ilter  [q]uit│
└────────────────────────────────────────────────────────────────┘
```

**2. Issues List**
- Sortable by severity, category, unit
- Filterable by tags, severity, category
- Press Enter to expand issue details

**3. Unit Detail**
- Shows all issues for a specific unit
- Displays parsed unit file with inline annotations
- Shows security score and breakdown

**4. Dependency Graph** (ASCII)
- Interactive navigation of dependency tree
- Highlights problematic edges (cycles, missing deps)

### Rescan Features

- **`r`**: Full rescan - re-runs complete analysis
- **`R`**: Quick rescan - only re-checks previously failing rules
- **`Ctrl+r`**: Rescan specific unit (when in unit detail view)

### Diff View After Rescan

```
┌─ Rescan Results ───────────────────────────────────────────────┐
│ Rescanned: 2024-01-20 14:45 (13 min since last scan)          │
├────────────────────────────────────────────────────────────────┤
│  ✓ Fixed (3):                                                  │
│      SEC001  nginx.service - NoNewPrivileges now set          │
│      SEC002  nginx.service - PrivateTmp now enabled           │
│      REL001  myapp.service - Restart policy configured        │
│                                                                │
│  ✗ New (1):                                                    │
│      BP005   myapp.service - Env vars in unit file            │
│                                                                │
│  ─ Unchanged: 71 issues                                        │
├────────────────────────────────────────────────────────────────┤
│ [Enter] back to dashboard    [d] show diff details             │
└────────────────────────────────────────────────────────────────┘
```

### Keybindings

| Key | Action |
|-----|--------|
| `j/k` or arrows | Navigate |
| `/` | Search/filter |
| `Enter` | Expand/select |
| `Esc` | Back |
| `r` | Full rescan |
| `R` | Quick rescan |
| `Ctrl+r` | Rescan current unit |
| `d` | Toggle diff view |
| `?` | Help |
| `q` | Quit |

---

## Output Formats

### JSON Output

```json
{
  "version": "1.0.0",
  "timestamp": "2024-01-20T14:32:00Z",
  "system": {
    "hostname": "ubuntu-server-01",
    "systemd_version": "255",
    "os": "Ubuntu 24.04 LTS"
  },
  "summary": {
    "total": 74,
    "by_severity": {"critical": 2, "high": 12, "medium": 34, "low": 18, "info": 8},
    "by_category": {"security": 28, "reliability": 19, "performance": 15, "bestpractice": 12}
  },
  "issues": [
    {
      "id": "SEC001",
      "name": "NoNewPrivileges not set",
      "severity": "high",
      "category": "security",
      "tags": ["hardening", "privilege-escalation"],
      "unit": "nginx.service",
      "file": "/lib/systemd/system/nginx.service",
      "line": null,
      "description": "Service does not set NoNewPrivileges=yes, allowing potential privilege escalation.",
      "suggestion": "Add 'NoNewPrivileges=yes' to the [Service] section.",
      "references": [
        "https://www.freedesktop.org/software/systemd/man/systemd.exec.html#NoNewPrivileges="
      ]
    }
  ],
  "boot_analysis": { },
  "dependency_graph": { },
  "security_scores": { }
}
```

### SARIF Output

Follows SARIF 2.1.0 spec for GitHub Security integration:
- Each rule maps to a SARIF `reportingDescriptor`
- Issues map to `results` with location info
- Suggestions populate `fixes` array
- Tags map to `properties.tags`

Enables: `sdaudit scan -f sarif | gh api repos/{owner}/{repo}/code-scanning/sarifs -X POST`

---

## Configuration

### Config File Locations

```
~/.config/sdaudit/config.yaml    # User config
/etc/sdaudit/config.yaml         # System-wide config
.sdaudit.yaml                    # Project/repo config (for CI)
```

### Config Structure

```yaml
# Severity threshold for exit code (CI integration)
fail_on: high  # critical, high, medium, low, info

# Rule customization
rules:
  # Disable specific rules
  disabled:
    - BP004  # We don't require Documentation=
    - BP008  # We don't require Description=

  # Override severity
  severity_overrides:
    SEC002: critical  # PrivateTmp is critical for us
    PERF001: info     # Boot time not a concern

  # Custom thresholds
  thresholds:
    security_score_max: 4.0      # Default: 5.0
    boot_critical_chain_max: 10s # Default: 30s
    restart_sec_min: 5s          # Default: 1s

# Unit filtering
include_units:
  - "myapp-*.service"
  - "nginx.service"

exclude_units:
  - "user@*.service"
  - "systemd-*.service"  # Skip systemd's own units

# Paths to scan (for `check` command)
unit_paths:
  - /etc/systemd/system
  - /lib/systemd/system
  - ./deploy/systemd  # Local project units

# Output defaults
output:
  format: text
  color: auto  # auto, always, never
```

### CI Example

```yaml
# .github/workflows/systemd-lint.yaml
- name: Validate systemd units
  run: |
    sdaudit check ./deploy/systemd/*.service \
      --format sarif \
      --fail-on high \
      > results.sarif

- uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

---

## Testing Strategy

### Test Structure

```
sdaudit/
├── testdata/
│   ├── units/
│   │   ├── valid/              # Well-configured unit files
│   │   ├── invalid/            # Unit files with known issues
│   │   └── fixtures/           # Specific test cases per rule
│   ├── systemd-analyze/
│   │   ├── blame/              # Sample blame outputs
│   │   ├── dot/                # Sample dependency graphs
│   │   └── security/           # Sample security outputs
│   └── golden/                 # Expected outputs for regression
```

### Test Types

**1. Rule Unit Tests**
```go
func TestSEC001_NoNewPrivileges(t *testing.T) {
    unit := loadTestUnit("fixtures/sec001-missing.service")
    issues := rules.SEC001.Check(newContext(unit))
    assert.Len(t, issues, 1)
    assert.Equal(t, SeverityHigh, issues[0].Severity)
}
```

**2. Parser Tests**
- Verify unit file parsing handles all directive types
- Test malformed input handling
- Verify systemd-analyze output parsing

**3. Integration Tests**
- Run against real systemd (in VM/container)
- Verify end-to-end CLI behavior
- Test TUI flows with go-test/teatest

**4. Golden Tests**
- Snapshot expected JSON/SARIF output
- Catch unintended output format changes

### CI Pipeline

```
make lint      → golangci-lint
make test      → unit + parser tests
make integ     → integration tests (requires systemd)
make golden    → golden file comparison
```

---

## Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Rule definition | Go code | Maximum flexibility, no DSL complexity |
| Auto-fix | No (suggestions only) | System services too risky for automation |
| Architecture | Pluggable rules via `init()` | Easy contribution, clear organization |
| Output formats | Text + JSON + SARIF | Human use + scripting + security tooling |
| TUI framework | Bubbletea | Best Go TUI library, active community |
| Regression check | Dot file diff | Leverage existing systemd-analyze output |
