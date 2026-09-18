# Sysdiag & Infrastructure Explorer

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=flat&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64%20%7C%20Cross--Platform-lightgrey.svg)](https://microsoft.com/windows)

A portable, read-only system diagnostic sensor and spatial infrastructure explorer. Sysdiag provides fast, deterministic system triage across 9 core diagnostic domains, emitting canonical JSON reports and interactive HTML summaries with zero external runtime dependencies. The accompanying **Infrastructure Explorer** delivers spatial, hierarchical visualization with complete 5-step deterministic evidence chain tracing.

---

## 🏛️ Core Architectural Principles

1. **Sensor vs. Viewer Separation**: `sysdiag` is an observational sensor; the Infrastructure Explorer is an independent consumer. The sensor describes measured reality; the viewer decides how that reality is rendered.
2. **Deterministic Diagnostic Integrity**: The diagnostic engine may interpret evidence, but it never invents evidence. The visualizer may represent relationships, but it never fabricates topology not present in source data.
3. **5-Step Evidence Chain**: Every diagnostic finding strictly preserves its complete, auditable provenance:
   $$\text{Observation} \longrightarrow \text{Evidence Map} \longrightarrow \text{Interpretation} \longrightarrow \text{Potential Impact} \longrightarrow \text{Actionable Recommendation}$$
4. **Zero State Mutation & Observational Safety**: Sysdiag is strictly read-only. It provides no remediation, process killing, service mutation, or registry modification capabilities.
5. **Collection Provenance vs. Diagnostic Health**: Provenance (whether evidence could be collected) is strictly decoupled from diagnostic health (whether findings were detected). Missing data is never rendered as "healthy."

```
+-------------------------------------------------------------+
|                 sysdiag CLI Sensor (Go 1.22+)              |
|   Win32 / NT Syscalls • Event Logs • Performance Counters    |
+-------------------------------------------------------------+
                              │
                              ▼
+-------------------------------------------------------------+
|               Canonical Report (Schema v1.0.0)             |
|   9 Diagnostic Domains • Granular Probes • Finding Overlays |
+-------------------------------------------------------------+
                              │
                              ▼
+-------------------------------------------------------------+
|         Infrastructure Explorer (Spatial Web UI)            |
|   Spatial Constellation • 5-Tab Inspector • Evidence Chains |
+-------------------------------------------------------------+
```

---

## 🔍 Diagnostic Domains & Capabilities

Sysdiag gathers measurements across 9 distinct operational domains:

| Domain | Probes & Evidence Collected |
| :--- | :--- |
| **System** | OS build, architecture, install date, motherboard/BIOS, hypervisor detection, boot time, system uptime. |
| **Compute** | CPU model, physical/logical core counts, L2/L3 cache sizes, processor frequency, utilization rates. |
| **Memory** | Total physical RAM, available memory, percent utilized, system commit total/limit/peak. |
| **Storage** | Physical disk inventory (NVMe/SATA/USB, bus type, media type, size), volume free space, filesystem types. |
| **Network** | Network adapters, operational status, interface types, MAC addresses, IPv4/IPv6 addresses, DNS servers, gateway, DNS resolution latency probes. |
| **Processes** | Top processes by CPU and working-set memory footprint, system vs user space resource distribution. |
| **Services** | Full Windows service inventory, service start types, current run states, service account privileges. |
| **Reliability** | Windows Event Log crash events, system bugchecks (BSOD), kernel power loss incidents, unexpected shutdowns. |
| **Software** | Installed software inventory, Windows hotfixes and security patches, .NET/PowerShell runtimes. |

---

## ⚡ Collection Provenance & Diagnostic Semantics

### Collection Provenance States
Every registered probe records an explicit execution status:
- **`SUCCESS`**: Probe executed completely within allotted timeout.
- **`PARTIAL`**: Partial data collected; domain remains explorable with limitation callouts.
- **`REQUIRES_ADMIN`**: Probe requires elevated Windows Administrator privileges.
- **`UNSUPPORTED`**: Operating system or environment lacks underlying capability.
- **`FAILED`**: WinAPI or system call failed with a recorded error code.
- **`TIMEOUT`**: Probe execution exceeded maximum timeout threshold.
- **`UNKNOWN / LEGACY`**: Backward-compatible fallback for legacy reports lacking per-probe logs.

### Diagnostic Health States
- **`CRITICAL`**: Severe issue detected with potential for immediate failure or data loss.
- **`WARNING`**: Degraded state, high resource pressure, or anomalous configuration.
- **`INFO`**: Low-priority operational observation.
- **`NO FINDING`**: Probe evaluated successfully; zero abnormal conditions detected.
- **`NOT ASSESSED`**: Domain is inventory-only or collection was unavailable.

---

## 🚀 Getting Started

### Prerequisites
- **Sysdiag CLI**: Windows 10/11 or Windows Server 2016+ (cross-compiles on Linux/macOS with standard Go toolchain).
- **Go Toolchain**: Go 1.22 or higher (zero external Go module dependencies).
- **Infrastructure Explorer**: Python 3.9+ (for the local server runner) or any static web server.

### 1. Building the Sysdiag CLI

Compile a single, self-contained executable with zero runtime dependencies:

```powershell
# From repository root
go build -ldflags="-s -w" -o sysdiag.exe ./cmd/sysdiag
```

### 2. Running Sysdiag Scans

Run a quick observational scan:
```powershell
.\sysdiag.exe
```

Run a comprehensive deep diagnostic scan with PII redaction:
```powershell
.\sysdiag.exe --profile deep --sanitize
```

Output only canonical JSON to stdout (ideal for scripts and pipelines):
```powershell
.\sysdiag.exe --json-only > system_report.json
```

#### CLI Command-Line Reference

| Flag | Shorthand | Description | Default |
| :--- | :--- | :--- | :--- |
| `--profile <quick\|deep>` | | Select diagnostic profile | `quick` |
| `--output-dir <path>` | `-o` | Output directory for JSON/HTML reports | Current directory |
| `--json-only` | | Output JSON to stdout and suppress terminal dashboard | `false` |
| `--no-html` | | Disable generation of standalone HTML report | `false` |
| `--sanitize` | | Redact hostnames, usernames, IPs, and MACs | `false` |
| `--pause` | | Pause for Enter key before closing terminal | `false` |
| `--version` | `-v` | Display version information | `false` |
| `--storage` | | Execute storage & volume probes only | `false` |
| `--network` | | Execute network & DNS probes only | `false` |
| `--perf` | | Execute CPU, Memory, Process, & Storage probes only | `false` |
| `--services` | | Execute service inventory & health probes only | `false` |
| `--inventory` | | Execute system & software inventory probes only | `false` |

---

## 🌐 Running Infrastructure Explorer

The Infrastructure Explorer is an interactive, spatial visualization console for inspecting Sysdiag reports.

### Starting the Local Server

Launch the viewer using the included Python server:
```powershell
python main.py --port 8080
```

Open your browser at `http://localhost:8080/index.html`.

### Key Features
- **Spatial Focus Navigation**: Focus any Machine, Subsystem, Component, or Finding with smooth, context-preserving layout transitions.
- **High-Cardinality Workspaces**: Search, filter, and sort high-volume domains (hundreds of services, processes, and software packages) with millisecond response times.
- **5-Tab Contextual Inspector**: View **Overview**, **Measurements**, **Findings**, **Provenance**, and **Raw Data** tailored to the focused entity.
- **Graph-Driven Search**: Instant global search across hostnames, components, IP addresses, service names, and finding IDs.
- **Air-Gapped / Offline-First**: Zero external scripts, fonts, or CDNs. Pure vanilla ES6 modules, SVG, and CSS.

---

## 🧪 Testing & Validation

The codebase includes an end-to-end Go test suite and Python acceptance test suite:

```powershell
# Run Go unit, collector, analyzer, and reporter tests
go test -v -count=1 ./...

# Run Infrastructure Explorer unit and Phase 1-3 acceptance tests
python test_explorer.py
```

---

## 📁 Repository Structure

```
├── cmd/
│   └── sysdiag/            # CLI entrypoint and flag routing
├── internal/
│   ├── analyzer/           # Deterministic diagnostic rule engine
│   ├── collector/          # Probe orchestration and execution engine
│   ├── config/             # Scan profiles and runtime options
│   ├── models/             # Canonical schema 1.0.0 data structures
│   ├── probes/             # Domain probes (cpu, memory, network, etc.)
│   ├── reporter/           # Terminal, JSON, and standalone HTML generators
│   ├── sanitizer/          # PII and sensitive identifier redaction
│   └── winapi/             # Windows NT / Win32 syscall bindings
├── test/
│   ├── fixtures/           # Adversarial test fixtures and synthetic reports
│   ├── e2e_test.go         # End-to-end collector and analyzer tests
│   └── fixture_test.go     # Rule engine regression test suite
├── web/
│   ├── js/
│   │   ├── app.js              # Application entrypoint & state coordinator
│   │   ├── graph-model.js      # Hierarchical InfrastructureGraph abstraction
│   │   ├── graph-renderer.js   # Spatial focus canvas and orbital layout engine
│   │   ├── sysdiag-adapter.js  # Schema 1.0.0 adapter & provenance mapper
│   │   ├── detail-inspector.js # 5-tab evidence and telemetry inspector
│   │   └── schema-validator.js # JSON schema structural validation
│   ├── samples/                # Sample diagnostic reports for testing
│   ├── index.html              # Operations console web interface
│   └── styles.css              # Dark operations-center stylesheet
├── main.py                 # Local web server entrypoint
├── test_explorer.py        # Web explorer test suite (23 acceptance tests)
└── go.mod                  # Go module definition (zero dependencies)
```

---

## 🔒 Security & Privacy

- **No Remote Calls / No Telemetry**: Sysdiag does not transmit data over the network or communicate with external servers.
- **Read-Only Operation**: Collects system state via standard Windows APIs without modifying system configuration or executing destructive operations.
- **Optional Sanitization**: Use `--sanitize` to mask usernames, hostnames, IP addresses, MAC addresses, and serial numbers before sharing reports.

---

## 📄 License

This project is licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for details.
