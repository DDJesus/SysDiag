# SysDiag Engineering Guide

## Product

SysDiag is a portable, read-only Go diagnostic utility. It collects and analyzes
observations, then writes canonical JSON and a self-contained HTML report. End
users need no Python, Node.js, local server, or Explorer application. Reports
are generated locally; there is no automatic upload.

## Architecture

- `cmd/sysdiag` is the CLI entry point.
- `internal/collector`, `internal/probes`, and `internal/winapi` collect observations.
- `internal/models` defines the versioned report contract in `schema/v1.json`.
- `internal/analyzer` evaluates observations.
- `internal/reporter` generates terminal, canonical JSON, and standalone HTML output.
- `internal/sanitizer` redacts selected identifiers.

## Engineering standards

- Preserve existing behavior unless a task explicitly authorizes a change.
- Avoid unnecessary dependencies and preserve report JSON compatibility.
- Use only synthetic or sanitized data in tests and fixtures.
- Run `go test ./...`; run race detection with CGO and a C compiler; cross-build supported targets.

## Agent workflow

Inspect, plan, implement on a feature branch, test, review, commit conventionally, push, and open a PR. Stop before merging.
