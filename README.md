# SysDiag

SysDiag is a portable, read-only Go diagnostic utility. It collects and analyzes system observations and generates canonical JSON and a self-contained HTML report. The executable requires no Python, Node.js, web server, or external report assets. Reports remain local; SysDiag does not upload data to Cayde.

## Build

Requires Go 1.22 or newer. Build for the current platform:

```sh
go build -o sysdiag ./cmd/sysdiag
```

Cross-compile with `GOOS` and `GOARCH`, for example `GOOS=windows GOARCH=amd64 go build -o sysdiag.exe ./cmd/sysdiag`.

## Run

Double-click `sysdiag.exe` on Windows or run it from a terminal. By default, reports are written to the current directory. Use `--output-dir` to choose another location. The CLI prints the paths of successfully generated artifacts.

```sh
./sysdiag --profile quick
./sysdiag --profile deep --sanitize
./sysdiag --json-only
```

`--json-only` writes canonical JSON to stdout for pipelines. Normal runs produce JSON and standalone HTML unless `--no-html` is supplied. The HTML file can be opened directly in a browser; no server or network connection is required.

| Flag | Description |
|---|---|
| `--profile quick\|deep` | Select diagnostic profile (default `quick`) |
| `--output-dir`, `-o` | Report output directory (default current directory) |
| `--json-only` | Write JSON to stdout and suppress terminal dashboard |
| `--no-html` | Disable standalone HTML generation |
| `--sanitize` | Redact selected identifiers |
| `--pause` | Wait for Enter before exit |
| `--version`, `-v` | Print version |
| `--storage`, `--network`, `--perf`, `--services`, `--inventory` | Run selected probe groups |

## Report contract and tests

The canonical JSON contract is [schema/v1.json](schema/v1.json), Draft 2020-12, version 1.0.0. Historical sanitized examples are retained under `test/legacy-fixtures`; contract tests distinguish those inputs from current Go output.

Run all Go tests with:

```sh
go test ./...
```

Cross-platform builds and race detection are also used in CI where the runner supports them.

## Architecture

- `cmd/sysdiag`: CLI entry point
- `internal/collector`, `internal/probes`, `internal/winapi`: observation collection
- `internal/analyzer`: diagnostic findings
- `internal/models` and `schema`: canonical report model and contract
- `internal/reporter`: terminal, JSON, and self-contained HTML reports
- `internal/sanitizer`: optional identifier redaction

SysDiag is observational and does not remediate, upload, or modify host configuration. See [LICENSE](LICENSE) for license terms.
