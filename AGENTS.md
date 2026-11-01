# SysDiag Engineering Guide

## Architecture

- `cmd/sysdiag` contains the Go diagnostic CLI and command-line entry point.
- `internal/collector` orchestrates probes; platform-specific implementations live under `internal/probes` and `internal/winapi`.
- `internal/models` defines the shared diagnostic report and its JSON representation.
- `internal/analyzer` evaluates collected metrics and produces findings.
- `internal/reporter` contains terminal, JSON, and standalone HTML report outputs; `internal/sanitizer` redacts selected identifiers.
- `web` contains the JavaScript Infrastructure Explorer, and `main.py` provides its local development server.

## Engineering standards

- Preserve existing functionality unless a task explicitly authorizes a behavior change.
- Prefer small, testable changes over broad refactors.
- Avoid unnecessary third-party dependencies.
- Maintain backwards compatibility with the report JSON contract. Stop for developer approval before changing a public API or report schema.
- Respect platform-specific behavior and verify supported operating systems when changing shared code.
- Never add sensitive diagnostic data to commits, tests, or fixtures. Use synthetic or sanitized data.

## Agent workflow

1. Inspect relevant code and tests.
2. Identify requirements and risks.
3. Create a scoped implementation plan.
4. Implement on a dedicated feature branch.
5. Write and run appropriate tests.
6. Review the diff for correctness, security, and scope.
7. Commit using a conventional commit message.
8. Push the feature branch.
9. Open a pull request containing a summary, tests, and risks.
10. Stop before merging.

## Stop conditions

Stop and request developer approval when:

- A public API or report schema must change.
- A new dependency is required.
- Existing behavior must be removed.
- A security-sensitive architectural decision is required.
- Tests fail and cannot be resolved within the approved scope.
- Unexpected repository changes or Git conflicts occur.

Do not put one-time task details into these permanent instructions.

## Verification commands

- Run Go unit and integration tests with `go test ./...`.
- Run race detection with `go test -race ./...` on a runner with CGO enabled and a C compiler.
- Build the CLI for supported targets by setting `GOOS` and `GOARCH`, then running `go build ./cmd/sysdiag`.
