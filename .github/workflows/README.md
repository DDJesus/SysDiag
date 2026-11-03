# GitHub Actions runtime and dependency notes

All JavaScript actions used by the CI and manual release workflows are pinned to
verified full commit SHAs and currently declare `runs.using: node24`:

| Action | Pinned release |
| --- | --- |
| `actions/checkout` | `v7.0.1` |
| `actions/setup-go` | `v7.0.0` |
| `actions/upload-artifact` | `v7.0.2` |
| `actions/download-artifact` | `v8.0.2` |

GitHub states that Node.js 20 is no longer available to JavaScript Actions on
GitHub-hosted runners as of September 23, 2026. The listed action releases are
Node.js 24 compatible and require Actions Runner `2.327.1` or newer; GitHub's
hosted runners manage their runner versions.

## Runtime verification limits

The Node.js executable found on a runner's normal `PATH` is not necessarily the
runtime that executes a JavaScript action. GitHub Actions invokes JavaScript
actions with a Node runtime managed by the runner agent. Installing or checking
the system Node executable does not establish the version of that managed
runtime.

The latest published GitHub-hosted Ubuntu runner image information available
when this was reviewed listed Node.js `24.22.2` as an installed image runtime.
That image inventory does not prove which exact runtime binary was used by a
particular job: hosted runner images and runner-agent updates roll out
independently, and the workflow does not control or directly attest the
agent-managed action runtime. Therefore this repository cannot independently
confirm that every individual job used Node.js `24.22.1` or later, the minimum
patched version for CVE-2026-111497. GitHub must provide that per-run assurance.

References:

- [GitHub: Node 20 is no longer available in GitHub Actions](https://github.blog/changelog/2026-09-23-node-20-is-no-longer-available-on-github-actions/)
- [GitHub-hosted runner image releases](https://github.com/actions/runner-images/releases)
- [Node.js v24.22.1 security release](https://github.com/nodejs/node/releases/tag/v24.22.1)
- [actions/checkout v7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1)
- [actions/setup-go v7.0.0](https://github.com/actions/setup-go/releases/tag/v7.0.0)
- [actions/upload-artifact v7.0.2](https://github.com/actions/upload-artifact/releases/tag/v7.0.2)
- [actions/download-artifact v8.0.2](https://github.com/actions/download-artifact/releases/tag/v8.0.2)
