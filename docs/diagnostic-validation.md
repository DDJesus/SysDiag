# Diagnostic validation

This document describes deterministic automated checks and optional manual
comparisons for SysDiag's current diagnostic behavior. Automated tests use only
synthetic measurements and identifiers. No real-machine reports are committed
or uploaded.

## Automated validation matrix

The table reports automated coverage in `test/diagnostic_validation_test.go`.
The test runner feeds synthetic probe results through collector normalization,
checks the recorded status and limitation count, then compares finding IDs,
severity, and selected evidence with the expected result.

| Category | Scenario and expected behavior | Automated evidence | Manual comparison | Known limitations |
|---|---|---|---|---|
| CPU | Normal utilization produces no finding; just below 85% is quiet, 85% through just below 95% is warning, and 95% is critical. | `cpu normal`, `cpu below warning boundary`, `cpu warning boundary`, `cpu upper warning boundary`, `cpu critical boundary` | Compare one sampling interval with Task Manager/Performance Monitor or Linux `/proc/stat`. | SysDiag reports aggregate utilization over its sample window; sampling intervals and accounting definitions differ by OS. macOS CPU collection is currently unsupported and should report that status. |
| CPU | Failed or absent data does not create a healthy/high-load finding; partial topology without utilization is quiet but remains Partial; partial measured high utilization remains a finding. | `cpu measurement unavailable after failure`, `cpu partial topology without utilization finding`, `cpu partial high measurement` | Verify the collection status alongside the corresponding monitor. | A zero-valued measurement struct alone cannot distinguish a valid zero from unavailable data; status and missing subsystem data must be considered together. |
| Memory | Normal availability is quiet; 90% through just below 95% commit is warning and 95% is critical. | `memory normal`, `memory warning boundary`, `memory upper warning boundary`, `memory critical boundary` | Windows: Task Manager or `Get-Counter`; Linux: `/proc/meminfo`; macOS: `vm_stat`. | Linux `MemAvailable`, Windows available physical memory, and macOS VM page categories are not numerically interchangeable. Commit metrics have OS-specific meanings. |
| Memory | Zero total memory or availability above total is treated as unavailable/inconsistent and produces no finding with Partial status. | `memory incomplete with zero total`, `memory invalid availability above total`, plus analyzer guard in `rules_system.go` | Check that the reference tool reports consistent total and available capacity before comparing percentages. | The analyzer skips zero-total and impossible available-above-total memory. Other malformed numeric combinations are not comprehensively validated yet. |
| Storage | Healthy volume is quiet; 90% through just below 95% used is warning; a critical volume among healthy volumes produces a finding only for the affected volume. | `storage healthy`, `storage warning boundary`, `storage upper warning boundary`, `storage multiple volumes isolate pressure` | Windows: volume capacity in Explorer/PowerShell; Linux/macOS: `df -h`. | Capacity may change between reads. Queue depth and latency are separate sampling metrics and are not equivalent to free-space measurements. |
| Storage | Missing/inaccessible information is represented by failure/permission status; partial data retains findings supported by the observed volume. | `storage unavailable`, `storage partial data` | Compare collection status and available mounts/volumes. | `df`/volume capacity is logical filesystem availability, not physical disk health. |
| Services | A running automatic service is quiet; an observed stopped automatic service produces the existing informational finding. | `service running`, `service stopped auto start` | Windows: Service Control Manager / `Get-Service`; Linux: `systemctl`. | Trigger-start and on-demand services can appear stopped without indicating a failure. macOS service inventory is currently unsupported. |
| Services | Inaccessible or unsupported inventory produces a limitation and no healthy-state finding. | `service inaccessible`, `service inventory unsupported` | Review the recorded probe status and platform support. | The analyzer only evaluates the `FailedAutoStart` observations supplied by the collector; it does not independently enumerate services. |
| Network/DNS | Successful adapter and DNS observations under the current latency threshold are quiet. | `network and DNS normal` | Compare adapter counters with OS network tools and repeat the same DNS query when possible. | Adapter error counters are cumulative OS counters; snapshot values need not match deltas observed over another interval. |
| Network/DNS | DNS failure and timeout produce the current DNS warning; partial adapter data without a DNS measurement stays Partial. | `DNS failure`, `DNS timeout`, `partial network data without DNS`, `network unavailable` | Run a read-only lookup for a reserved `.invalid` name to confirm resolver failure behavior; this does not change configuration. | A DNS warning describes the diagnostic lookup, not proof of general network outage. OS probes use different lookup targets. |
| Reliability | A known synthetic crash event produces the existing critical finding; successful empty collection produces none. | `reliability known crash`, `reliability no events` | Windows: Event Viewer; Linux: journal/system logs. | macOS reliability event collection is currently unsupported. Event categories and retention differ by OS. |
| Reliability | Access failure produces a limitation and no healthy-state result; partial observed events remain reportable with Partial status. | `reliability access failure`, `reliability partial events` | Compare the Event Log/journal access outcome with the probe status. | Empty results are meaningful only when collection status is Success; partial/failed status must be read with the event list. |
| Sanitization | Redacting a synthetic host, IP, and MAC preserves finding identity, severity, and observed error count. | `TestDiagnosticValidationSanitizationPreservesMeaning` | Not applicable. | Sanitization is defense in depth; never publish raw real-machine reports as validation evidence. |

The automated matrix validates current rules and statuses; it does not claim
that the thresholds are universal operating targets. Current rules are
defined in `internal/analyzer` and are the source of threshold values.

## Optional manual reference checks

Use a disposable, non-production machine and compare observations over a known
time window. These checks are manual and have not been performed as part of CI.
Do not upload raw reports or screenshots. Record only a sanitized summary if
publishing a result is approved.

### Windows

- **CPU:** compare aggregate utilization with Task Manager or Performance
  Monitor's processor counters while keeping the SysDiag sample window in mind.
  Per-process counters may use a different normalization and should not be
  expected to match aggregate utilization.
- **Memory:** compare total/available physical memory with Task Manager or
  PowerShell performance counters. Commit charge/limit is virtual-memory commit,
  not the same quantity as physical RAM used.
- **Storage:** compare each logical volume's total/free capacity with
  `Get-Volume`. Physical disk identity and volume capacity describe different
  layers.
- **Services:** compare state and startup type with Service Control Manager or
  `Get-Service`; SysDiag's finding applies only to observed automatic-start
  services in the stopped state.
- **Network/DNS:** compare adapter state and cumulative error counters with
  `Get-NetAdapterStatistics`. Use the same query target and account for resolver
  caching when comparing DNS duration.
- **Reliability:** compare event IDs and time window with Event Viewer. Event
  retention, channel permissions, and the query's time window affect counts.

### Linux

- **CPU:** sample `/proc/stat` twice over the same interval and calculate deltas;
  SysDiag utilization is a sampled aggregate, so use a comparable interval and
  account for its CPU-state denominator.
- **Memory:** compare physical totals and availability with `/proc/meminfo`,
  especially `MemTotal` and `MemAvailable`. `MemAvailable` is a kernel estimate,
  not simply `MemFree`.
- **Storage:** use `df` for filesystem capacity. Compare I/O deltas from
  `/proc/diskstats` only to SysDiag's disk I/O sampling fields; sector units,
  device mapping, and queue accounting must be normalized first.
- **Services:** compare service state and startup settings with `systemctl`; the
  probe reports systemd service inventory only where systemd is available.
- **Network/DNS:** compare interfaces and counters with `ip -s link`; compare a
  resolver lookup only using the target SysDiag queried on that platform.
- **Reliability:** compare the time window with available journal or kernel
  logs. Privileges, journal retention, and `dmesg` access can produce partial
  collection.

### macOS

- **CPU:** Activity Monitor can provide a manual reference, but SysDiag currently
  reports CPU collection as unsupported; no numeric comparison is available.
- **Memory:** compare with `vm_stat` after accounting for page size and the
  distinction between free, inactive, compressed, and available memory.
- **Storage:** compare filesystem capacity with `df`. Physical disk telemetry
  may be unsupported and is not the same as mount capacity.
- **Services and reliability:** service inventory and reliability event
  collection are currently unsupported; do not interpret absent data as healthy.
- **Network:** compare adapter counters with native network diagnostics and
  DNS resolution with a matching query target. The query duration can differ due
  to caching and resolver configuration.

## Optional bounded workload experiments

These experiments are opt-in examples only. They are not run by CI and do not
alter machine configuration. Close the test process or stop the experiment
immediately if the machine becomes unresponsive. Avoid administrator privileges.

- **Temporary CPU load (Linux/macOS shell):** the following runs one busy worker
  for at most five seconds and installs cleanup for interruption:

  ```sh
  yes >/dev/null & worker=$!
  trap 'kill "$worker" 2>/dev/null || true; wait "$worker" 2>/dev/null || true' EXIT INT TERM
  sleep 5
  ```

- **Temporary CPU load (Windows PowerShell):** use a short-lived background job
  and always stop/remove it in `finally`:

  ```powershell
  $job = Start-Job { while ($true) { } }
  try { Start-Sleep -Seconds 5 } finally { Stop-Job $job; Remove-Job $job }
  ```

- **Temporary memory allocation:** on a disposable machine, a short-lived
  process may allocate at most 64 MiB, hold it for five seconds, then exit to
  release it. Example where Python is already installed:
  `python3 -c "import time; x=bytearray(64*1024*1024); time.sleep(5)"`.
  This is bounded and may be too small to cross a finding threshold; do not
  increase it on a production system.
- **DNS failure:** `getent hosts sysdiag-validation.invalid` can demonstrate a
  failed lookup on Linux without changing resolver settings. It validates the
  OS resolver only; SysDiag's analyzer failure cases are exercised with
  deterministic synthetic DNS observations.
- **Stopped service:** only in a disposable test VM, and only for a service
  created for that experiment and confirmed non-critical. Do not stop an
  installed production or system service. Skip this experiment if a safe,
  disposable service is unavailable.

Never fill a disk, change firewall/DNS/registry/network configuration, crash an
OS, or stop production/system-critical services for validation.
