# Report contract

`schema/v1.json` is the authoritative JSON Schema Draft 2020-12 definition of
current canonical Go output. Its `$id` preserves the existing report `$schema`
URL; the schema document's `$schema` identifies the JSON Schema draft. Validation
uses the local file and requires no schema hosting or network access.

The report version remains `1.0.0`. All seven root fields, metadata fields and
collection counters emitted by Go are required. Nested `omitempty` fields are
optional. Nil slices without `omitempty` and nil evidence maps serialize as null;
empty slices serialize as arrays. `speed_mbps` accepts an integer or null.
Optional pointers are omitted when nil. Timestamps use RFC 3339 date-time strings,
including Go zero timestamps. Integers remain JSON numbers: consumers using
JavaScript must account for precision loss above Number.MAX_SAFE_INTEGER.

Unknown properties are permitted at every object boundary. Finding severity and
confidence are closed enums. OS/service/probe status strings remain extensible;
comments listing platform examples do not define closed enums. Evidence is an
open object. This schema validates structure, not arithmetic relationships or
physical plausibility of measurements.

## Compatibility and verification

Run `go test ./...`. The validator is imported exclusively by tests and pinned in
Go modules (including its transitive text module). CI's existing Go test job runs
these tests. Tests cover both serialization APIs, populated synthetic models,
optional subsystems, nulls, types, enums, versions and required fields.

All nine existing JSON fixtures are historical sanitized report inputs: each lacks
`collection_status.canceled` and `collection_status.skipped`. Additionally,
`network_down_virtual_adapter.json` lacks `data.system.boot_time`, and
`unclassified_storage_warning_event.json` lacks `data.reliability.bugchecks`.
They remain unchanged. Tests classify their raw form as legacy and validate the
Go-decoded/reserialized form, which supplies current fields. Explorer's existing
permissive validation remains unchanged, including missing `$schema` warnings
and rejection of unsupported report versions. Canonical validity does not imply
that every empty/zero model is suitable for visualization (Explorer requires a
nonempty hostname, for example).

Add compatible optional fields without rejecting unknown properties. Review any
new required fields, type/nullability changes or enum removals as breaking
changes requiring explicit approval and a versioned contract. Keep serialization,
this schema, contract tests and consumer compatibility cases together in review.
Do not maintain another independent canonical schema.

## Optional external consumers

The JSON contract can be used by independently developed tools that choose to
read SysDiag report files. SysDiag does not ship, configure or require such a
consumer. Consumer-specific integration proposals should be evaluated separately
and must preserve the versioned report contract.
