---
type: Architecture
title: audit — overview
description: Why every writer shares one emitter and one schema, how a record flows to the krateo_audit table, and how the schema file drives the constants, the checker and the live queries.
resource: github.com/krateo-platformops/audit
tags: [library, audit, architecture]
timestamp: 2026-11-09T00:00:00Z
---

# Overview

## Why one emitter, and one schema

Several Krateo components audit what they do: snowplow for user-driven calls,
the identity-lifecycle and access-review controllers for their own actions,
the adapters that perform external writes during reconcile, and the agent
gateway for the hops it proxies. Hand-copied emitters drift, and a drifted
attribute name silently breaks every query that joins on it. A single package
fixes the record shape in one place, and a single schema file
([schema/v1.yaml](../schema/v1.yaml), installer#716) says what each writer
must write.

The package depends only on `go.opentelemetry.io/otel/{log,trace,baggage,metric}`.
Krateo has two controller runtimes (`provider-runtime` and
`unstructured-runtime`); a package inside either would not be importable by
the other.

## Flow

```
component ──Emit(ctx, Event)──▶ OTel Logs SDK ──OTLP──▶ node-local collector
                                (TraceId/SpanId          logs/audit pipeline
                                 stamped from ctx)       (filter event.name=="audit")
                                                               │
                                                               ▼
                                                   ClickHouse krateo_audit
                                                   (365-day retention; sealed by
                                                    krateo-audit-worm)
```

## One schema, four uses

```
schema/v1.yaml ──go generate──▶ schema_gen.go: Key* constants + the rule table
               │                    ├─▶ Emit: keys, markers, W1 dual-write
               │                    ├─▶ Check / audittest: each writer's unit tests
               │                    └─▶ auditschema: OTLP/JSON check + live SQL
               └──go generate──▶ docs/schema.md
```

The YAML parser lives only in the generator, so the package itself stays
OTel-only. A test fails when the generated files are stale, so the unit check,
the live check and the documentation cannot drift from the schema or from each
other.

## Correlation

Two keys tie an audit row to everything else:

- **`trace_id`**: the Logs SDK stamps TraceId/SpanId from the span on `ctx`.
- **Object identity** (`krateo.audit.object_ref.uid` +
  `krateo.audit.object_ref.generation`): the user's write and the reconcile it
  caused carry the same pair, so they join without ever mutating the user's
  object. See [usage](./usage.md).
