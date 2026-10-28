---
type: Architecture
title: audit — overview
description: Why every controller shares one audit emitter, and how an audit record flows from a component to the krateo_audit table.
resource: github.com/krateo-platformops/audit
tags: [library, audit, architecture]
timestamp: 2026-10-28T00:00:00Z
---

# Overview

## Why one emitter

Several Krateo components audit what they do: snowplow for user-driven calls,
the user-lifecycle and access-review controllers for their own actions, and the
adapters that perform external writes during reconcile. Hand-copied emitters
drift, and a drifted attribute name silently breaks every query that joins on
it. A single package fixes the record shape in one place.

It depends only on `go.opentelemetry.io/otel/{log,trace,baggage}`. Krateo has
two controller runtimes (`provider-runtime` and `unstructured-runtime`); a
package inside either would not be importable by the other.

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

## Correlation

Two keys tie an audit row to everything else:

- **`trace_id`**: the Logs SDK stamps TraceId/SpanId from the span on `ctx`.
- **Object identity** (`k8s.object.uid` + `k8s.object.generation`): the user's
  write and the reconcile it caused carry the same pair, so they join without
  ever mutating the user's object. See [usage](./usage.md).
