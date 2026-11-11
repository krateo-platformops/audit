---
type: Library
title: audit — index
description: The map of the audit documentation bundle, the shared emitter and schema for the canonical Krateo AuditEvent.
resource: github.com/krateo-platformops/audit
tags: [library, audit, opentelemetry, logs]
timestamp: 2026-11-11T00:00:00Z
---

# audit

`audit` is the Go package every Krateo component uses to emit the canonical
AuditEvent: one OTLP LogRecord shape (EventName and `event.name` = `audit`)
that the shared collector routes to the ClickHouse `krateo_audit` table, and
one schema (`schema/v1.yaml`) every writer is checked against. It depends only
on the OpenTelemetry APIs, so it is importable whichever runtime a controller
is built on. It ships no image, no chart and no CRDs.

- [overview](./overview.md): why one shared emitter and schema, and how a record flows
- [schema](./schema.md): the record contract, key by key, per writer (generated)
- [coverage](./coverage.md): the cross-component inventory (AUDIT-4): every mutating path, its writer class, identity source, status and owner issue
- [usage](./usage.md): when to emit, the actor, adopting v0.4 and v0.5, testing a writer, the live check
- [configuration](./configuration.md): the Emitter's options and metrics, and the OTel Logs SDK setup
- [api](./api.md): the Go API, audittest and cmd/auditschema
- [examples](./examples.md): runnable examples
- [release](./release.md): tag-only release runbook
- [log](./log.md): history
