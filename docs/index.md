---
type: Library
title: audit — index
description: The map of the audit documentation bundle, the shared emitter for the canonical Krateo AuditEvent.
resource: github.com/krateo-platformops/audit
tags: [library, audit, opentelemetry, logs]
timestamp: 2026-10-28T00:00:00Z
---

# audit

`audit` is the Go package every Krateo controller uses to emit the canonical
AuditEvent: one OTLP LogRecord shape (`event.name="audit"`) that the shared
collector routes to the ClickHouse `krateo_audit` table. It depends only on the
OpenTelemetry APIs, so it is importable whichever runtime a controller is built on.
It ships no image, no chart and no CRDs.

- [overview](./overview.md): why one shared emitter, and how a record flows
- [usage](./usage.md): install, when to emit, and correlating a reconcile with its request
- [configuration](./configuration.md): the OTel Logs SDK setup the package relies on
- [api](./api.md): the Go API and the full record contract
- [examples](./examples.md): runnable examples
- [release](./release.md): tag-only release runbook
- [log](./log.md): history
