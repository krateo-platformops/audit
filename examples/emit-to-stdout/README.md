---
type: Example
title: audit — emit-to-stdout example
description: A runnable program that emits one canonical Krateo AuditEvent to stdout through a real OTel Logs SDK pipeline and checks it against the schema.
resource: github.com/krateo-platformops/audit
tags: [library, audit, example]
timestamp: 2026-11-09T00:00:00Z
---

# emit-to-stdout

Builds a `LoggerProvider` with the OTel stdout log exporter, starts a span, and
emits one audit record for a repository a controller created, with the
controller's ServiceAccount as the actor (`audit.WithActor`).

```sh
go run ./examples/emit-to-stdout
```

The output is the LogRecord exactly as the collector would receive it: the
EventName and `event.name=audit` discriminator, `krateo.audit.schema_version`,
the actor and its class, the object reference and identity
(`krateo.audit.object_ref.*`, and the v0.3 `k8s.resource.*` / `k8s.object.*`
written beside them during W1), and the TraceId/SpanId stamped from the span.
A processor ahead of the exporter runs `audit.CheckRecord` on the record and
prints `0 violation(s)` to stderr. Source: [main.go](main.go).
