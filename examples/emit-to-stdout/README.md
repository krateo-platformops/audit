---
type: Example
title: audit — emit-to-stdout example
description: A runnable program that emits one canonical Krateo AuditEvent to stdout through a real OTel Logs SDK pipeline.
resource: github.com/krateo-platformops/audit
tags: [library, audit, example]
timestamp: 2026-10-28T00:00:00Z
---

# emit-to-stdout

Builds a `LoggerProvider` with the OTel stdout log exporter, starts a span, and
emits one audit record for a repository created by a reconcile.

```sh
go run ./examples/emit-to-stdout
```

The output is the LogRecord exactly as the collector would receive it: the
`event.name=audit` discriminator, the object identity
(`k8s.object.uid`, `k8s.object.generation`) used for correlation, and the
TraceId/SpanId stamped from the span. Source: [main.go](main.go).
