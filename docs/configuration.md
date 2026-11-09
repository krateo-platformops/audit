---
type: Configuration
title: audit — configuration
description: The Emitter's three options and two metrics, and the OTel Logs SDK setup the package relies on.
resource: github.com/krateo-platformops/audit
tags: [library, audit, configuration, opentelemetry]
timestamp: 2026-11-09T00:00:00Z
---

# Configuration

`audit.New(logger, opts...)` takes the logger records are written to and three
options. Where records go is decided by the process's OTel Logs SDK.

## Options

| option | effect |
|---|---|
| `WithActor(username, class)` | the actor of every record whose `Event` names none. A controller passes its ServiceAccount, `system:serviceaccount:<namespace>:<name>`, and `audit.ClassController`; a tool executor its own principal and `audit.ClassAgent`. Without it, an `Event` with no `UserName` is refused |
| `WithWriter(w)` | the writer class the Emitter records for. `Emit` then marks every gap that class must mark (snowplow, `WriterRequest`, gets `method` marked). Without it, a gap is marked only when every writer class that can write the key would have to |
| `WithMeterProvider(mp)` | where the two counters below go. Default: `otel.GetMeterProvider()` |

## Metrics

| instrument | attribute | counts |
|---|---|---|
| `krateo.audit.records.refused` | `reason="actor"` | records refused for want of an actor |
| `krateo.audit.records.incomplete` | `marker` | records emitted marked `krateo.audit.incomplete`, per marker |

The attributes name a reason or a marker, never a value of the record.

## Sending records to the audit trail

Export OTLP **logs** to the node-local collector agent:

| setting | value |
|---|---|
| endpoint | `http://$(HOST_IP):4318`, with `HOST_IP` from `fieldRef: status.hostIP` |
| signal | logs (OTLP/HTTP) |
| routing | the collector's `logs/audit` pipeline keeps `event.name == "audit"` and writes `krateo_audit` |

Gate the logs exporter behind a component knob that defaults off. If it's off,
pass a nil logger (or no `Emitter`) and every `Emit` is a no-op.

Name the logger's instrumentation scope as the schema's `populations` list it
(see [schema.md](./schema.md)), so the live conformance queries find your rows.
A new writer adds its scope there.

## Failure behaviour

Export runs asynchronously in the SDK's processor. If the collector can't be
reached, the SDK retries and then drops the record, and the audited action has
already proceeded. Expose an export-failure metric in the component.
