---
type: Configuration
title: audit — configuration
description: The package has no configuration of its own; this is the OTel Logs SDK setup it relies on and where records are sent.
resource: github.com/krateo-platformops/audit
tags: [library, audit, configuration, opentelemetry]
timestamp: 2026-10-28T00:00:00Z
---

# Configuration

The package itself takes no configuration: `audit.New(logger)` is its only
input. Where records go is decided by the process's OTel Logs SDK.

## Sending records to the audit trail

Export OTLP **logs** to the node-local collector agent:

| setting | value |
|---|---|
| endpoint | `http://$(HOST_IP):4318`, with `HOST_IP` from `fieldRef: status.hostIP` |
| signal | logs (OTLP/HTTP) |
| routing | the collector's `logs/audit` pipeline keeps `event.name == "audit"` and writes `krateo_audit` |

Gate the logs exporter behind a component knob that defaults off. If it's off,
pass a nil logger (or no `Emitter`) and every `Emit` is a no-op.

## Failure behaviour

Export runs asynchronously in the SDK's processor. If the collector can't be
reached, the SDK retries and then drops the record, and the audited action has
already proceeded. Expose an export-failure metric in the component.
