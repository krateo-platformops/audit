---
type: API
title: audit — API
description: The exported Go API of the audit package and the full record contract: every attribute an AuditEvent can carry.
resource: github.com/krateo-platformops/audit
tags: [library, audit, api]
timestamp: 2026-10-28T00:00:00Z
---

# API

## Go API

```go
const EventName = "audit"            // the discriminator on every record
const BaggageSessionKey = "session.id"
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
	OutcomeDenied  = "denied"
)

func New(logger log.Logger) *Emitter
func (e *Emitter) Emit(ctx context.Context, ev Event) // nil-safe

type Event struct { /* see the record contract below */ }
```

## Record contract

| attribute | `Event` field | notes |
|---|---|---|
| `event.name` | always `audit` | the discriminator the collector routes and every query filters on |
| `enduser.id`, `user.name` | `EndUserID`, `UserName` | who acted |
| `user.roles` | `UserRoles` | a slice attribute |
| `krateo.action` | `Action` | logical verb, e.g. `call`, `rest.write` |
| `http.request.method` | `HTTPMethod` | the verb actually sent |
| `http.response.status_code` | `StatusCode` | omitted when 0 |
| `outcome` | `Outcome` | `success` → INFO; anything else → ERROR |
| `k8s.namespace.name` | `Namespace` | |
| `k8s.resource.group` / `version` / `resource` / `subresource` / `kind` / `name` | `Group`, `Version`, `Resource`, `Subresource`, `Kind`, `ObjectName` | the object acted on |
| `k8s.object.uid` | `ObjectUID` | correlation key |
| `k8s.object.generation` | `ObjectGeneration` | correlation key; omitted when 0 |
| `k8s.object.resource_version` | `ObjectResourceVersion` | exact-match key |
| `server.address` | `ServerAddress` | external endpoint, **host[:port] only** |
| `session.id` | read from W3C baggage on `ctx` | present on request paths |
| `krateo.audit.no_trace_context` | set automatically | `true` when `ctx` carries no valid span |
| LogRecord body | `Message` | must not echo a response body |
| TraceId / SpanId | the span on `ctx` | LogRecord fields stamped by the SDK, not attributes |

Unset fields are omitted, never written empty.
