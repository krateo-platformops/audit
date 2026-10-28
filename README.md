# audit

The one emitter for the canonical **Krateo AuditEvent**. Every Krateo
controller that audits what it does on a person's behalf writes the same record
shape through this package, whichever runtime it is built on
(`provider-runtime` or `unstructured-runtime`). It depends only on the
OpenTelemetry APIs.

Each event is an OTLP LogRecord with `event.name="audit"`. The shared OTel
collector routes those records to the ClickHouse `krateo_audit` table, which
keeps them for 365 days. The `krateo-audit-worm` chart (observability repo)
makes that table tamper-evident.

```go
import "github.com/krateo-platformops/audit"

// once, at startup
emitter := audit.New(loggerProvider.Logger("github.com/<org>/<component>/audit"))

// at each audited action — ctx carries the active span
emitter.Emit(ctx, audit.Event{
	Message:          "created repository demo",
	UserName:         requester,
	Namespace:        cr.GetNamespace(),
	Group:            "github.krateo.io", Version: "v1alpha1", Resource: "repoes",
	Kind:             "Repo", ObjectName: cr.GetName(),
	ObjectUID:        string(cr.GetUID()),
	ObjectGeneration: cr.GetGeneration(),
	ServerAddress:    "api.github.com",
	Action:           "rest.write", HTTPMethod: "POST", StatusCode: 201,
	Outcome:          audit.OutcomeSuccess,
})
```

A nil `*Emitter`, or one built with a nil logger, is a no-op. A component with
OTLP logs switched off needs no guard at each call site.

## Record contract

| attribute | from | notes |
|---|---|---|
| `event.name` | always `audit` | the discriminator the collector routes and every query filters on |
| `enduser.id`, `user.name`, `user.roles` | `EndUserID`, `UserName`, `UserRoles` | who acted |
| `krateo.action`, `http.request.method` | `Action`, `HTTPMethod` | what was done |
| `k8s.namespace.name`, `k8s.resource.{group,version,resource,subresource,kind,name}` | the object's coordinates | what it was done to |
| `k8s.object.uid`, `k8s.object.generation`, `k8s.object.resource_version` | `ObjectUID`, `ObjectGeneration`, `ObjectResourceVersion` | the correlation key (below) |
| `server.address` | `ServerAddress` | external endpoint, **host[:port] only** |
| `outcome`, `http.response.status_code` | `Outcome`, `StatusCode` | `success` → INFO; anything else → ERROR |
| `session.id` | W3C baggage on `ctx` | present on request paths |
| TraceId / SpanId | the span on `ctx` | stamped by the SDK; a record emitted without a span carries `krateo.audit.no_trace_context=true` |

Unset fields are omitted, never written empty.

**Never put a credential in any field.** The trail is kept for 365 days. A path
or query can carry a secret (webhook tokens, signed URLs), and so can an upstream
response body. That is why `server.address` is host-only and `Message` must not
echo a response body.

## When to emit

- **One event per write, after the call**, carrying the authority's answer
  (`Outcome`, `StatusCode`). A timeout or transport error comes back as an
  error, so it is still recorded, as `Outcome: failure`. Don't add a pre-call
  "intent" record: it doubles the volume and adds an attempted-but-unknown state
  every reader has to handle.
- **Known limit:** if the process dies between the external call and the emit,
  that call leaves no record. A reconciling controller retries the write, and
  the retry is audited.
- **Audit export must never block the action.** Export runs asynchronously
  through the OTel SDK. If the collector is unreachable, the write still
  happens. Expose an export-failure metric, so a dropped record shows up as a
  number rather than a silent gap.
- Export OTLP logs to the node-local collector (`http://$(HOST_IP):4318`, with
  `HOST_IP` from `status.hostIP`). Its audit pipeline routes `event.name="audit"`
  to `krateo_audit`.

## Correlating a reconcile with the request that caused it

A reconcile has no inbound request, so it has no `session.id` in baggage. The
link back to the person is the **object's identity**. snowplow's audit event for
the write that created or changed an object records that object's `uid`,
`generation` and `resourceVersion`. A controller records the `uid` and the
`generation` it acted on (its `observedGeneration`). Joining the two on
`(k8s.object.uid, k8s.object.generation)` in `krateo_audit` ties the external
write to the user's request and its `session.id`, without touching the user's
object:
- a write that came through `kubectl` or GitOps produces a generation with no
  snowplow record, so it is correctly not attributed to a portal session;
- a resync on an unchanged generation joins to the original write.

A controller that writes its own spec, or a CR without a status subresource, can
bump `generation` itself. Record the `resourceVersion` it read for an exact
match in those cases.

## Versioning

Released as Go module tags `vX.Y.Z`.
