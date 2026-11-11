---
type: Usage
title: audit — usage
description: Install the package, when and how to emit, who the actor is, adopting v0.4.0 and v0.5.0, testing a writer against the schema, and checking the live table.
resource: github.com/krateo-platformops/audit
tags: [library, audit, usage]
timestamp: 2026-11-11T00:00:00Z
---

# Usage

## Install

```sh
go get github.com/krateo-platformops/audit@latest
```

The module requires Go ≥ 1.26 (see `go.mod`). Build with **Go ≥ 1.26.10**: the
`go` line is only the language floor, and the standard library comes from your
toolchain. Older 1.26 patches carry `net/http`, `crypto/x509` and `net/url`
vulnerabilities that `govulncheck` reports against code using this package. The
floating `golang:1.26` images track the latest 1.26 patch.

This repo's `go.mod` also carries `toolchain go1.26.10`, so its own builds,
tests and scans use a patched standard library. Go ignores a dependency's
`toolchain` line, so it does not raise your floor; set your own if you scan with
an older Go.

Build one `Emitter` at startup from the process `LoggerProvider` and inject it.
A nil `*Emitter`, or one built with a nil logger, is a no-op, so a component
with OTLP logs switched off needs no guard at each call site.

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

**Never put a credential in any field.** The trail is kept for 365 days. A path
or query can carry a secret (webhook tokens, signed URLs), and so can an upstream
response body. That is why `ServerAddress` is host[:port] only and `Message` must
not echo a response body: write a closed-set text, such as "external write
failed", never `err.Error()`.

`Emit` enforces the `ServerAddress` rule itself: it reduces the value to
host[:port], so passing the request URL records only its host and port. A value
with no parseable host is omitted, never written raw. That reduction is a
safety net, not permission to put a secret in any other field.

**Never log audit attributes.** They carry identity on purpose. They go to the
audit LoggerProvider and nowhere else: not to a span, not to an ordinary log
line. `Check` and `audittest` report keys and reasons, never values.

## Who the actor is

`user.name` is whoever performs the action, as their credential proves it.
`krateo.audit.actor_class` is that principal's class.

- **A controller or tool executor** reports its own principal: build the
  Emitter with `audit.WithActor("system:serviceaccount:<ns>:<sa>",
  audit.ClassController)` (a tool executor: `audit.ClassAgent`).
- **A writer that serves authn tokens** takes the actor from the token. With
  plumbing's `jwtutil` v1.34.0 or later:

  ```go
  ev.UserName = ui.Actor() // the outermost act subject on a delegated token
  ev.UserRoles = ui.Groups
  if c, ok := audit.ParseClaim(ui.ActorPrincipal()); ok {
  	ev.ActorClass = c
  } // else omit it: Emit marks krateo.audit.incomplete=actor_class. Never default to human.
  if ui.Act != nil {
  	ev.OnBehalfOf = ui.Username // the token's sub, the person
  	for a := ui.Act; a != nil; a = a.Act {
  		c, _ := audit.ParseClaim(a.Principal)
  		ev.Delegation = append(ev.Delegation, audit.Link{Class: c, Subject: a.Sub})
  	}
  	c, _ := audit.ParseClaim(ui.Principal)
  	ev.Delegation = append(ev.Delegation, audit.Link{Class: c, Subject: ui.Username})
  }
  ```

- **The affected user is not the actor.** When an action is done *to* a user
  (a revoked grant's subject, a deactivated account), that user goes in
  `AffectedUser`, never in `UserName` and never in `Message`.

## Preview

Set `Preview` on every record that names a Kubernetes object. It is
`PreviewOf(true)` when the target is a namespaced object whose Namespace
carries the label `krateo.io/purpose=preview-sandbox`, as read from apiserver
state by the writer (a namespace lister or a get on its own client), and
`PreviewOf(false)` otherwise, a cluster-scoped object included. Leave it
`PreviewUnknown` when the Namespace could not be read: the record is then
marked `krateo.audit.incomplete=preview`. A record that names only an
external endpoint carries no preview. Never read the label from the object
itself: whoever creates an object writes its labels.

## Dry runs

A writer that serves requests or performs actions (snowplow, a tool executor)
builds its Emitter with `WithWriter(audit.WriterRequest)` or
`WithWriter(audit.WriterAction)`, and sets `Event.DryRun` on a write the
authority was asked to validate and not persist (Kubernetes `dryRun=All`).
Every write record then carries `krateo.audit.dry_run`: `true` for a dry run,
`false` otherwise. A read carries none, and neither does a controller record.
Readers use the key, not a `.dryRun` suffix on `krateo.action`. That suffix is
the writer's own literal, and snowplow keeps it.

## Marking the trace of a request that wrote a record

observability's tail sampler keeps a trace whole when its Server span carries
`krateo.audit.recorded=true` (`audit.SpanKeyRecorded`). `Emit` sets it once
the logger has taken a record:

- **An HTTP writer** wraps its handler with `audit.RecordedMiddleware`, placed
  inside the middleware that starts the Server span:

  ```go
  handler := otelhttp.NewHandler(audit.RecordedMiddleware(mux), "server")
  ```

  It installs a holder on the request context. Every `Emit` on that context, or
  on one derived from it (a stage's client span included), sets the holder.
  When the handler exits, by returning or by panicking, it marks the Server
  span.
- **A writer whose Server span is started elsewhere** does the same by hand:
  `ctx = audit.WithRecordedMarker(ctx)` where the Server span is active, then
  `audit.MarkRecorded(ctx, serverSpan)` before the span ends.
- **With no holder installed**, `Emit` sets the attribute on the span active
  on its `ctx`, while that span records. That is right when that span is the
  Server span, and wrong when it is a client span, which is why the holder
  exists.
- **A controller with no Server span** (rest-dynamic-controller) installs the
  holder at its reconcile's root span, `ctx = audit.WithRecordedMarker(ctx)`,
  and calls `audit.MarkRecorded(ctx, rootSpan)` before that span ends. The
  root span must still be recording when the reconcile emits. Emitting after
  the otelhttp client span has ended, with no holder, marks nothing.
- **What the code guarantees about a marker that may reach no trace.** With
  no holder and no recording span on `ctx` (no span, an ended one, or one
  that does not record), the record is still emitted, the miss is counted
  under `krateo.audit.recorded_marker.unattached{reason}` (`no_span` or
  `not_recording`), and one WARN per process names the key and the reason.
  With a holder, `RecordedMiddleware` marks the Server span whenever the
  handler exits, a panic included. A writer that calls `MarkRecorded` by hand
  gets the same only if it calls it before its span ends on every exit path
  (a `defer` placed after the span's own deferred `End`); nothing counts a
  holder that is set and never read.

The marker is a boolean, only ever `true`, and never carries identity.

## Adopting v0.4.0

v0.4.0 adds the schema and keeps every v0.3 field compiling. **A plain bump
keeps every record**: each one the caller emitted on v0.3 is still emitted,
with every attribute and value v0.3 wrote. On top of that:

1. **New keys are written beside the old ones** (W1): `krateo.audit.outcome`
   beside `outcome`, `krateo.audit.object_ref.*` beside `k8s.resource.*` and
   `k8s.object.*`. Readers of the old keys keep working. The release that
   closes W1 removes the old keys (v0.5.x still writes them). `enduser.id`
   is not added: it stays only where a caller sets `EndUserID`.
2. **Gaps are marked.** A record that lacks what its writer must write is
   emitted marked `krateo.audit.incomplete` (a v0.3 record with no actor:
   `actor`), and counted under `krateo.audit.records.incomplete{marker}`.

Then adopt the schema, per emit site, to clear the marks: set `WithActor`;
set `Verb`; set `Resource` (the plural) whenever the record names a
Kubernetes object; set `Preview` for every Kubernetes object (`false` for a
cluster-scoped one); move an affected
user to `AffectedUser`; replace an upstream error text in `Message` with a
closed-set text; and test the site (next section).

## Adopting v0.5.0

v0.5.0 is additive: a v0.4.0 record is still valid, a plain bump changes no
record, and the v0.3 keys are still written beside their replacements (W1
continues). It adds two keys a writer may now set
([schema.md](./schema.md)):

1. **`Event.Cause`** (`krateo.audit.cause_ref.*`, controllers only): the
   object the controller reconciled, while `Namespace`, `Group`, `Version`,
   `Resource`, `ObjectName` and `ObjectUID` now name the object it **wrote**.
   A v0.4 controller named the reconciled object in `object_ref`; move it to
   `Cause` and put the written object (or, for an external write, only
   `ServerAddress`) where it was. Set `Cause` on every record of a reconcile,
   with its `UID` and `Generation`: they are the join key.
2. **`Event.DenialReason`** (`krateo.audit.denial_reason`): why the writer
   itself refused, on an `OutcomeDenied` record only, spelled through the
   generated `audit.DenialReason*` constants. Each writer class has its own
   closed set: authn's name guard for `request`, `kept_resource_policy` for
   `controller`. A writer that needs a new value adds it to `schema/v1.yaml`
   in a minor release, never as free text.

authn writes as a `request` writer on the scope
`github.com/krateo-platformops/authn/audit`, and its background credential
writes as a `controller` writer on `github.com/krateo-platformops/authn/audit/controller`,
so the live queries report each apart.

## Testing a writer

Drive each emit site through the real SDK and assert the record conforms for
your writer class, then prove the check fails when the site stops writing a
key:

```go
rec := audittest.NewRecorder(t)
e := audit.New(rec.Logger("test/audit"), audit.WithActor(sa, audit.ClassController))
runTheEmitSite(ctx, e)
r := rec.Only(t)
audittest.AssertConformant(t, audit.WriterController, r)
audittest.AssertRequiredKeysDetected(t, audit.WriterController, r)
audittest.AssertEnumsDetected(t, audit.WriterController, r)
```

`AssertRequiredKeysDetected` removes each key `Check` requires of that record,
one at a time, and fails unless `Check` then reports it missing.
`AssertEnumsDetected` replaces each value the writer may only pick from a
closed set (the verb, the outcome, a denial reason) with one outside it, and
fails unless `Check` then reports it `bad-enum`. Both mutate the checker's
input, never its logic. A site that legitimately cannot establish a
key (a token minted before the principal claim) passes
`audittest.AllowIncomplete(audit.KeyActorClass)`.

A writer not written in Go validates its records with
`auditschema check -writer <class> records.json` (OTLP/JSON).

## Checking the live table

`auditschema sql` prints the conformance queries for `default.krateo_audit`,
generated from the same schema as `Check`:

- **required keys** per population (scope name × service × schema × class ×
  key), with `missing` and `missing_unmarked`. Controls: the impossible key
  `claude.no.such.key` must be missing on every row, and the pre-schema gateway
  rows (`ScopeName = 'request'`) must lack `event.name`;
- **rules** on schema-1 rows: unmet conditional keys, enums, the closed set,
  keys a writer cannot establish, the target rule, the W1 pairs, an affected
  user equal to the actor. Every column must be 0;
- **the leak detector**: no identity key on `otel_traces` or `otel_logs`, with
  `krateo_audit` as the positive control and an impossible-key rerun.

Run them read-only (`clickhouse-client --readonly 1`) with `--param_start` and
`--param_end`. Zero rows in a window is not conformance.

## Correlating a reconcile with the request that caused it

A reconcile has no inbound request, so there is no `session.id` in its baggage.
The link back to the person is the **object's identity**:

- the write that created or changed the object records its `uid`, `generation`
  and `resourceVersion`;
- the controller records the `uid` and the `generation` of the object it
  reconciled in `Event.Cause` (`krateo.audit.cause_ref.uid`,
  `krateo.audit.cause_ref.generation`: the object's `metadata.generation` as
  read at reconcile start; a status `observedGeneration` is not required),
  and the object it wrote in `object_ref`.

Joining the request row's `(krateo.audit.object_ref.uid,
krateo.audit.object_ref.generation)` to the controller row's
`(krateo.audit.cause_ref.uid, krateo.audit.cause_ref.generation)` in
`krateo_audit` ties the controller's write to the user's request and its
`session.id` ([schema.md](./schema.md) has the query). A controller row
written before v0.5.0 named the reconciled object in `object_ref` (or the v0.3
`k8s.object.uid`, `k8s.object.generation` during W1): a join over those rows
reads `object_ref` where `cause_ref` is absent.

- a DELETE's request row carries no generation, so a reconcile it caused
  joins on `uid` alone;

- a `kubectl` or GitOps write produces a generation with no request-side record,
  so it is correctly not attributed to anyone's session;
- a resync on an unchanged generation joins to the original write.

A controller that writes its own spec, or a CR without a status subresource, can
bump `generation` itself. Record the `resourceVersion` it read for an exact
match in those cases.
