---
type: Usage
title: audit — usage
description: Install the package, when and how to emit, who the actor is, adopting v0.4.0, v0.5.0, v0.6.0, v0.7.0, v0.8.0, v0.9.0, v0.10.0, v0.11.0, v0.12.0, v0.13.0 and v0.14.0, testing a writer against the schema, and checking the live table.
resource: github.com/krateo-platformops/audit
tags: [library, audit, usage]
timestamp: 2026-11-12T00:00:00Z
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

## Adopting v0.6.0

A v0.5.0 record is still valid (a test replays records v0.5.0's own `Emit`
wrote and expects v0.5.0's own check report), and a plain bump changes no
record. One rule is tighter, as the schema already defined it:

1. **No status code on a denied record.** `denied` means the writer itself
   refused, so no authority answered and there is no
   `http.response.status_code`. `Check` now reports one there as
   `unexpected`. Leave `StatusCode` at 0 on an `OutcomeDenied` Event.

What a writer may now set ([schema.md](./schema.md)):

2. **`Event.ContentSHA256`** (`krateo.audit.object_ref.content_sha256`): on a
   `create` or `update` that writes content, the `c1:<hex>` value
   `audit.ContentSHA256(group, resource, subresource, obj)` returns for the
   request body as sent, with the target as `object_ref` names it. Never for
   a credential target (a Secret, a token request or review):
   `ContentSHA256` refuses it (`ErrCredentialTarget`) and `Check` reports the
   key there as `not-for-target`.
3. **`Event.Client`** (`krateo.audit.client.*`, request and action writers):
   what the portal asserted in its provenance header, after the writer
   validated it. Set `Client.Rejected` instead when the header was rejected;
   `Emit` then writes it alone.
4. **Four request denial reasons** for authn: `DenialReasonDelegationNotAllowed`
   and `DenialReasonDelegationTooDeep` for `/delegate`;
   `DenialReasonPlatformGroup` for an identity source that asserted a
   `krateo:` group; and `DenialReasonNameMissing` for a verified identity
   that came back with no username. Each is a denied record with no status
   code. A `name_missing` record names the Secret resource but no Secret.

access-review and identity-lifecycle each emit on their own scope,
`github.com/krateo-platformops/access-review/audit` and
`github.com/krateo-platformops/identity-lifecycle/audit`. The shared scope
`github.com/krateo-platformops/audit` stays a controller population for the
rows written before the move.

## Adopting v0.7.0

v0.7.0 is additive. It gives authn's `/delegate` a reason for refusing a
subject token after the actor verified: `DenialReasonSubjectTokenExpired`
(the token has expired, or expires within authn's 1 s margin) and
`DenialReasonSubjectTokenInvalid` (the token did not verify). Both go on a
denied record with no status code; the caller still gets one 401.

## Adopting v0.8.0

v0.8.0 is additive. Every refusal of an identity that has already verified
is a denied record with a closed reason and no status code. It adds six,
for authn:

- the step-up, after the ID token verified: `DenialReasonStepupNotEnabled`
  (step-up is not enabled for the OIDCConfig), `DenialReasonInsufficientAssurance`
  (the ID token's acr is not one of the step-up's acr values) and
  `DenialReasonStaleAuthentication` (no `auth_time`, or older than the
  step-up's maxAge);
- a ServiceAccount login, after the TokenReview authenticated the caller:
  `DenialReasonNotAServiceAccount` (the username is not a ServiceAccount's),
  `DenialReasonNoMapping` (no mapping admits the ServiceAccount) and
  `DenialReasonAmbiguousMapping` (more than one does). The two mapping
  records name the mapping resource without a name.

An audience mismatch is part of verification, so it never gets a row.
Failures after verification are `failure` rows, not denials, and their
status code is the authority's answer, never authn's own HTTP status. A
failed mapping lookup carries the apiserver's code when the apiserver
answered, and no code when nothing answered. A misconfigured step-up
carries no status code.

## Adopting v0.9.0

v0.9.0 is additive: a plain bump changes no record. It adds one optional
key, **`Event.CheckResult`** (`krateo.audit.check_result`): what a check
the writer ran concluded, on a record whose `Action` is a check. Its closed
set is declared **per action** in `schema/v1.yaml` (a requirement's
`actions:`), not per writer, and spelled through the generated
`audit.CheckResult*` constants.

The first action is authn's `authn.username.check` (`POST
/usernames/check`, audit#23): a request record, verb `get`, targeting the
clientconfig Secret the name guard protects, outcome `success` whenever the
check completed and `failure` when a lookup failed, never `denied`. Its set
is `CheckResultAvailable`, `CheckResultReserved`,
`CheckResultNameClaimed`, `CheckResultNameHeldLegacy`,
`CheckResultNameProvisioned`, `CheckResultNameBound` and
`CheckResultInvalid`. authn owns each value's meaning.

The key appears **only on a success**, when the check ran (a new condition,
`succeeded`, as its `only_when`). A `failure` (the lookup failed) and a
`denied` record (the check never ran) carry none; `Check` reports it there
as `unexpected`.

authn's refusals on this action are denied records with no status code and
no check result:

- `DenialReasonUsernameCheckNotAllowed` (`username_check_not_allowed`, new):
  the caller's TokenReview passed, but its mapping has not opted in
  (`spec.usernameCheck.allowed`), so authn answers 403. The record names the
  checked name's clientconfig Secret.
- v0.8.0's `DenialReasonNoMapping`, `DenialReasonAmbiguousMapping` and
  `DenialReasonNotAServiceAccount`, which name the mapping resource without
  a name, as on `/delegate`. A denial reason is the request writer's on any
  action, so the schema allows them here unchanged.

`Check` reports a value outside the set of the record's action as
`bad-enum`, and the key on any action that declares no set (a record with
no `krateo.action` included) as the new `not-for-action`. Every writer
class other than `request` cannot write it (`not-for-writer`). An action
gains a value, or the key gains an action, in a minor release.

## Adopting v0.10.0

v0.10.0 is additive: a plain bump changes no record. It adds two request
denial reasons (audit#29).

`DenialReasonNameNotIssued` (`name_not_issued`) is for a sign-in whose
username an identity source chose and authn would issue in another form, one
the clientconfig Secret's name derivation would rewrite (authn#141 at `2fb07895`, `internal/helpers/kube/config/guard.go:57-65`, `:126`, `:143-152`).
An administrator-provisioned name (a basic User, a ServiceAccount mapping) is
not refused: it keeps signing in, and its records stay nameless under the
same naming rule (authn#140). The record is denied, with no status code and
no `check_result`, and names the Secret resource without a name: the derived
name would be another username's (coverage.md, "Naming a derived credential
Secret").

`DenialReasonInvalidRequest` (`invalid_request`) is for authn's
`authn.username.check`: a verified, mapped and opted-in caller
sent a body with no username, or one that isn't JSON, so authn answers 400
and the check never runs. The record is denied, with no status code and no
`check_result`. With no username it names the Secret resource without a
name, as `name_missing` does. Like every denial reason, both are the request
writer's alone: `Check` reports it `bad-enum` on a controller and
`not-for-writer` on the gateway and action writers.

## Adopting v0.11.0

v0.11.0 adds API and changes no record or rule. The schema's value formats are
exported validators, generated from schema/v1.yaml (audit#32):
`audit.ValidOpaqueID(s)` and one `Valid*` per format, the generic
`audit.ValidFormat(format, s)`, and `audit.ValidValue(key, s)`, which applies
a key's declared format and returns a `*FormatError` naming the key and the
format, never the value. `Check` uses exactly these.

A writer that takes a value from an untrusted source validates it with them
before writing it, and drops any copy of a pattern it keeps (authn, snowplow,
the gateway).

**One rule tightens: `session.id` is now of format `session_id`**, 1 to 128
of `[A-Za-z0-9._-]` (`audit.ValidSessionID`). Until v0.11.0 any value
passed. The shape is snowplow's, the id's origin: its minted ids (16 hex
characters, or the request's trace id) and identity-lifecycle's (a UUID) fit
it, and dots are safe in baggage and on a log line. `Check` now reports any
other `session.id` as `bad-format`, on every writer that writes it. A writer
that takes the id from inbound baggage refuses a value that isn't of this
format (`ValidSessionID`, or `ValidValue(KeySessionID, s)`) and mints its
own instead.

**Emit never writes an invalid inbound `session.id`.** A baggage `session.id`
that isn't of format `session_id` is left out of the record, per writer:
- the request writer must establish a valid id, so with none on the context
  Emit omits the key and marks it `session` in `krateo.audit.incomplete` (the
  key is markable for it from v0.11.0): the gap is stated, never filled with
  a value `Check` would refuse;
- for the gateway and action writers the key is conditional on inbound
  baggage carrying a `session_id`-formatted value, so a malformed client
  value is refused input, not a gap: Emit omits it plainly, with no marker.
 A writer that wants an id on the
record puts a valid one on the context first, as authn's request middleware
does: it keeps a valid inbound id and mints one otherwise. Every `session.id` that v0.4.0, v0.5.0, v0.8.0, v0.9.1 and
v0.10.0 wrote in this module's compatibility fixtures is of the format.

## Adopting v0.12.0

v0.12.0 is additive (audit#22): a plain bump changes no record.

- **Which endpointRef a stage dialled through.** `Event.EndpointRefNamespace`
  and `Event.EndpointRefName` (`krateo.audit.endpoint_ref.*`, request writer,
  optional), only on a record whose target is `ServerAddress`; `Check`
  reports them anywhere else as `unexpected`. They name the Endpoint
  reference, never credential data. The name is never a per-user clientconfig
  Secret's (one ending in `-clientconfig` or `-clientconfig-stepup` embeds a
  username): `Check` reports it `bad-format`, and `Emit` never writes it.
- **A non-resource path as the target.** `Event.URLPath` (`url.path`, OTel
  semconv) is the request writer's third target form, for a route it served
  that names no object and no endpoint, such as snowplow's
  `POST /debug/shadow-parity` (action `debug.shadowParity`, verb `post`). The
  request writer's target rule is now exactly one of `object_ref`,
  `server.address` and `url.path`; `TargetRule.KeysFor(w)` lists a writer's
  target keys. Every other writer keeps its two, and `url.path` there is
  `not-for-writer`.
- **snowplow's refusals.** Twelve request denial reasons, each a denied
  record with no status code: `destination_refused`,
  `per_user_credential_ref`, `endpoint_ref_malformed`,
  `internal_identity_context`, `write_refused`, `dry_run_not_executed`,
  `dependency_failed`, `uaf_on_write_verb`, `invalid_path`, `template_error`,
  `session_credential_missing`, `step_up_required` (schema/v1.yaml cites
  each refusal site in snowplow). A refusal before the endpoint is resolved
  may know no address: the record marks `target` rather than invent one.
  `per_user_credential_ref` never names the Secret it refused.
  `write_refused` is written only when the refused write had a requester:
  in snowplow, an export's read (snowplow#970). Background work has none and
  writes no record (snowplow#1381). Not denials: a
  Secret the apiserver answered NotFound or Forbidden for, a page-budget
  cut, and a refused 3xx redirect stay failures with the authority's code.
- **A controller's own actor.** `audit.ControllerActor()` returns
  `system:serviceaccount:<namespace>:<name>` from the downward-API variables
  `audit.EnvPodNamespace` (`POD_NAMESPACE`) and `audit.EnvPodServiceAccount`
  (`POD_SERVICE_ACCOUNT`), and `""` when either is unset or is not a name
  Kubernetes gives (a DNS-1123 label for the namespace, a DNS-1123
  subdomain for the ServiceAccount). With `""`, pass no `WithActor`: every
  record is then marked `actor`, and names no principal it is not.
  `audit.ServiceAccountActor(namespace, name)` is the same rule on values
  in hand. It replaces each controller's own copy (access-review and
  identity-lifecycle carry one). The chart sets both from the pod's own
  fields, and should refuse an override of either (an `extraEnv` entry, say):

  ```yaml
  env:
    - name: POD_NAMESPACE
      valueFrom:
        fieldRef:
          fieldPath: metadata.namespace
    - name: POD_SERVICE_ACCOUNT
      valueFrom:
        fieldRef:
          fieldPath: spec.serviceAccountName
  ```

  ```go
  opts := []audit.Option{audit.WithWriter(audit.WriterController)}
  if actor := audit.ControllerActor(); actor != "" {
  	opts = append(opts, audit.WithActor(actor, audit.ClassController))
  }
  emitter := audit.New(logger, opts...)
  ```

## Adopting v0.13.0

v0.13.0 is additive: a plain bump changes no record and no content hash.
A content comparator that takes `audit.AuthorizationAnnotations()` now also
counts `authn.krateo.io/username`.

- **Authorization-bearing labels.** `audit.AuthorizationLabels()` returns
  `authn.krateo.io/principal` and `authn.krateo.io/username-label`, which
  authn will stamp on every session Secret (planned, per authn#144, behind
  `exactUsernames.enabled`, off by default) and which acmp's tenant
  onboarding reads. It sits beside
  `audit.AuthorizationAnnotations()`, and both are generated from one
  schema list, `authorization_metadata`, where each entry declares its
  kind, its key and why it is content.
- **One more authorization annotation.** `audit.AuthorizationAnnotations()`
  adds `authn.krateo.io/username` (plumbing v1.58.0's
  `endpoints.UsernameAnnotation`): the exact username a session Secret
  holds the credential of, by which a reader proves the Secret is the
  requester's (`endpoints.OwnsSecret`; snowplow#1382, planned, will read
  it so). acmp's tenant onboarding requires the session Secret's name to
  equal the annotation's value + `-clientconfig`. authn will stamp it on
  every session Secret (planned, per authn#144, behind
  `exactUsernames.enabled`, off by default).
- **What content is.** The desired state (coverage.md, boundary ruling 1)
  plus the declared annotations and labels, compared by key and value. A
  write that changes a declared annotation or label, adds it or removes it
  is a content change; an undeclared one is metadata; a key counts only as
  the kind it is declared as. The comparator is plumbing's
  `kubeutil/content`, which takes both lists from v1.59.0
  (`content.DiffersWith`, `content.Keys`). `content.Differs` is unchanged
  and counts the annotations only, so a writer moves to `DiffersWith` to
  count the labels:

  ```go
  import (
  	"github.com/krateo-platformops/audit"
  	"github.com/krateo-platformops/plumbing/kubeutil/content"
  )

  // before and after are runtime.Object values, the object as it was and as the write leaves it.
  changed, err := content.DiffersWith(before, after, content.Keys{
  	Annotations: audit.AuthorizationAnnotations(),
  	Labels:      audit.AuthorizationLabels(),
  })
  ```

  `content.CanonicalWith(obj, keys)` is the form it compares.
- **Testing a comparator.** `audittest.AuthorizationMetadataCases()` is the
  rule as cases, derived from the schema: run each `Before` and `After`
  through the comparator (as `&unstructured.Unstructured{Object: c.Before}`
  for `DiffersWith`), and its verdict must be `Changed`.
- **The content hash.** Form c1's key set is frozen:
  `audit.ContentFormC1Annotations()`, v0.12.0's two annotations
  (`authn.krateo.io/strategy`, `authn.krateo.io/groups`), and no label. It
  is not `audit.AuthorizationAnnotations()`, so declaring
  `authn.krateo.io/username` (or any later key) never changes a c1 hash. A
  comparator counts every declared key, so it can report a content change
  that c1 does not hash. To check a c1 hash against the annotations,
  compare `ContentFormC1Annotations()`. Hashing another key set is a new
  form, c2. The new keys' carrier, the session Secret, is a credential
  target, which carries no content hash.
- **The writer's own RBAC refusal.** `audit.DenialReasonRbacNotAllowed`
  (`rbac_not_allowed`), a request denial reason: the writer itself
  evaluated Kubernetes RBAC for a verified caller and refused before its
  handler ran and before any dial for the request. With the cache off the
  evaluation is a SelfSubjectAccessReview, still the writer's own decision.
  A denied record with no status code. In snowplow, DebugAuthz
  refusing `POST /debug/shadow-parity` (schema/v1.yaml cites the sites).
  An authority's 403, such as the apiserver answering 403, is not this
  reason: it stays a failure with the authority's status code.

## Adopting v0.14.0

v0.14.0 is additive: a plain bump changes no record and no content hash.

- **A username check's claimant.** `authn.username.check` gains two
  results, `audit.CheckResultNameClaimedByClaimant` and
  `audit.CheckResultNameClaimedByAnother`: the name is claimed, and the
  claim is (or is not) the claimant's, the identity the request said it
  expects (authn#146, pending merge). The writer's obligation, which
  `Check` can't verify because it never sees the request: write these two
  only when the request carried a claimant, and bare `name_claimed` only
  when it didn't. Never record the claimant's identity.
- **A kept value.** A controller that declines to overwrite an
  authorization-bearing annotation or label an object already holds with
  another value writes a denied `update` with
  `audit.DenialReasonKeptExistingValue` and the key it kept in
  `Event.AuthorizationKey` (`krateo.audit.authorization_key`), one record
  per key, never a value, no status code:

  ```go
  key, ok := audit.AuthorizationKeyValue(audit.MetadataKindAnnotation, "authn.krateo.io/username")
  if ok {
  	e.Emit(ctx, audit.Event{Action: "authn.identity.inconsistent", Verb: "update", HTTPMethod: "PUT",
  		Outcome: audit.OutcomeDenied, DenialReason: audit.DenialReasonKeptExistingValue, AuthorizationKey: key,
  		Namespace: ns, Version: "v1", Resource: "secrets", Kind: "Secret", ObjectName: name, Preview: preview})
  }
  ```

  The key's closed set is generated from `authorization_metadata`
  (`<kind>:<key>`), so it grows with that list. `Check` reports the key
  without the reason as `unexpected` and the reason without the key as
  `missing`. First user: authn's startup backfill (authn#147, pending
  merge).
- **Naming a derived credential Secret** ([coverage.md](./coverage.md)) now
  applies to refusals and username checks only: a successful write names
  the Secret it wrote.
- **oasgen-provider's population**,
  `github.com/krateo-platformops/oasgen-provider/audit` (controller), for
  its RBAC and admission-policy writes (oasgen-provider#543). A new scope is
  the emitting module's path plus `/audit`; rest-dynamic-controller's bare
  `rest-dynamic-controller/audit` is a historical exception.

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
