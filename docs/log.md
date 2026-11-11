---
type: Log
title: audit — log
description: Curated history of the audit package.
resource: github.com/krateo-platformops/audit
tags: [library, audit, log]
timestamp: 2026-11-11T00:00:00Z
---

# Log

- **2026-11-11**: schema v1 gains two keys, for v0.5.0 (audit#8, audit#10;
  AUDIT-4, installer#410). Additive: every v0.4.0 record stays valid (a test
  replays records v0.4.0's own `Emit` wrote and expects v0.4.0's own check
  report), and the v0.3 keys are still written beside their replacements: W1
  now closes in a later release, not in v0.5.0.
  - `krateo.audit.cause_ref.{api_group,api_version,resource,namespace,name,uid,generation}`
    (`Event.Cause`, a `CauseRef`): the object a controller **reconciled**,
    while `object_ref` names the object it **wrote**. Controller only (every
    other writer: not applicable); optional, and once a row names a cause its
    `api_version`, `resource`, `name` and `uid` are required. snowplow joins
    a controller row to the request that caused it on `cause_ref.uid` /
    `generation` = the request row's `object_ref.uid` / `generation`
    ([schema.md](./schema.md) has the query).
  - `krateo.audit.denial_reason` (`Event.DenialReason`): why the writer
    itself refused, only on a `denied` record (anywhere else `unexpected`),
    from a closed set **per writer class** (`values:` on a writer's
    requirement, `Requirement.Values`, generated `DenialReason*`
    constants). `request`: authn's name guard (`name_reserved`,
    `name_claimed`, `name_held_legacy`, `name_provisioned`, `name_bound`,
    `system_group`); `controller`: `kept_resource_policy`, a delete helm
    declined because of `helm.sh/resource-policy: keep` (verb `delete`,
    outcome `denied`). The kept deletion is that key, not a body value:
    `Check` reads attributes only.
  - authn is a `request` writer (the class now reads "a request a component
    served for a caller"), on its own scope
    `github.com/krateo-platformops/authn/audit`, with its background writes
    on `github.com/krateo-platformops/authn/audit/controller`. The generator
    refuses a scope listed twice: the live queries judge a scope's rows by
    the one writer it is listed under.
  - `audittest.AssertEnumsDetected`, the falsifier for the closed sets.
  - [schema.md](./schema.md) shows the kept-deletion and pruned-child
    records as Go literals, copied by the generator from
    `contract_records_test.go`, whose tests emit and check them.
  - The generator refuses a requirement field it does not know. That found
    the `when` texts of three keys, which the YAML had cut at a comma ("a successful,
    non-dry-run write" read as "a successful"); they are quoted now. The
    texts are descriptive only: no rule changed.
- **2026-11-09**: audit schema v1 (installer#716), for v0.4.0.
  `schema/v1.yaml` is the one record contract: every attribute, its type and
  semconv status, and per writer class (request, gateway, action, controller)
  whether it is required, conditional, optional, not established or not
  applicable. `go generate` turns it into the `Key*` constants, the checker's
  rule table and [schema.md](./schema.md); a test fails when they are stale.
  New: `Check`/`CheckRecord`/`RequiredKeys`, `ParseClaim`, `Sanitize`,
  `WithLegacyKeys`, the `audittest` package and `cmd/auditschema`. `Emit` now:
  - **never drops a record**: one that lacks a key its writer must write is
    emitted without it, marked in `krateo.audit.incomplete` and counted under
    `krateo.audit.records.incomplete{marker}`. A record that names no actor is
    marked `actor`. `WithActor` sets the actor of a controller or tool
    executor. A caller that only bumps keeps every record and every attribute
    it emitted on v0.3;
  - sets the LogRecord EventName and Timestamp, and stamps
    `krateo.audit.schema_version=1`;
  - writes the new keys (`krateo.audit.outcome`, `krateo.audit.object_ref.*`,
    `krateo.audit.actor_class`, `verb`, `preview`, delegation, impersonation,
    `affected_user`, the request facts) and, during migration window W1, the
    v0.3 keys beside them with the same value (`outcome`, `k8s.resource.*`,
    `k8s.object.*`). v0.5.0 removes the v0.3 keys. `enduser.id` is written
    only when the caller sets `EndUserID`, as in v0.3, and never added;
  - makes every string valid UTF-8, at any depth (snowplow#1261: one invalid
    string made the OTLP exporter drop the whole batch);
  - writes `user.roles` as a string slice (an OTLP array of strings, as
    before), and an HTTP method semconv does not name (lowercase included)
    as `_OTHER`, with the method as given in `http.request.method_original`,
    so no v0.3 value is lost;
  - requires `krateo.audit.preview` for every Kubernetes target, `false` for
    a cluster-scoped one (installer#716 §2.4);
  - writes `krateo.audit.dry_run` (AUDIT-9). It is `true` from `Event.DryRun`,
    and `false` on the other write records of a declared request or action
    writer. Never on a read or a controller record, and never added to a v0.3
    caller's records;
  - marks the request recorded for the tail sampler,
    `krateo.audit.recorded=true` on its Server span, once the logger has
    taken a record. Through a `WithRecordedMarker` holder and
    `RecordedMiddleware`, or on the active span when no holder is installed
    and that span records. A marker that reaches no trace (no holder, and no
    span, an ended one or one that does not record) is counted under
    `krateo.audit.recorded_marker.unattached{reason}` and logged once per
    process at WARN; the record is still emitted.
  Every v0.3 field and constant still compiles; `Event.EndUserID` is
  deprecated.
- **2026-10-29**: requires Go 1.26 (`go 1.26.0`, was 1.25.6), and the module's
  own builds use `toolchain go1.26.10`. At go1.25.6, `govulncheck` reports seven
  standard-library vulnerabilities (`net/http`, `crypto/x509`, `net/url`) that a
  patched toolchain doesn't have; with go1.26.10 it reports none. Consumers
  should build with Go ≥ 1.26.10. No dependency, API or behaviour change.
- **2026-10-29**: `Emit` reduces `ServerAddress` to host[:port] before writing
  `server.address`. It drops any scheme, userinfo, path, query and fragment, so
  a caller that passes a full URL no longer writes the path or query (which can
  carry a token) into the 365-day trail. A value with no parseable host is
  omitted, never written raw. The API is unchanged; the emitted value changes
  only for callers that passed more than host[:port].
- **2026-10-29**: builds on the Logs API from `go.opentelemetry.io/otel/log`
  v0.21.0 onward. v0.21.0 moved the record value types (`KeyValue`, `Value`,
  `String`, `Int64`, ...) to `go.opentelemetry.io/otel/attribute`, so v0.1.0 did
  not compile in any program that used `otel/log` v0.21 or later, including the
  stable v1.47. The module now requires the lowest version that has the new
  types (otel v1.45.0, log and sdk/log v0.21.0), so consumers keep their own
  versions. CI builds and tests the package with `otel/log` v0.21.0, v0.22.0 and
  v1.47.0. The emitted record is unchanged: same attribute names, types and
  values.
- **2026-10-28**: initial version. Lifted from the identical emitters in the
  user-lifecycle and access-review controllers, and extended with the object
  identity fields (`k8s.object.uid`, `k8s.object.generation`,
  `k8s.object.resource_version`), `server.address` and
  `k8s.resource.subresource`. Tests run the real OTel Logs SDK pipeline.
