---
type: Log
title: audit — log
description: Curated history of the audit package.
resource: github.com/krateo-platformops/audit
tags: [library, audit, log]
timestamp: 2026-11-12T00:00:00Z
---

# Log

- **2026-11-12**: v0.9.0 (audit#23). One optional key,
  `krateo.audit.check_result` (`Event.CheckResult`): what a check the writer
  ran concluded. Its closed set is declared per writer **and per action**
  (`actions:` on a writer's requirement, `Requirement.ActionValues`,
  generated `CheckResult*` constants), the way `denial_reason` is declared
  per writer. The first action is authn's `authn.username.check` (`POST
  /usernames/check`, which identity-lifecycle's AccessRequest controller
  calls so it can drop its RBAC on Secrets), request writer, with the set
  `available`, `reserved`, `name_claimed`, `name_held_legacy`,
  `name_provisioned`, `name_bound`, `invalid`. `Check` reports a value
  outside the record's action's set as `bad-enum`, and the key on an action
  that declares no set (or a record with no action) as the new reason
  `not-for-action`; every other writer class gets `not-for-writer`. The
  key appears only on a success, when the check ran: a new condition,
  `succeeded` (outcome `success`), is its `only_when`, so a failure (the
  lookup failed) or a denied record (the check never ran) carrying it is
  `unexpected`. One request denial reason for the same route,
  `username_check_not_allowed`: the caller's TokenReview passed but its
  mapping has not opted in (`spec.usernameCheck.allowed`), 403, naming the
  checked name's clientconfig Secret, with no status code and no check
  result. authn's other refusals there reuse v0.8.0's `no_mapping`,
  `ambiguous_mapping` and `not_a_service_account`, naming the mapping
  resource without a name. Compatibility: `testdata/v0.8.0/` holds records
  audit v0.8.0's own `Emit` wrote (gen, pinned to v0.8.0: the content hash,
  client provenance and its rejection, a delegated call, the denial reasons
  v0.6.0 to v0.8.0 added, a failure row, a kept deletion), with v0.8.0's own
  `auditschema` report on them; this release gives the same report.
  `auditschema sql` counts both (`bad_` and `not_for_action_` columns on the
  request writer's rules), and the column test runs them on fixture rows
  derived from the schema: every value of every action, a value outside the
  set, an action with no set, and no action. `audittest.AssertEnumsDetected`
  exercises per-action sets. The collector's `logs/audit` pipeline
  (observability@2d92f2b8) drops only attributes whose key names a
  credential (`authorization`, `cookie`) and redacts JWT-shaped values, so
  `krateo_audit` stores this key in `LogAttributes` with no observability
  change. Additive, so a minor version per docs/release.md.
- **2026-11-11**: v0.8.0 (audit#20, authn#132). The AUDIT-4 lead ruled that
  every refusal of an identity that has already verified gets a row. Six
  request-writer denial reasons for authn, each denied with no status code,
  with authn's own meanings (authn@9e352bde, quoted in schema/v1.yaml):
  - the step-up, after the ID token verified: `stepup_not_enabled` (step-up
    is not enabled for the OIDCConfig, `spec.stepUp`), `insufficient_assurance`
    (the ID token's acr is not one of the step-up's acr values), and
    `stale_authentication` (no `auth_time`, or older than the step-up's
    maxAge);
  - a ServiceAccount login, after the TokenReview authenticated the caller:
    `not_a_service_account` (the authenticated username is not a
    ServiceAccount's), `no_mapping` (no mapping admits the ServiceAccount, an
    allowlist miss), and `ambiguous_mapping` (more than one does). The two
    mapping records name the mapping resource without a name, like
    `name_missing`.

  Not denial reasons: `AudienceMismatch` is part of verification (a counted
  pre-verification refusal, no row). `MappingLookupFailed` is a failure row
  carrying the apiserver's code for the lookup when it answered, and none when
  nothing answered. `StepUpMisconfigured` is a failure row with no status
  code. `http.response.status_code` is the authority's answer, never authn's
  own HTTP status. Additive, so a minor version per docs/release.md.
- **2026-11-11**: v0.7.0 (audit#18). Two request-writer denial reasons for
  authn's `/delegate`, which verifies the actor but refuses the subject
  token. The caller's answer is one cause either way (401
  SubjectTokenInvalid); the record keeps the two apart, as denied with no
  status code. `subject_token_expired` (routine): the token verified but has
  expired, or expires within authn's 1 s margin. `subject_token_invalid`
  (security-relevant): the token did not verify (a bad signature, an unknown
  or retired kid, a key retired to revoke tokens included, malformed, a wrong
  alg, or no exp). plumbing's jwtutil returns only ErrTokenExpired and
  ErrTokenInvalid for authn's local key set, so there is no finer split.
  Additive, so a minor version per docs/release.md: no record that was valid changes.
- **2026-11-11**: schema v1 for v0.6.0 (audit#12, audit#13; AUDIT-4,
  installer#410). Backward compatible: a test replays records v0.5.0's own
  `Emit` wrote (`testdata/v0.5.0`, generated by `testdata/v0.5.0/gen` on
  v0.5.0) and expects v0.5.0's own `auditschema` report, beside the v0.4.0
  replay. One rule is tighter, and no compatibility record meets it:
  - **No status code on a denied record** (audit#13).
    `http.response.status_code` is `not_when: denied`, so `Check` and the
    live query (`unexpected_http_response_status_code`) report it there.
    Schema v1 always defined the key as the authority's answer and `denied`
    as the writer's own refusal; no v0.4.0 or v0.5.0 compatibility record
    that is denied carries a code. A writer that wrote one now fails its
    `Check`, which makes this a tightening rather than a pure addition. It
    ships in a minor release because the AUDIT-4 lead ruled that a denied
    record carries no code, and no compatibility record carries one.
  - `krateo.audit.object_ref.content_sha256` (`Event.ContentSHA256`): the
    tamper-evidence anchor of a `create` or `update` (condition
    `content_write`), `c1:` and the lowercase hex SHA-256 of the object's
    canonical content in form **c1**. The form is fixed before the tag
    because changing it would invalidate every stored hash: any later change
    is `c2`, and `Check` refuses a prefix other than `c1` (format
    `content_hash`). `audit.ContentSHA256(group, resource, subresource, obj)`
    computes it from the request body as sent: a ConfigMap's `data` and
    `binaryData`, any other object's top-level fields but `apiVersion`,
    `kind`, `metadata` and `status`; plus, for every kind,
    `metadata.annotations` kept to the declared authorization annotations
    (`AuthorizationAnnotations()`, schema `content_annotations`:
    `authn.krateo.io/strategy`, `authn.krateo.io/groups`, from authn's
    `storage.AuthorizationAnnotations`; plumbing's `helm/v3/verdicts.go`
    declares none); object members that are null left out at every depth;
    as canonical JSON (sorted keys, no whitespace, minimal escaping,
    integers only). [schema.md](./schema.md) defines c1 and a test vector
    that `TestContentSHA256_Vector` computes. **Never on a credential
    target**: the schema's new `credential_targets` (core `secrets` with any
    subresource, `serviceaccounts/token`, `tokenreviews.authentication.k8s.io`;
    the schema lists the kinds checked and left out) and a key's
    `credential_free` make `Check` report it there as `not-for-target`, and
    the live query count it (`not_for_target_...`); `ContentSHA256` refuses
    the same targets (`ErrCredentialTarget`).
  - `krateo.audit.client.*` (`Event.Client`, a `ClientProvenance`), the
    client-asserted provenance of snowplow#1333's `X-Krateo-Provenance`
    header: `source` (`portal`), `agent_session_id`, `confirmation_id`,
    `confirmed_set.{count,irreversible,sha256,op}`, `requested_at`, and
    `rejected` (`oversize`, `encoding`, `version`, `schema`). Asserted (the
    asserted prefixes are now `krateo.audit.asserted.` and
    `krateo.audit.client.`), never identity, marked or required, never a
    target; request and action writers, on a write only. `source` is
    required beside any other client key; the confirmed set's four keys come
    together and `op` is below `count`. With `rejected`, no other client key
    may be written (`not_when: client_rejected`), and `Emit` writes it
    alone.
  - Request denial reasons `delegation_not_allowed` and
    `delegation_too_deep` (authn's `/delegate` refusals, authn#123) and
    `platform_group` (an identity source asserted a `krateo:` group; not
    `system_group`, a Kubernetes `system:` group), and `name_missing` (an
    identity source verified an identity but returned no username: an OIDC
    claim absent or empty, an OAuth RESTAction with no username, an LDAP
    entry with no uid; authn refuses it with 403. The record is denied, has
    no status code, and names the Secret resource without a name. It closes
    the LOW from authn#123's review, which recorded the case as a failure).
  - Populations `github.com/krateo-platformops/access-review/audit` and
    `github.com/krateo-platformops/identity-lifecycle/audit`, controller;
    the shared `github.com/krateo-platformops/audit` row stays for the rows
    written before each moved.
  - Populations `github.com/krateo-platformops/composition-dynamic-controller/audit`
    and `github.com/krateo-platformops/core-provider/audit`, controller, for
    core-provider's emitters (module paths from each go.mod). The cdc runs
    one Deployment per CompositionDefinition version, so its rows are
    selected by scope, not ServiceName; a population's new `note` says so
    under the table in [schema.md](./schema.md).
  - [schema.md](./schema.md): the generation range join (a reconcile at
    generation *G* covers the request writes in (*P*, *G*], *P* its
    previous reconcile's generation; every one is returned, none is picked)
    and the decider of a decision (acmp's Q6: no key; the actor of the
    request rows the join returns). The query is documentation; it is not
    run by a test.
  - Schema grammar: `not_when`, `credential_free` with `credential_targets`,
    `minimum` and `less_than` on an int key, the formats `sha256_hex`, `content_hash`,
    `uuid`, `opaque_id` and `rfc3339`. `Check` gains the reasons
    `not-for-target` and `out-of-range`; `KeySpec` gains `NotWhen`,
    `CredentialFree`, `Min` and `LessThan`. The generator refuses an unknown
    `not_when`, `not_when` equal to `only_when`, an unprefixed or repeated content annotation, `credential_free` with no
    targets, a format or bound on the wrong type, `less_than` naming no
    other int key, and an asserted key that is required, marked or a target.
  - docs/coverage.md is unchanged: its rows describe merged code, and
    access-review and identity-lifecycle still emit on the shared scope.
- **2026-11-11**: [coverage.md](./coverage.md), the cross-component audit
  inventory (audit#9; AUDIT-4, installer#410). One row per mutating path per
  component, in one table per writer class and one for the paths no writer
  records: what changes, the writer class, where the identity comes from,
  the status (audited, audited and non-conformant, not audited, or out of
  scope with its reason), the owner issue, and the scope, `krateo.action`,
  verb and outcomes where they are known. It covers snowplow, authn, the
  agent path (gateway, cert-replay-hop, kagent tools), the controllers (cdc,
  core-provider, rest-dynamic-controller, oasgen-provider, access-review,
  identity-lifecycle), the installer, the frontend and the readers. The
  2026-11-09 boundary rulings, the exclusions and the stated limit are
  written once; the kept deletion is the v0.5.0 key
  `denial_reason=kept_resource_policy`. A status describes merged code
  only. An owner's emit-site PR updates its rows in the same change. The
  page names no identity, not even a placeholder.
  `TestCoverage_EveryRowMeetsTheAcceptance` fails when a row has no owner
  issue or no out-of-scope reason, a writer class or status outside the
  closed sets, a scope that is not a population of its own writer in
  `schema/v1.yaml`, or an audited path with no scope, and when the page
  holds a placeholder such as `<user>`. Docs and a test only; no code or
  schema change.
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
    constants). `request`: authn's refusals, its name guard
    (`name_reserved`, `name_claimed`, `name_held_legacy`,
    `name_provisioned`, `name_bound`, `system_group`) and its OIDC
    `allowedGroups` gate (`group_not_allowed`: a verified identity in none
    of the admitted groups, 403 GroupNotAllowed); `controller`: `kept_resource_policy`, a delete helm
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
  - Go API: `audit.Requirement` gains `Values []string`, so it is no longer
    comparable with `==` (a struct holding a slice). No record changes; a
    caller that compared two `Requirement`s compares their fields instead.
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
    `k8s.object.*`). v0.5.0 removes the v0.3 keys (postponed: see
    2026-11-11). `enduser.id` is written only when the caller sets
    `EndUserID`, as in v0.3, and never added;
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
