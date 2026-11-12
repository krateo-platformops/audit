---
type: Log
title: audit — log
description: Curated history of the audit package.
resource: github.com/krateo-platformops/audit
tags: [library, audit, log]
timestamp: 2026-11-12T00:00:00Z
---

# Log

- **2026-11-12**: v0.12.0 (audit#22, for snowplow#1283 and snowplow's
  adoption). Additive.
  - `krateo.audit.endpoint_ref.{namespace,name}` (`Event.EndpointRefNamespace`,
    `EndpointRefName`), request writer, optional: the endpointRef a
    RESTAction stage dialled `server.address` through. Only when
    `server.address` is the target (a new condition, `endpoint_target`), and
    credential-free. New formats `k8s_namespace` (a DNS-1123 label) and
    `endpoint_ref_name` (1 to 253 of `[a-z0-9.-]`, never a per-user
    clientconfig Secret's name: one ending in `-clientconfig` or
    `-clientconfig-stepup` embeds a username). `Emit` never writes such a
    name.
  - `url.path` (`Event.URLPath`, OTel semconv; format `url_path`, `/` and up
    to 1000 more, no query, fragment or whitespace): the request writer's
    third target form. The target rule gains `writer_keys` (request:
    `url.path`), `TargetRule.WriterKeys` and `KeysFor(w)`. `Check`, the
    marker logic, the falsifier and the live SQL count a writer's own
    target keys; `two_targets` is now any pair. Every other writer keeps
    `object_ref` and `server.address`, and `url.path` is `not-for-writer`
    there. First user: snowplow's `POST /debug/shadow-parity`, whose literal
    `debug.shadowParity` joins the registry.
  - The request writer's denial reasons gain snowplow's twelve, each cited
    in schema/v1.yaml at snowplow `219a076e`: `destination_refused`,
    `per_user_credential_ref`, `endpoint_ref_malformed`,
    `internal_identity_context`, `write_refused`, `dry_run_not_executed`,
    `dependency_failed`, `uaf_on_write_verb`, `invalid_path`,
    `template_error`, `session_credential_missing`, `step_up_required`. A
    refusal before resolution may know no address and marks `target`; a
    NotFound or Forbidden Secret, a page-budget cut and a refused redirect
    stay failures.
  - [coverage.md](./coverage.md): the Exclusions no longer say every
    snowplow 401 is pre-verification. The pre-verification causes
    (TokenMissing, TokenInvalid, TokenExpired, KeyNotPublished) are counted;
    a verified caller refused for a missing session or step-up credential
    gets a row.
  - The registry accepts camel-case words in a literal (`call.dryRun`,
    `debug.shadowParity`). The SQL column-count test now matches whole
    aliases, since `endpoint_ref.name`'s prefixes `endpoint_ref.namespace`'s.
  - Compatibility: `testdata/v0.11.0/` (25 records audit v0.11.0's own `Emit`
    wrote) gives v0.11.0's own report, and every earlier replay is
    unchanged.
- **2026-11-12**: v0.11.0 (audit#32, for authn#139). The schema's value
  formats become exported validators, generated from a new `formats:`
  section of schema/v1.yaml (id, Go name, description, and the pattern when a
  regular expression states the whole rule): `ValidOpaqueID` and one
  `Valid*` per format, `ValidFormat(format, value)`, `ValidValue(key,
  value)` (a `*FormatError` that names the key and format, never the value;
  `ErrUnknownKey` for an undeclared key) and `Formats()`. `Check` applies a
  key's format through `ValidFormat`, element by element for a string list;
  the check.go regexes are gone, and a test fails if any declared pattern is
  copied into another file of the module. The generator refuses an
  undeclared format, an unanchored or invalid pattern, and a repeated or
  undescribed format; docs/schema.md's format list comes from the YAML.
  Tests: every declared format has its rule and generated validator; one
  table (an email, a newline inside and at either end, 128 and 129
  characters, empty, unicode, and each format's boundaries) runs through
  `Check` and every export, and they agree; every element of a list is
  checked. **One rule tightens** (the AUDIT-4 lead's ruling, 2026-11-12):
  `session.id` declares the new format `session_id`, 1 to 128 of
  `[A-Za-z0-9._-]` (`ValidSessionID`), where any value passed before. The
  shape is snowplow's (it accepts and mints it), and identity-lifecycle's
  UUIDs fit it; `Check` reports any other value as `bad-format` on every
  writer of the key. Its rows: a dotted id, a UUID, 16 hex characters, a
  trace id, 128 and 129 characters, empty, whitespace, `;`, `,`, `=`,
  non-ASCII, an email. Every `session.id` in the v0.4.0, v0.5.0, v0.8.0,
  v0.9.1 and v0.10.0 compatibility fixtures (65 values) is of the format,
  and every replay gives its version's own report. Compatibility:
  `testdata/v0.10.0/` holds 25 records audit v0.10.0's own `Emit` wrote,
  and this release gives v0.10.0's own report. New API and one tightened
  rule that no recorded writer's output breaks: a minor version per
  docs/release.md, under its tightening rule (added in this release).

  **The tightening, and each registered writer's status** (the release
  note docs/release.md asks for):
  - `session.id` must be of format `session_id`; it was any value.
  - authn: conformant. It keeps a valid inbound id and mints one otherwise
    (authn#139 at `498828bf`, `internal/auditlog/middleware.go:52-63`; a
    minted id is 32 lowercase hex, `:74-78`).
  - snowplow, `internal/support/audit`: conformant. Its accepted shape is the
    same pattern, at most 128 characters (snowplow `219a076e`,
    `go/snowplow/internal/support/audit/audit.go:88-96`).
  - this library's `Emit`: conformant by construction. It never writes an
    invalid inbound `session.id`; it omits it and marks it `session`, with
    the key markable for the request writer. Proved by
    `TestEmit_InvalidInboundSessionIDIsOmittedAndMarked`,
    `TestEmit_InvalidInboundSessionIDConformsMarked` and the fuzz test
    `FuzzEmit_RecordPassesItsOwnCheck` (for any inbound value, the record
    passes its own `Check`).
  - observability's gateway projection: conformant. It copies
    `baggage_session` into `session.id` only when the value matches the
    format, and otherwise writes nothing and sets no marker
    (krateo-platformops/observability `6f5c2b15603a9166d8d1ad5fdcc6e20ed1ca8825`,
    "write session.id only in the session_id format (0.1.29)", #166,
    `charts/otel-collector-daemonset/values.yaml:621`). The earlier 0.1.28
    copied any non-empty value (`a73bda4`, `values.yaml:616`), so an inbound
    value outside the format would have become a `session.id` that `Check`
    reports `bad-format`.
  - The gateway and action writers' `session.id` is conditional on inbound
    baggage carrying a `session_id`-formatted value: a malformed client
    value is omitted plainly, with no marker. Only the request writer's
    missing id is marked `session`.
  - The compatibility fixtures v0.4.0 to v0.10.0 hold only
    `example-session`, so their replays don't prove that real writers fit;
    the per-writer evidence above does.
  - The character set is pinned by hand-written rows that don't derive from
    the generated pattern (`TestSessionID_CharacterSetIsPinned`): widening
    it to `:` or `/` and regenerating turns the test red.
- **2026-11-12**: v0.10.0 (audit#29, authn#136). Two request-writer denial
  reasons. `name_not_issued` (`DenialReasonNameNotIssued`, plumbing's
  `usernames.ErrNotIssued`): a sign-in for a username authn would issue in
  another form, one the clientconfig Secret's name derivation would rewrite;
  denied, no status code, no `check_result`, naming the Secret resource with
  no name under the aliasing rule below. `invalid_request`
  (`DenialReasonInvalidRequest`): on
  `authn.username.check`, a verified, mapped and opted-in caller sent a body
  with no username, or one that isn't JSON, so authn answers 400 and the
  check never runs (the AUDIT-4 lead's ruling of 2026-11-12). Denied, no
  status code, no `check_result`; with no username the record names the
  Secret resource without a name, and its verb and method are marked, as
  `name_missing`'s are. Both are the request writer's alone: `bad-enum` on a
  controller, `not-for-writer` on the gateway and action writers. The
  derived column fixtures pick them up from the schema. Compatibility:
  `testdata/v0.9.1/` holds 23 records audit v0.9.1's own `Emit` wrote (each
  username-check result, `username_check_not_allowed`, a failed lookup, and
  the v0.6.0 to v0.8.0 shapes), with v0.9.1's own `auditschema` report; this
  release gives the same report. [coverage.md](./coverage.md) states the
  rule for naming a derived credential Secret: `object_ref.name` is the
  derived name only when `MakeDNS1123Compatible(username) == username`,
  otherwise the resource with no name, because the derivation aliases
  distinct usernames. Additive, so a minor version per docs/release.md.
- **2026-11-12**: [coverage.md](./coverage.md), authn's rows refreshed from
  authn's code at authn@0fa999e0 (authn#123 merged; audit v0.8.0), each row
  citing its emit site and recorder by file and line, and the authn PR that
  shipped it (authn#123, authn#131, authn#133): the four logins, the
  ServiceAccount login, the mapping-lookup refusals and failures (marked
  incomplete by design), the step-up, `/delegate`, the step-up sweep, the
  service certificate, and two controller rows the inventory lacked:
  `authn.identity.backfilled` (which answers open question 1) and
  `authn.servicecert.annotated`. `/usernames/check` is listed from authn#136
  at `751f089d`, pending its merge. Docs only.
- **2026-11-12**: docs and the action-literal registry only, no release (no
  exported API, schema rule or record changes). The registry gains the
  controller literal `helm.rollback` (cdc: Observe clearing a release stuck
  pending past the grace, and Delete's rollback; real child patches, creates
  and deletes, from plumbing#140's per-child verdicts), pinned by
  `TestActionLiterals_RegistryIsWellFormed`. [coverage.md](./coverage.md):
  the cdc and core-provider notes state two expected cases (a child never
  attempted after a failed create gets no record, the AUDIT-4 lead's ruling of
  2026-11-12 in reply to core-provider#423; a child whose Namespace
  can't be read is marked `incomplete=preview`, never guessed `false`), and
  authn's `/delegate` row now matches authn's shipped record (verb `create`
  on the mapping's `token` subresource, authn@0fa999e0
  `internal/auditlog/delegate.go:39-44`).
- **2026-11-12**: v0.9.1 (audit#26, audit#25). A fix in `audittest`, no
  schema or record change.
  - `AssertRemovalDetected`, and so `AssertRequiredKeysDetected`, failed on
    every conformant `authn.username.check` success record (authn, building
    authn#136): removing `krateo.action` makes `Check` report
    `krateo.audit.check_result` `not-for-action`, correctly, and the
    falsifier counted that as collateral damage. Its relation of keys is now
    read from the schema in one more way: when `krateo.action` is removed or
    changed, every key whose closed set the writer declares per action
    (`Requirement.ActionValues`) is related. No key is named. Tests: the
    removal falsifier and `AssertRequiredKeysDetected` on an
    `authn.username.check` success record (v0.9.0's suite never ran them),
    and the relation pinned per writer and per key.
  - The `krateo.action` literal registry in docs/schema.md: its statement of
    which rules read `krateo.action` is now derived from the schema's
    per-action sets, not typed, and a test fails when an action a
    per-action set declares is not registered under the writer that
    declares it.
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
  `http.request.method`'s description now states the rule writers already
  follow (authn's methodOf, authn@0fa999e0): the method is derived from the
  verb of the authority request the writer sent, never the method of the
  request it served; no rule changed.
  docs/schema.md gains a registry of `krateo.action` literals, documentation
  only (schema v1 enforces no literal; `TestCheck_ActionLiteralsAreNotEnforced`
  pins that): core-provider's helm literals for cdc (core-provider#423),
  `helm.install`, `helm.upgrade`, `helm.reconcile` and `helm.uninstall`,
  and authn's `authn.username.check`.
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
