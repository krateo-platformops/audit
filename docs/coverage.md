---
type: Architecture
title: audit — coverage
description: The cross-component audit inventory (AUDIT-4, installer#410). Every mutating path of every Krateo component, per writer class, with its identity source, status, owner issue, and the scope, action, verb and outcomes its records carry.
resource: github.com/krateo-platformops/audit
tags: [library, audit, coverage, inventory]
timestamp: 2026-11-12T00:00:00Z
---

# Coverage

This page lists every path in Krateo that changes something. It is the
checked-in inventory that AUDIT-4 asks for ([installer#410]; this page is
[audit#9]). Each row is judged against [schema v1](./schema.md). Snowplow
owns this page. Each component's owner keeps that component's rows
correct.

There is one table per writer class, and one for the paths no writer
records. Each row is one mutating path of one component.

## Reading a row

| column | meaning |
|---|---|
| component | the process that performs the change |
| path (what changes) | the route, tool or reconcile step, and the object or endpoint it changes |
| writer class | `request`, `gateway`, `action` or `controller`, as defined in [schema.md](./schema.md#writers). `—` means no writer records this path, by decision |
| identity source | where the emit site gets the actor |
| status | one of the four values below |
| owner issue | the issue that closes the gap, or the issue that records the decision. Where a merged PR added the emit site, it follows as `emit:` |
| scope | the instrumentation scope of the emitter's logger. It must be a population of the same writer in `schema/v1.yaml`, so that `auditschema sql` judges the rows by that writer's rules. A path that is audited names its scope |
| krateo.action | the action literal the records carry |
| verb | `krateo.audit.verb`, the verb sent |
| outcomes | the outcomes the path can record |

The four schema columns are blank where they aren't known yet. The owner
fills them in with the emit site.

The four status values:

- **audited**: the owner's default branch emits a schema v1 record on this
  path.
- **audited, non-conformant**: a record is emitted, but `Check` (or the
  schema's body rule) rejects it. The owner issue lists the gaps.
- **not audited**: the path changes something and no record is emitted.
- **out of scope (reason)**: no record, by a decision. The reason is
  written in the row, so no exclusion is inherited silently.

A status describes merged code only. An open pull request doesn't change a
status, and a plan, a branch or a deploy note never makes a path audited.
The row's owner issue links to the PR.

No identity appears on this page: component, path and object names only.
An object whose name embeds a user name is described in words ("the
user's clientconfig Secret"), never spelled out, not even with a
placeholder.

`TestCoverage_EveryRowMeetsTheAcceptance` enforces the column rules above:
the writer class, the status, the owner issue, the out-of-scope reason and
the scope. Of the identity rule, it enforces the shapes a pattern can
see: no placeholder in angle brackets, no email address, and no
clientconfig Secret spelled by its user-named name. A person's name has no
such shape, so keeping names off this page is a review rule.

## Owner rule

An owner's PR that adds, changes or removes an emit site updates that
component's rows here in the same change. When the emit site lives in
another repository, the PR body carries the new rows, and they land here,
in a PR that links it, before the work is reported as done. Owner issues
link back to [audit#9]. A new installer hook Job that writes is also added
to the AUDIT-5 list ([installer#411]) in the same PR ([installer#781]).

A component's own detail stays with the component. Snowplow's
[audit coverage](https://github.com/krateo-platformops/snowplow/blob/main/go/snowplow/docs/architecture/audit-coverage.md)
lists every attribute it writes and every route it serves. This page has
one row per path.

## Boundary rulings

These are the owner's rulings of 2026-11-09 ([installer#410], scope comment),
stated once here for every row below.

1. **Creates and deletes pass the ".spec changes" test** of AUDIT-7
   ([installer#413]). A create moves the desired state from absent to
   present, and a delete moves it from present to absent. Desired state,
   ruled by the AUDIT-4 lead on 2026-11-11 for [plumbing#106], is every
   top-level field except `apiVersion`, `kind`, `metadata` and `status`:
   `.spec` where it exists, and also ConfigMap and Secret `data`, `type` and
   `immutable`, RBAC `rules`, `subjects`, `roleRef` and `aggregationRule`
   (compared as sets), and an admission configuration's `webhooks`.
2. **A kept deletion is a controller row.** That is a delete that helm
   declined because of `helm.sh/resource-policy: keep`. The row has verb
   `delete`, outcome `denied`, and `krateo.audit.denial_reason` =
   `kept_resource_policy` (v0.5.0, [audit#8]). The reason is that key, not
   a body value: `Check` reads attributes only
   ([schema.md](./schema.md#kept-deletions-and-pruned-children)).
3. **rest-dynamic-controller records every external mutating call it
   sends.** Each record carries the CR's uid and generation and the
   endpoint's `server.address`. `*.krateo.io` doesn't gate an external
   write: the external write is the action itself.
4. **Controller writes to RBAC, admission and credential Secrets are in
   scope**, as a named exception to [installer#413] condition 1 (target
   `*.krateo.io`). For these objects, condition 2 becomes "their rules,
   subjects or data changed".

## Naming a derived credential Secret

Every writer that names a credential Secret derived from a username, authn's
username checks and its sign-in refusals included, follows one rule. The
derived name is plumbing's `endpoints.SecretName`:
`kubeutil.MakeDNS1123Compatible(username)` plus `-clientconfig`
(plumbing v1.51.0 `endpoints/endpoints.go:107-109`,
`kubeutil/dns1123.go:18-32`). The derivation lowercases the username, drops
every character outside `[-a-z0-9]` and any leading run that isn't `[a-z0-9]`,
and cuts the result to 63 characters (`kubeutil/dns1123.go:9`, `:27-29`). So
usernames that differ only in case, in characters the derivation drops, or
beyond its 63-character limit derive the same Secret name. A username made
only of dropped characters derives an empty name, and the Secret name
`-clientconfig`, which isn't a valid object name; the rule below never names
such a Secret, since the derivation changed the username.

- `krateo.audit.object_ref.name` is the derived Secret name only when the
  derivation leaves the username unchanged
  (`MakeDNS1123Compatible(username) == username`).
- Otherwise the record names the Secret resource with no name, as a
  `name_missing` record does. A sign-in with such a username that an
  identity source chose is refused with `name_not_issued` (audit v0.10.0;
  authn#141 at `2fb07895`, `internal/helpers/kube/config/guard.go:57-65`, `:126`, `:143-152`). An administrator-provisioned name (a basic User, a
  ServiceAccount mapping) keeps signing in, and its records stay nameless
  under this rule ([authn#140]).

The reason is aliasing: a query for one user's Secret must never show checks
or refusals for names that weren't theirs.

## Exclusions

None of these is a row anyone emits. Each is a decision.

- **Installer hook Jobs** (shell `kubectl`) are out of AUDIT-4. The library
  can't reach them. Each Job is listed as an AUDIT-5 admission acceptance
  case ([installer#411], [installer#781]).
- **Authentication failures before verification** are counted, never
  recorded as rows. Recording them would let anyone who can send a bad
  token or a bad password write to the trail. authn records none
  (authn@0fa999e0 `internal/auditlog/auditlog.go:74-75`,
  `internal/routes/auth/serviceaccount/login.go:258-265`). The
  per-strategy-and-cause counter [authn#119] asks for is not on authn's
  `main`; they show only in authn's generic `http.server.request.count`, by
  route and status, when its metrics are on
  (`internal/telemetry/metrics_middleware.go:15`, `:24`, `:46-52`).
  snowplow refuses a caller before verification in its UserConfig
  middleware, before any handler runs: a missing, invalid or expired token,
  or one signed by a key authn no longer publishes (TokenMissing,
  TokenInvalid, TokenExpired, KeyNotPublished; snowplow `219a076e`,
  `go/snowplow/internal/handlers/middleware/credential_status.go:64-80`).
  Those are counted, never rows, and stay visible in the gateway's access
  log. Not every snowplow 401 is one of them: a **verified** caller refused
  because its session or step-up credential Secret is missing
  (`session_credential_missing`, `step_up_required`;
  `credential_status.go:195-199`, via `userconfig.go:363-364`) gets a row,
  with its denial reason (audit v0.12.0).
- **Tool-server actions that run on the tool server's own ServiceAccount**
  (the kagent helm, istio, cilium, argo and shell tools) can't be
  attributed to a person by any hop. No record can name the human, so
  nothing here records them.

## Stated limit

Content parity with the Kubernetes apiserver's audit log is reachable. A
completeness guarantee isn't, without admission (AUDIT-5,
[installer#411]). The apiserver's audit log is written by the thing being
protected. Krateo's trail is written by each component that performs an
action, so a path that fails to emit leaves no trace, and nothing else
notices. Present the trail as "what each component did, and for whom",
never as a record of everything that happened to an object.

## request (H)

snowplow writes with this library since [snowplow#1348] (merged
2026-11-11), on audit v0.6.0 (`go/snowplow/go.mod:15`). The rows below cite
snowplow's `main` at `219a076e`, relative to `go/snowplow/`.

- **The writer.** `internal/support/audit/audit.go` builds the Emitter
  declared as the request writer (`New`, `:201-207`), on the scope at `:75`.
- **What every record gets.** `Emit` (`:237-253`) adds the actor, the
  `.dryRun` action suffix, the received request's source IPs, User-Agent and
  URI, and the target's preview flag.
- **The actor.** `setActor` (`:271-288`) reads the actor only from the JWT
  the UserConfig middleware verified. Its class comes from the signed
  `principal` claim, through `ParseClaim`, and is never defaulted. A
  delegated token adds `on_behalf_of` and `delegation`.
- **Outcomes.** A dialled write's outcome, code and body come from what was
  observed at the dial (`internal/credhttp/answer.go:119-133`, `Outcome`). A
  destination snowplow's policy refused is `denied` with no code. The
  `destination_refused` reason is not yet written: that is
  [snowplow#1381]'s.
- **Agents.** An agent's `/call` records are written on the same scope, as
  the action writer (T), per the population. They are not listed apart.
- **Tests.** snowplow's arms run `audittest.AssertConformant` on every
  record shape: the `AssertConformant` calls at
  `internal/handlers/audit_parity_1291_test.go:146` and `:228`, and
  `internal/resolvers/restactions/api/stage_audit_parity_1291_test.go:208`.
- **Gaps `Check` can't see.** Where a row is non-conformant, the record
  names something other than what the schema defines: the object dialled, or
  the request that was served. [snowplow#1379] (open) moves the writer to
  v0.10.0 and closes the `/call` and `/export` gaps. Those rows are pending
  it.

authn emits on `main` (authn@0fa999e0, audit v0.8.0 in `go/authn/go.mod:26`;
[authn#123], [authn#131] and [authn#133] merged). The rows below cite authn's code at that commit,
relative to `go/authn/`; the recorders are in `internal/auditlog/`. A
login's target is the credential Secret authn wrote (or, refused or failed
before the write, the one it would have written), its verb is the verb
authn sent for that Secret, and its method follows from that verb
(`auditlog.go:106-125`, `methodOf` at `:143-157`). A refusal carries no
status code (`auditlog.go:93-97`, `:101`). The query of the request authn
served is dropped except the parameters its route reads, so no OAuth or OIDC
`code` or `state` reaches the record (`auditlog.go:159-190`). The CSR that a
login creates, approves and deletes is an intermediate step, not a row.
ui-token-hop's own `POST` to authn's LoginURL, which mints the bearer it
then sends on, is one of these logins: the login rows cover it. A
`/delegate` record is shaped as a Kubernetes TokenRequest: verb `create`,
method `POST`, on the `token` subresource of the actor's
`serviceaccount.authn.krateo.io` mapping, with no status code, since authn
issues the token itself (`internal/auditlog/delegate.go:39-44`, `:59-60`);
the verb `get` in [authn#119]'s text is superseded by it. A ServiceAccount
caller the TokenReview verified but that no single mapping admits is
recorded on the mapping resource without a name and with no verb, so its
actor class, verb, method and preview are marked incomplete by design
(`internal/auditlog/mapping.go:29-67`; authn's own arm allows exactly those
four, `internal/routes/auth/serviceaccount/login_audit_test.go:90`). The
`/usernames/check` rows are [authn#136]'s, at its head `751f089d`, on audit
v0.9.1: pending its merge.

| component | path (what changes) | writer class | identity source | status | owner issue | scope | krateo.action | verb | outcomes |
|---|---|---|---|---|---|---|---|---|---|
| snowplow | `POST`, `PUT`, `PATCH`, `DELETE /call`: an object, written with the caller's own credential. Emit: `internal/handlers/call.go:242-275`, the record built by `requestAuditEvent` (`internal/handlers/audit_event.go:34-48`); routes `main.go:268-298` | request | the caller's JWT, verified by the UserConfig middleware and read from the request context (`audit.go:271-288`) | audited, non-conformant: the object recorded can differ from the object dialled, for a name or subresource that is not one path segment ([snowplow#1257]), and a create can record the query's name instead of the object the apiserver wrote ([snowplow#1378]). Pending [snowplow#1379] | [snowplow#1257], [snowplow#1378]; fix: [snowplow#1379]; emit: [snowplow#116], [snowplow#1348] | `github.com/krateo-platformops/snowplow/audit` | `call` | create, update, patch, delete (`audit.KubernetesVerb` on the dialled URI, `call.go:262`) | success, failure, denied (a refused destination, `answer.go:126-128`) |
| snowplow | `POST`, `PUT`, `PATCH /call/dry-run`: nothing persisted; the apiserver admits or refuses the write. Emit: as `/call` (`call.go:264`, `ev.DryRun`); the suffix `audit.go:242-244`; routes `main.go:291-296` | request | as `/call` | audited, non-conformant: as `/call`. Pending [snowplow#1379] | [snowplow#1257]; fix: [snowplow#1379]; emit: [snowplow#461], [snowplow#1348] | `github.com/krateo-platformops/snowplow/audit` | `call.dryRun` | create, update, patch | success, failure, denied |
| snowplow | a RESTAction `api[]` stage with a write verb, dialled by a customer request (`GET /call`, `POST /call/read`, `/export`): the caller's apiserver object (no `endpointRef`), or a named endpoint (`server.address`). Emit: `internal/resolvers/restactions/api/stage_audit.go:179-183`, the record built by `stageAuditEvent` (`:102-164`); only a customer's own resolve (`:107-109`) | request | the request's verified caller; one record per dialled call | audited | the endpointRef a stage dialled through, audit v0.12.0's `krateo.audit.endpoint_ref.*`, not yet written: [snowplow#1283]; emit: [snowplow#902], [snowplow#1348] | `github.com/krateo-platformops/snowplow/audit` | `restaction`, `restaction.dryRun` | the stage's write verb (the apiserver's for an apiserver object, `:139`; else the lowercase method, `:153`) | success, failure, denied (a refused destination) |
| snowplow | `GET`, `POST /export`: nothing changes; data leaves as a file built from the caller's own `/call`. Emit: `internal/handlers/export.go:249-264` (`auditExport`), called after a render or send (`:271`, `:300`); routes `main.go:313-326` | request | as `/call` | audited, non-conformant: the exits before the render emit nothing: an unsupported format or mismatched header labels (`export.go:174-186`), a failed page from the `/call` lane, a row path that does not evaluate, or the page collection (`:213-237`) ([snowplow#986]). Pending [snowplow#1379] | [snowplow#986]; fix: [snowplow#1379]; emit: [snowplow#116], [snowplow#1348] | `github.com/krateo-platformops/snowplow/audit` | `export` | get (the read its `/call` lane dials, `audit_event.go` `dialledVerb`) | success, failure |
| snowplow | `POST /debug/shadow-parity`: toggles a per-process dark parity measurement; it can't change an authorization verdict (`internal/handlers/debug_shadow_parity.go:92-100`, `rbac.SetShadowParityEnabled`). Its target is the non-resource path, `url.path` (audit v0.12.0). No emit; route `debug_routes.go:308` | request | the caller's JWT (RefreshAuth), authorized for verb `post` on the path by DebugAuthz (`debug_routes.go:208-216`, since [snowplow#1362]) | not audited | [snowplow#909] | | `debug.shadowParity` | post | |
| snowplow | a verified caller refused because its session or step-up credential Secret is missing (`internal/handlers/middleware/credential_status.go:195-199`, via `userconfig.go:363-364`) | request | the verified token | not audited | [snowplow#1381] | | | | denied (`session_credential_missing`, `step_up_required`) |
| snowplow | a RESTAction write stage in a background resolve (the refresher, a cohort seed, a prewarm, a demand revalidation, or a background hop: a `/call` snowplow makes to itself for one of them), refused before the dial (`internal/resolvers/restactions/api/background_write.go:155-173`; origins `internal/cache/background_writes.go:129-144`). The stage record is written only for a customer's own resolve (`stage_audit.go:107-109`) | request | none: no person is behind it | out of scope (nothing is sent, and no one requested it: background work has no requester and writes no record, [snowplow#903], [snowplow#1381]) | [snowplow#1381] | | | | |
| snowplow | a RESTAction write stage in an export's resolve (`GET`, `POST /export`: the export's read is not the customer's own write), refused before the dial (`background_write.go:155-173`; origin `internal/cache/background_writes.go:145-147`, [snowplow#970]) | request | the export's verified caller: the refused write had a requester | not audited | [snowplow#1381] | | | | denied (`write_refused`) |
| snowplow | a RESTAction write stage in an inline dry-run draft (`POST /call/read`): refused before egress (`internal/resolvers/restactions/api/resolve.go:831-840`, [snowplow#443]) | request | the caller | not audited | [snowplow#1381] | | | | denied (`dry_run_not_executed`) |
| snowplow | a RESTAction write stage refused or abandoned before the dial, in a customer's resolve. The refusals: a refused destination (`internal/credhttp/send.go:371`), a per-user credential Secret named as the endpointRef (`api/per_user_ref.go:52-56`), a malformed endpointRef (`api/endpoints.go:125-127`, `:150`), the internal identity context (`api/provenance.go:32-38`), a write verb on a UAF-governed stage (`api/uaf_non_read.go:66-69`), a failed dependency (`api/dependent_write.go:49`), an invalid path or a failed template (`api/undialled_write.go:70-90`). Also an endpoint Secret the apiserver answered NotFound or Forbidden for | request | the caller | not audited | [snowplow#1381] | | | | denied, each with its reason (`destination_refused`, `per_user_credential_ref`, `endpoint_ref_malformed`, `internal_identity_context`, `uaf_on_write_verb`, `dependency_failed`, `invalid_path`, `template_error`); failure with the apiserver's code for the Secret's NotFound or Forbidden |
| authn | basic, LDAP, OAuth and OIDC login: creates or updates the user's clientconfig Secret. Emit: `internal/routes/auth/basic/login.go:157`, `ldap/login.go:136`, `oauth/login.go:205`, `oidc/login.go:96`; recorder `internal/auditlog/auditlog.go:76-104`; literals `auditlog.go:33`, `:38`, strategies `internal/helpers/kube/config/storage/identity.go:54-57` | request | the identity the strategy verified, class human (each call passes `jwtutil.PrincipalHuman`); a row only after verification | audited | [authn#119]; emit: [authn#123]; refusal reasons: [authn#131] | `github.com/krateo-platformops/authn/audit` | `authn.login.basic`, `authn.login.ldap`, `authn.login.oauth`, `authn.login.oidc` | the verb sent for the Secret | success, denied (`auditlog.go:256-265`), failure |
| authn | ServiceAccount login: creates or updates the clientconfig Secret owned by the mapping. Emit: `internal/routes/auth/serviceaccount/login.go:125`; recorder `auditlog.go:76-104` | request | the ServiceAccount the TokenReview verified, of its mapping's declared class | audited | [authn#119]; emit: [authn#123] | `github.com/krateo-platformops/authn/audit` | `authn.login.serviceaccount` | the verb sent for the Secret | success, denied, failure |
| authn | a ServiceAccount the TokenReview verified, refused or failed at the mapping lookup, on `/serviceaccount/login` and `/delegate`: names the mapping resource without a name, no verb. Emit: `internal/routes/auth/serviceaccount/login.go:104` and `internal/routes/delegate/delegate.go:126`, through `RecordUnmapped` (`serviceaccount/login.go:258-271`); recorder `internal/auditlog/mapping.go:40-67` | request | the TokenReview's username; actor class, verb, method and preview marked incomplete by design | audited | [authn#119]; emit: [authn#133] | `github.com/krateo-platformops/authn/audit` | `authn.login.serviceaccount`, `authn.delegate` | none (marked) | denied (`no_mapping`, `ambiguous_mapping`, `not_a_service_account`, `mapping.go:16-27`), failure with the apiserver's answer to the lookup (`:61-63`) |
| authn | OIDC step-up: creates or updates the user's step-up clientconfig Secret. Emit: `internal/routes/auth/oidc/stepup.go:260`; recorder `auditlog.go:76-104`; literal `auditlog.go:34` | request | the identity the IdP verified, class human | audited | [authn#119]; emit: [authn#123]; post-verification refusals: [authn#133] | `github.com/krateo-platformops/authn/audit` | `authn.stepup.oidc` | the verb sent for the Secret | success, denied (`stepup_not_enabled`, `insufficient_assurance`, `stale_authentication`, `auditlog.go:266-269`), failure |
| authn | `POST /delegate`: signs a delegated JWT for an actor its mapping admits; recorded as a create on the mapping's `token` subresource. Emit: `internal/routes/delegate/delegate.go:133`, `:142`, `:150`, `:168`, `:172`; recorder `internal/auditlog/delegate.go:49-97`; literal `auditlog.go:32` | request | the actor, of its mapping's class; the subject goes to `on_behalf_of`, the chain to `delegation` (`delegate.go:86-94`) | audited | [authn#119]; emit: [authn#123]; subject-token refusals: [authn#131] | `github.com/krateo-platformops/authn/audit` | `authn.delegate` | create | success, denied (`delegation_not_allowed`, `subject_token_expired`, `subject_token_invalid`, `delegation_too_deep`, `delegate.go:22-34`), failure |
| authn | `POST /usernames/check`: whether a username is free; a read of the checked name's clientconfig Secret, verb get. [authn#136] at `751f089d`: route `internal/routes/usernames/check.go:107-150`, recorder `internal/auditlog/usernames.go:54-94`, on audit v0.9.1 | request | the caller's mapping, of its declared class (`usernames.go:60`, `:75-77`); an unmapped caller as in the mapping-lookup row (`check.go:107`) | not audited | [authn#136] (pending authn#136 merge) | `github.com/krateo-platformops/authn/audit` | `authn.username.check` | get | success with `krateo.audit.check_result` (`check.go:166-176`), denied (`username_check_not_allowed`, `check.go:120`; an unreadable body or one with no username: no reason at `751f089d`, `check.go:129`, `invalid_request` from audit v0.10.0, audit#29; the record names the Secret resource with no name, and a derived name only as "Naming a derived credential Secret" says), failure (`check.go:137`, `:146`) |
| kagent-controller | its REST writes (sessions, runs, agent edits), reached from the kagent UI through ui-token-hop and the agent gateway | request | the Krateo bearer ui-token-hop mints and swaps in | not audited | [kagent#31] | | | | |

## gateway (G)

These rows are written by the observability collector's
`logs/gateway-audit` projection, merged as `4da2a25` in
otel-collector-daemonset 0.1.27. 0.1.28 (`a73bda4`, [observability#158])
also counts every gateway record it does not project. The projection reads
the access-log facts agentgateway-policies emits (0.2.28 or later for
complete records). `krateo.action` is `gateway.` followed by the protocol (`a2a`, `mcp`, `llm`). The verb is the
lowercase HTTP method the gateway proxied, and every acting hop on these
paths is a `post`. A hop the gateway refused before dialing still names its
target: `server.address` is the route's configured backend. Every row is
tested in observability's `check-gateway-audit` workflow against the real
agentgateway's output with `auditschema check -writer gateway`.
[observability#156] tracks the remaining test gaps. The live
`auditschema sql` check follows the roll.

| component | path (what changes) | writer class | identity source | status | owner issue | scope | krateo.action | verb | outcomes |
|---|---|---|---|---|---|---|---|---|---|
| agent gateway | an A2A call to an agent (a request with an `a2a.method`) | gateway | the token the gateway verified: `principal` and the `act` chain; `user.name` is the outermost actor | audited | [observability#138], [agentgateway-policies#79]; emit: [observability#155] | `github.com/krateo-platformops/observability/gateway-audit` | `gateway.a2a` | the lowercase method proxied (`post` for this path) | `success`, `failure` (the backend answered 4xx/5xx, the gateway failed to reach it, or another gateway-side failure), `denied` (the gateway itself refused: authentication, authorization, rate limit, guardrail, overload) |
| agent gateway | an MCP `tools/call`, `resources/read` or `prompts/get`, and any MCP method on neither the projected nor the excluded list | gateway | as above | audited | [observability#138], [agentgateway-policies#79]; emit: [observability#155] | `github.com/krateo-platformops/observability/gateway-audit` | `gateway.mcp` | the lowercase method proxied (`post` for this path) | `success`, `failure` (the backend answered 4xx/5xx, the gateway failed to reach it, or another gateway-side failure), `denied` (the gateway itself refused: authentication, authorization, rate limit, guardrail, overload) |
| agent gateway | an LLM completion | gateway | as above | audited | [observability#138], [agentgateway-policies#79]; emit: [observability#155] | `github.com/krateo-platformops/observability/gateway-audit` | `gateway.llm` | the lowercase method proxied (`post` for this path) | `success`, `failure` (the backend answered 4xx/5xx, the gateway failed to reach it, or another gateway-side failure), `denied` (the gateway itself refused: authentication, authorization, rate limit, guardrail, overload) |
| agent gateway | a plain HTTP hop (protocol `http`), such as ui-token-hop's `/api/...` traffic to kagent-controller | gateway | as above | out of scope (not projected: the write is recorded where it is applied, at kagent: not audited yet, kagent#31; counted in `krateo.gateway_audit.excluded` by protocol, route and method) | [observability#138], [kagent#31]; emit: [observability#158] | | | | |
| agent gateway | MCP session plumbing, agent-card fetches, model listing, and requests that matched no route | gateway | as above | out of scope (not an acting hop; counted in `krateo.gateway_audit.excluded`) | [observability#138] | | | | |

## action (T)

The action record at cert-replay-hop is snowplow's to build. It shares the
gateway's TraceId once the agent propagates the inbound A2A trace context
to the tool call (part 2 of [kagent#31]).

| component | path (what changes) | writer class | identity source | status | owner issue | scope | krateo.action | verb | outcomes |
|---|---|---|---|---|---|---|---|---|---|
| cert-replay-hop | the apiserver write a `k8s_*` tool sends, forwarded under `TOKEN_PASSTHROUGH` | action | the token the hop verifies, per event; `WithActor` is never used, because it would name the hop's ServiceAccount | not audited | [agentgateway-policies#79], [kagent#31] | | | | |

## controller (C)

The actor is the controller's own ServiceAccount, passed with `WithActor`.
`object_ref` names the object written, and `cause_ref` names the CR
reconciled ([audit#8], v0.5.0). Each controller also needs the
[installer#413] predicate at the emit site, and a counter for every write
the predicate drops, by reason.

- **authn**'s background credential writes are emitted since [authn#123]
  (the rows below cite authn@0fa999e0).
- **cdc and core-provider** emit nothing today. [core-provider#423] waits
  on [plumbing#106] (the uncapped per-object verdict, merged as
  plumbing#120) and on audit v0.5.0. It also renders
  `spec.principal: controller` on every cdc authn mapping, so cdc's tokens
  carry the class `controller`, not `service`. The installer's pin flips,
  which prune and recreate leaves, are executed by cdc and core-provider,
  so their rows cover them. Two cases are expected, not gaps:
  - A child helm never attempted, because an earlier create failed, gets
    **no** record. The failed create is the record; the count of children
    not attempted belongs to the Composition's status and metric, not to
    the trail.
  - A child whose Namespace can't be read (one an uninstall's cascade
    deleted included) is recorded with preview unknown: the record omits
    `krateo.audit.preview` and marks it, `krateo.audit.incomplete=preview`.
    It is never guessed `false`.
- **rest-dynamic-controller** emits on audit v0.3.0. **oasgen-provider**
  emits nothing.
- **access-review** emits on audit v0.3.0, under the shared scope (split by
  ServiceName). The records carry no actor, the revoked user is in
  `user.name`, user names are in the body, and there is no verb or
  preview. [access-review#28] moves every site to schema v1 on v0.5.0 and
  retires `campaign.close` (a second record for the evidence create).
  v0.6.0 gives access-review its own scope and adds
  `object_ref.content_sha256` for the evidence ConfigMap ([audit#12]).
- **identity-lifecycle** emits on audit v0.3.0, under the shared scope. It
  records no failure, writes the affected user in `user.name`, sets no
  `server.address` on IdP writes, and puts user names in the body.
  [identity-lifecycle#27] moves every site to schema v1 on v0.5.0 and
  retires the `deprovision` summary record (it writes nothing of its own).

| component | path (what changes) | writer class | identity source | status | owner issue | scope | krateo.action | verb | outcomes |
|---|---|---|---|---|---|---|---|---|---|
| authn | the step-up Secret sweep: deletes an expired step-up clientconfig Secret. Emit: `internal/stepupsweep/sweep.go:129`; recorder `internal/auditlog/controller.go:70-93`; literal `controller.go:16` | controller | authn's own ServiceAccount, class controller (`controller.go:50-57`) | audited | [authn#119]; emit: [authn#123] | `github.com/krateo-platformops/authn/audit/controller` | `authn.stepup.expired` | delete | success, failure with the apiserver's code |
| authn | service certificate issue or renewal: writes authn's own clientconfig Secret. Emit: `internal/certrenewal/renewal.go:258`; recorder `controller.go:110-133`; literal `controller.go:19` | controller | authn's own ServiceAccount | audited | [authn#119]; emit: [authn#123] | `github.com/krateo-platformops/authn/audit/controller` | `authn.servicecert.issued` | the verb sent (plumbing `StoreWritten`); marked when unknown | success, failure |
| authn | identity backfill at startup: stamps the authorization-bearing identity annotations (strategy, groups) or the owner on a credential Secret written before authn recorded them; a full update. Emit: `internal/identitybackfill/backfill.go:160`; recorder `controller.go:139-159`; literal `controller.go:20-23` | controller | authn's own ServiceAccount | audited | [authn#119]; emit: [authn#123] | `github.com/krateo-platformops/authn/audit/controller` | `authn.identity.backfilled` | update | success, failure |
| authn | its own credential's identity annotations brought in line with its certificate, recorded only when an authorization-bearing annotation changed. Emit: `internal/certrenewal/renewal.go:411-421`; recorder `controller.go:139-159`; literal `controller.go:24-26` | controller | authn's own ServiceAccount | audited | [authn#119]; emit: [authn#123] | `github.com/krateo-platformops/authn/audit/controller` | `authn.servicecert.annotated` | update | success, failure |
| authn | the leader-election Lease that elects the replica doing authn's own-identity work (`internal/leader/leader.go:24-26`); no emit | controller | authn's own ServiceAccount | out of scope (not `*.krateo.io`, and not an RBAC, admission or credential write) | [authn#119] | | | | |
| cdc | helm install or upgrade of a Composition's child: create, update or patch | controller | cdc's own ServiceAccount | not audited | [core-provider#423], [plumbing#106] | | | | |
| cdc | helm prune of a child the new revision no longer renders | controller | cdc's own ServiceAccount | not audited | [core-provider#423], [plumbing#106] | | | delete | |
| cdc | a kept deletion: a child helm declined to delete (`resource-policy: keep`) | controller | cdc's own ServiceAccount | not audited | [core-provider#423], [plumbing#106] | | | delete | denied |
| core-provider | the authn mapping `serviceaccount.authn.krateo.io`: create, update | controller | core-provider's own ServiceAccount | not audited | [core-provider#423] | | | | |
| core-provider | the spoke mirror Composition: create, update, delete (the update runs on every resync today and must stop first) | controller | core-provider's own ServiceAccount | not audited | [core-provider#423] | | | | |
| core-provider | the hub Composition delete | controller | core-provider's own ServiceAccount | not audited | [core-provider#423] | | | delete | |
| core-provider | the migration path that can lose a Composition's spec (`getters.go:371`) | controller | core-provider's own ServiceAccount | not audited | [core-provider#423] | | | | |
| core-provider | Roles, ClusterRoles, their bindings, ServiceAccounts and credential Secrets (named exception) | controller | core-provider's own ServiceAccount | not audited | [core-provider#423] | | | | |
| core-provider | CRDs, Deployments, labels and status | controller | core-provider's own ServiceAccount | out of scope ([installer#413] condition 1; counted by the excluded-writes counter) | [core-provider#423] | | | | |
| rest-dynamic-controller | an external `POST`, `PUT`, `PATCH` or `DELETE` to the API a RestDefinition describes | controller | none today; its own ServiceAccount is known to the process but not passed | audited, non-conformant (audit v0.3.0: no actor, error text in the body, `Kind` without `Resource`, no verb on delegated sites, emitted after its span ended) | [oasgen-provider#543] | `rest-dynamic-controller/audit` | `rest.write` | | |
| oasgen-provider | ClusterRoles, Roles, their bindings and ServiceAccounts (named exception) | controller | oasgen-provider's own ServiceAccount | not audited | [oasgen-provider#543] | | | | |
| oasgen-provider | MutatingAdmissionPolicy and its binding (named exception) | controller | oasgen-provider's own ServiceAccount | not audited | [oasgen-provider#543] | | | | |
| oasgen-provider | CRDs, Deployments and label patches | controller | oasgen-provider's own ServiceAccount | out of scope ([installer#413] condition 1; counted by the excluded-writes counter) | [oasgen-provider#543] | | | | |
| access-review | creates the immutable snapshot ConfigMap | controller | none today; the fix passes the controller's ServiceAccount | audited, non-conformant | [access-review#25] | `github.com/krateo-platformops/audit` | `campaign.snapshot` | | |
| access-review | creates the evidence ConfigMap that closes a campaign | controller | as above | audited, non-conformant | [access-review#25] | `github.com/krateo-platformops/audit` | `campaign.evidence` | | |
| access-review | deletes a RoleBinding or ClusterRoleBinding, or removes revoked subjects from one (named exception) | controller | as above; the revoked subject belongs in `affected_user` | audited, non-conformant | [access-review#25] | `github.com/krateo-platformops/audit` | `revoke.binding` | | |
| access-review | a deleted campaign keeps its snapshot and evidence ConfigMaps (a kept deletion) | controller | as above | audited, non-conformant | [access-review#25] | `github.com/krateo-platformops/audit` | `campaign.remove` | | |
| access-review | status writes and unchanged reconciles | controller | as above | out of scope ([installer#413]; counted) | [access-review#25] | | | | |
| identity-lifecycle | deactivate: disables the account at the IdP | controller | none today (the affected user is written as `user.name`); the fix passes the controller's ServiceAccount | audited, non-conformant | [identity-lifecycle#24] | `github.com/krateo-platformops/audit` | | | |
| identity-lifecycle | logout: revokes the account's IdP sessions | controller | as above | audited, non-conformant | [identity-lifecycle#24] | `github.com/krateo-platformops/audit` | | | |
| identity-lifecycle | revoke: deletes the user's RoleBinding or ClusterRoleBinding (named exception) | controller | as above | audited, non-conformant | [identity-lifecycle#24] | `github.com/krateo-platformops/audit` | | | |
| identity-lifecycle | revoke: deletes the user's downstream identity CR | controller | as above | audited, non-conformant | [identity-lifecycle#24] | `github.com/krateo-platformops/audit` | | | |
| identity-lifecycle | group membership: adds or removes the user from an IdP group | controller | as above | audited, non-conformant | [identity-lifecycle#24] | `github.com/krateo-platformops/audit` | | | |
| identity-lifecycle | status writes, unchanged reconciles and idempotent no-ops | controller | as above | out of scope ([installer#413]; counted) | [identity-lifecycle#24] | | | | |

## no writer

These paths have no writer, by decision. The portal is not a writer: every
portal write goes through snowplow's `/call`, so snowplow's `/call` row
records it. [snowplow#1333] replaces the portal's second `POST` (the
AuditRecord CR) with a request header, `X-Krateo-Provenance`. snowplow
attaches its fields to the `/call` record as the client-asserted
`krateo.audit.client.*` keys, kept apart from the verified keys
([audit#12], v0.6.0). Identity, actor class, target and outcome never come
from the header. The readers at the end change nothing. They are listed so
that no reader is mistaken for a gap. The four agent issues removed the
write-capable `k8s_check_service_connectivity` tool from read-only agents.
All four are closed, and the gateway denies the tool to every caller.

| component | path (what changes) | writer class | identity source | status | owner issue | scope | krateo.action | verb | outcomes |
|---|---|---|---|---|---|---|---|---|---|
| snowplow | a refusal before verification on any route: a missing, invalid or expired token, or one signed by a key authn no longer publishes (TokenMissing, TokenInvalid, TokenExpired, KeyNotPublished; `internal/handlers/middleware/credential_status.go:64-80`) | — | none: no verified identity | out of scope (see Exclusions) | [installer#410] | | | | |
| snowplow | `POST /convert` | — | none | out of scope (not mounted: the route is commented out, `main.go:1364`) | [installer#410] | | | | |
| snowplow | `POST /telemetry/v1/traces`: browser spans on the trace plane (`main.go:237-247`, `mountTelemetryRoute`, behind RefreshAuth) | — | the caller's verified JWT | out of scope (no platform state changes) | [snowplow#1291] | | | | |
| snowplow | snowplow's own writes to the cluster | — | snowplow's ServiceAccount | out of scope (there are none: the grant is `get`, `list`, `watch` on every resource, `create` on the non-persistent access reviews, and `impersonate` for reads; `helm/snowplow/templates/clusterrole.yaml:21-38`, `:60-95`) | [installer#410] | | | | |
| authn | a failed login before verification; no emit (`internal/auditlog/auditlog.go:74-75`) | — | none: nothing is verified yet | out of scope (see Exclusions) | [authn#119] | | | | |
| kagent tools | helm, istio, cilium, argo and shell tool writes, run on the tool server's own ServiceAccount | — | the tool server's ServiceAccount only | out of scope (see Exclusions) | [installer#412] | | | | |
| kagent agents | an agent's tool call | — | the caller's token, passed through to the tool | out of scope (an agent writes only through a tool; its writes are the tool rows) | [agentiko#160], [installer-agent#28], [incident-agent#26], [snowplow-agent#21] | | | | |
| installer | the `post-install`, `post-upgrade` self-bootstrap hook Job | — | the Job's ServiceAccount, seen only by admission | out of scope (shell hook Job: an AUDIT-5 acceptance case) | [installer#781], [installer#411] | | | | |
| installer | the `pre-delete` bootstrap teardown hook Job: deletes the installer CompositionDefinition | — | as above (the self-bootstrap ServiceAccount) | out of scope (shell hook Job: an AUDIT-5 acceptance case) | [installer#781], [installer#411] | | | | |
| installer | the `pre-delete` ordered teardown hook Job: deletes Compositions and PVCs | — | as above (cdc's ServiceAccount) | out of scope (shell hook Job: an AUDIT-5 acceptance case) | [installer#781], [installer#411] | | | | |
| installer | the `post-delete` cleanup hook Job | — | as above | out of scope (shell hook Job: an AUDIT-5 acceptance case) | [installer#781], [installer#411] | | | | |
| installer | pin flips that prune and recreate a Composition's leaves | — | executed by cdc and core-provider | out of scope (recorded as the cdc and core-provider rows) | [installer#781] | | | | |
| any client | a direct `kubectl` write to `*.krateo.io`, bypassing every Krateo component | — | the apiserver's authenticated user, seen only by admission | out of scope (AUDIT-5 admission) | [installer#411] | | | | |
| frontend | a portal write (create, update, delete) through `/call` | — | the signed-in user's token, verified by snowplow | out of scope (not a writer: snowplow's `/call` row records it) | [snowplow#1333] | | | | |
| frontend | the second `POST` per write that creates an `auditrecords.audit.krateo.io` CR (a client-written trail) | — | as above | out of scope (not a writer: recorded as a `/call` write; to be retired by AUDIT-8) | [snowplow#1333], [snowplow#850], [installer#414] | | | | |
| snowplow | reads: `GET /call`, `POST /call/read`, `GET /list`, `GET /rbac` (`main.go:1378-1472`, behind UserConfig), and `GET /debug/*` (`debug_routes.go:208-216`, behind RefreshAuth and DebugAuthz) | — | the caller's verified JWT | out of scope (reads; AUDIT-4 covers mutations) | [installer#410] | | | | |
| snowplow | reads with no identity: `GET /api-info/names` (`main.go:1373-1375`), `GET /capabilities` (`:1479`), `GET /health`, `GET /readyz`, `GET /swagger/` (`:1363-1367`) | — | none: no identity is read | out of scope (reads; AUDIT-4 covers mutations) | [installer#410] | | | | |
| snowplow | `GET`, `POST /refreshes` (the live-refresh subscription, `main.go:1447-1458`, behind RefreshAuth) and `POST /jq` (evaluates over the request body, no I/O, `:1481`, behind UserConfig) | — | the caller's verified JWT | out of scope (no state changes) | [installer#410] | | | | |
| snowplow | widgets served to a caller with no token, as a dedicated impersonated identity that no authenticator can issue; access is RBAC only. Proposed ([snowplow#1334], open); not on `main` at `219a076e` | — | the dedicated public identity | out of scope (reads only: no mutating path) | [snowplow#1334] | | | | |
| sse-proxy | the portal's audit view, read from `krateo_audit` | — | the viewer's token | out of scope (a reader of the trail) | [installer#410] | | | | |

## Open questions

Each open question is asked on its owner's issue; the link goes to the comment. An answered one says where its row is.

1. **authn's identity backfill on Secrets.** *Answered by authn's code.*
   [Asked on authn#119](https://github.com/krateo-platformops/authn/issues/119#issuecomment-6800345899).
   It writes the authorization-bearing identity annotations, or the owner,
   of a credential Secret, and authn records it as a controller row,
   `authn.identity.backfilled` (authn@0fa999e0
   `internal/identitybackfill/backfill.go:160`,
   `internal/auditlog/controller.go:20-23`, `:139-159`). It is in the
   controller table.
2. **ui-token-hop** in agentgateway-policies. *Answered by observability
   (2026-11-11, relayed by the AUDIT-4 lead).* It is a reverse proxy with no
   method filter: `/api/...` goes through the agent gateway to
   kagent-controller, and everything else to kagent-ui. It swaps in a Krateo
   bearer it mints itself, by its own `POST` to authn's LoginURL. So it has
   no row of its own: kagent-controller's REST writes are request rows
   ([kagent#31]), the gateway counts the hop without projecting it, and the
   LoginURL `POST` is one of authn's login rows.
3. **oasgen-provider and credential Secrets.** [oasgen-provider#543] puts
   credential Secrets in scope, but the write list read at `fadf5ed3` names
   none. Does oasgen-provider write a credential Secret?
   [Asked on oasgen-provider#543](https://github.com/krateo-platformops/oasgen-provider/issues/543#issuecomment-6800346558).
4. **identity-lifecycle's AccessRequest** ([identity-lifecycle#28], a draft
   stacked on #27). It adds controller writes (an IdP user create, a group
   join, an action email, a CRM form and contact update), and a public
   intake that creates AccessRequest objects with no verified caller. The
   controller rows land with that PR. Is the intake's create a row, and if
   so, which writer class and which actor?
   [Asked on identity-lifecycle#24](https://github.com/krateo-platformops/identity-lifecycle/issues/24#issuecomment-6800347833).
5. **The preview label on the sandbox Namespace.** The frontend sets the
   label that writers read for `krateo.audit.preview`. Does it set it
   through `/call` (then snowplow's `/call` row covers it), or by another
   path? [Asked on snowplow#1333](https://github.com/krateo-platformops/snowplow/issues/1333#issuecomment-6800348688).

[audit#8]: https://github.com/krateo-platformops/audit/issues/8
[audit#9]: https://github.com/krateo-platformops/audit/issues/9
[audit#12]: https://github.com/krateo-platformops/audit/issues/12
[audit#22]: https://github.com/krateo-platformops/audit/issues/22
[installer#410]: https://github.com/krateo-platformops/installer/issues/410
[installer#411]: https://github.com/krateo-platformops/installer/issues/411
[installer#412]: https://github.com/krateo-platformops/installer/issues/412
[installer#413]: https://github.com/krateo-platformops/installer/issues/413
[installer#414]: https://github.com/krateo-platformops/installer/issues/414
[installer#781]: https://github.com/krateo-platformops/installer/issues/781
[snowplow#116]: https://github.com/krateo-platformops/snowplow/pull/116
[snowplow#461]: https://github.com/krateo-platformops/snowplow/pull/461
[snowplow#850]: https://github.com/krateo-platformops/snowplow/issues/850
[snowplow#902]: https://github.com/krateo-platformops/snowplow/pull/902
[snowplow#909]: https://github.com/krateo-platformops/snowplow/issues/909
[snowplow#970]: https://github.com/krateo-platformops/snowplow/issues/970
[snowplow#986]: https://github.com/krateo-platformops/snowplow/issues/986
[snowplow#1257]: https://github.com/krateo-platformops/snowplow/issues/1257
[snowplow#1283]: https://github.com/krateo-platformops/snowplow/issues/1283
[snowplow#1291]: https://github.com/krateo-platformops/snowplow/issues/1291
[snowplow#1333]: https://github.com/krateo-platformops/snowplow/issues/1333
[snowplow#1334]: https://github.com/krateo-platformops/snowplow/issues/1334
[snowplow#443]: https://github.com/krateo-platformops/snowplow/issues/443
[snowplow#903]: https://github.com/krateo-platformops/snowplow/issues/903
[snowplow#1348]: https://github.com/krateo-platformops/snowplow/pull/1348
[snowplow#1362]: https://github.com/krateo-platformops/snowplow/issues/1362
[snowplow#1378]: https://github.com/krateo-platformops/snowplow/issues/1378
[snowplow#1379]: https://github.com/krateo-platformops/snowplow/pull/1379
[snowplow#1381]: https://github.com/krateo-platformops/snowplow/issues/1381
[authn#119]: https://github.com/krateo-platformops/authn/issues/119
[authn#123]: https://github.com/krateo-platformops/authn/pull/123
[authn#131]: https://github.com/krateo-platformops/authn/pull/131
[authn#133]: https://github.com/krateo-platformops/authn/pull/133
[authn#136]: https://github.com/krateo-platformops/authn/pull/136
[authn#140]: https://github.com/krateo-platformops/authn/issues/140
[observability#138]: https://github.com/krateo-platformops/observability/issues/138
[observability#155]: https://github.com/krateo-platformops/observability/pull/155
[observability#156]: https://github.com/krateo-platformops/observability/issues/156
[observability#158]: https://github.com/krateo-platformops/observability/pull/158
[agentgateway-policies#79]: https://github.com/krateo-agentiko/agentgateway-policies/issues/79
[kagent#31]: https://github.com/krateo-agentiko/kagent/issues/31
[agentiko#160]: https://github.com/krateo-agentiko/agentiko/issues/160
[installer-agent#28]: https://github.com/krateo-agentiko/installer-agent/issues/28
[incident-agent#26]: https://github.com/krateo-agentiko/incident-agent/issues/26
[snowplow-agent#21]: https://github.com/krateo-agentiko/snowplow-agent/issues/21
[plumbing#106]: https://github.com/krateo-platformops/plumbing/issues/106
[core-provider#423]: https://github.com/krateo-platformops/core-provider/issues/423
[oasgen-provider#543]: https://github.com/krateo-platformops/oasgen-provider/issues/543
[access-review#25]: https://github.com/krateo-platformops/access-review/issues/25
[access-review#28]: https://github.com/krateo-platformops/access-review/pull/28
[identity-lifecycle#24]: https://github.com/krateo-platformops/identity-lifecycle/issues/24
[identity-lifecycle#27]: https://github.com/krateo-platformops/identity-lifecycle/pull/27
[identity-lifecycle#28]: https://github.com/krateo-platformops/identity-lifecycle/pull/28
