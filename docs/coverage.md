---
type: Architecture
title: audit — coverage
description: The cross-component audit inventory. Every mutating path of every Krateo component, its writer class, where its identity comes from, whether it is audited, and the owner issue that closes the gap.
resource: github.com/krateo-platformops/audit
tags: [library, audit, coverage, inventory]
timestamp: 2026-11-11T00:00:00Z
---

# Audit coverage

This page lists every path in Krateo that changes something. It is the
checked-in inventory that AUDIT-4 asks for
([installer#410]; this page is [audit#9]). Each row is judged against
[schema v1](./schema.md). Snowplow owns this page. Each component's owner
keeps that component's rows correct.

## Reading a row

| column | meaning |
|---|---|
| component | the process that performs the change |
| path (what changes) | the route, tool or reconcile step, and the object or endpoint it changes |
| writer class | `request`, `gateway`, `action` or `controller`, as defined in [schema.md](./schema.md#writers). `—` means no writer: nothing is emitted on this path, by decision |
| identity source | where the emit site gets the actor. Only component, path and object names appear on this page. No person's identity appears here, and no object name that contains one |
| status | one of the four values below |
| owner issue | the issue that closes the gap, or the issue that records the decision |

The four status values:

- **audited**: the owner's default branch emits a schema v1 record on this
  path.
- **audited, non-conformant**: a record is emitted, but `Check` (or the
  schema's body rule) rejects it. The owner issue lists the gaps.
- **not audited**: the path changes something and no record is emitted.
- **out of scope (reason)**: no record, by a decision. The reason is
  written in the row, so no exclusion is inherited silently.

A status describes what the owner's merged code does. An open pull request
doesn't change a status. The row's owner issue links to the PR.

## Owner rule

An owner's PR that adds, changes or removes an emit site updates that
component's rows here in the same change. When the emit site lives in
another repository, the PR body carries the new rows, and they land here
before the PR is reported as done. Owner issues link back to [audit#9].
A new installer hook Job that writes is also added to the AUDIT-5 list
([installer#411]) in the same PR ([installer#781]).

Snowplow's own detail, with every attribute it writes and every route it
serves, stays in snowplow's
[audit coverage](https://github.com/krateo-platformops/snowplow/blob/main/go/snowplow/docs/architecture/audit-coverage.md).
This page has one row per path.

## Boundary rulings

These are Diego's rulings of 2026-11-09 ([installer#410], scope comment),
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
   `delete` and outcome `denied`. The ruling wrote the reason as body
   `kept: resource-policy`. Since v0.5.0 ([audit#8]) the reason is the key
   `krateo.audit.denial_reason` = `kept_resource_policy`, and the body is
   empty: `Check` reads attributes only
   ([schema.md](./schema.md#kept-deletions-and-pruned-children)).
3. **rest-dynamic-controller records every external mutating call it
   sends.** Each record carries the CR's uid and generation and the
   endpoint's `server.address`. `*.krateo.io` doesn't gate an external
   write: the external write is the action itself.
4. **Controller writes to RBAC, admission and credential Secrets are in
   scope**, as a named exception to [installer#413] condition 1 (target
   `*.krateo.io`). For these objects, condition 2 becomes "their rules,
   subjects or data changed".

## Exclusions

None of these is a row anyone emits. Each is a decision.

- **Installer hook Jobs** (shell `kubectl`) are out of AUDIT-4. The library
  can't reach them. Each Job is listed as an AUDIT-5 admission acceptance
  case ([installer#411], [installer#781]).
- **Authentication failures before verification** are counted, never
  recorded as rows. Recording them would let anyone who can send a bad
  token or a bad password write to the trail. authn counts them by strategy
  and cause, never by user name ([authn#119] asks for that counter). snowplow's 401s are answered
  by its UserConfig middleware before any handler runs, so they don't
  reach the trail either. They stay visible in the gateway's access log.
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

## snowplow

Writer `request`, scope `github.com/krateo-platformops/snowplow/audit`.
snowplow writes with its own emitter, not yet with this library, so its
records lack the actor class, `krateo.audit.verb`, `krateo.audit.preview`,
`krateo.audit.dry_run` and the delegation keys. Adopting the library closes
that ([snowplow#1291]).

| component | path (what changes) | writer class | identity source | status | owner issue |
|---|---|---|---|---|---|
| snowplow | `POST`, `PUT`, `PATCH`, `DELETE /call`: an object, written with the caller's own credential | request | the caller's JWT, verified by the UserConfig middleware and read from the request context | audited, non-conformant | [snowplow#1291], [snowplow#1257] |
| snowplow | `POST`, `PUT`, `PATCH /call/dry-run`: nothing persisted; the apiserver admits or refuses the write | request | as `/call` | audited, non-conformant | [snowplow#1291] |
| snowplow | a RESTAction `api[]` stage with a write verb, reached by `GET /call`, `POST /call/read` or `/export`: the caller's apiserver (no `endpointRef`) or a named endpoint | request | the request's verified caller; one record per dialled call | audited, non-conformant | [snowplow#1291], [snowplow#1283] |
| snowplow | `GET`, `POST /export`: nothing changes; data leaves as a file built from the caller's own `/call` | request | as `/call` | audited, non-conformant (the success path only) | [snowplow#1291], [snowplow#986] |
| snowplow | `POST /debug/shadow-parity`: toggles a per-process dark parity measurement; it can't change an authorization verdict | request | as `/call` | not audited | [snowplow#909] |
| snowplow | a RESTAction write stage in a background resolve (refresher, cohort seed, prewarm, revalidation) | request | none: no person is behind it | out of scope (nothing is sent: the stage is refused before the dial, snowplow#903) | [snowplow#1291] |
| snowplow | a RESTAction write stage in an inline dry-run draft (`POST /call/read`) | request | the caller | out of scope (nothing is sent: write stages are refused before egress, snowplow#443) | [snowplow#1291] |
| snowplow | a RESTAction write stage abandoned before the dial (unresolvable endpoint, failed template, guard refusal, failed dependency) | request | the caller | out of scope (nothing is sent) | [snowplow#1291] |
| snowplow | an authentication failure on any route (a missing, malformed or expired token, or an untrusted signature) | — | none: no verified identity | out of scope (see Exclusions) | [installer#410] |
| snowplow | `POST /convert` | — | none | out of scope (not mounted: the route is commented out) | [installer#410] |
| snowplow | `POST /telemetry/v1/traces`: browser spans on the trace plane; no platform state | — | none | out of scope (no platform state changes) | [snowplow#1291] |
| snowplow | snowplow's own writes to the cluster | — | snowplow's ServiceAccount | out of scope (there are none: the grant is `get`, `list`, `watch`, non-persistent access reviews and `impersonate` for reads) | [installer#410] |

The cert-replay-hop action record is snowplow's to build. Its row is under
the agent path.

## authn

Writer `request` for logins and `/delegate`, scope
`github.com/krateo-platformops/authn/audit`. Background credential writes
are writer `controller`, scope
`github.com/krateo-platformops/authn/audit/controller`. authn emits
nothing on `main` today. [authn#123] adds every row below. A login's
target is the credential Secret authn wrote, and its verb is the verb authn
sent for that Secret. The CSR that a login creates, approves and deletes is
an intermediate step, not a row. A `/delegate` record targets the actor's
`serviceaccount.authn.krateo.io` mapping, with verb `get`.

| component | path (what changes) | writer class | identity source | status | owner issue |
|---|---|---|---|---|---|
| authn | basic, LDAP, OAuth and OIDC login (`authn.login.*`): creates or updates the user's clientconfig Secret | request | the identity the strategy verified; a row only after verification | not audited | [authn#119] |
| authn | ServiceAccount login (`authn.login.serviceaccount`): creates or updates the clientconfig Secret owned by the mapping | request | the verified ServiceAccount token and its mapping | not audited | [authn#119] |
| authn | OIDC step-up (`authn.stepup.oidc`): creates or updates the user's step-up clientconfig Secret | request | the identity the IdP verified | not audited | [authn#119] |
| authn | `POST /delegate` (`authn.delegate`): writes nothing; signs a delegated JWT, authorised by the actor's mapping; a refusal is a `denied` row | request | the verified actor; the subject goes to `on_behalf_of`, the chain to `delegation` | not audited | [authn#119] |
| authn | the step-up Secret sweep (`authn.stepup.expired`): deletes an expired step-up clientconfig Secret | controller | authn's own ServiceAccount (`WithActor`) | not audited | [authn#119] |
| authn | service certificate renewal (`authn.servicecert.issued`): creates or updates authn's own clientconfig Secret | controller | authn's own ServiceAccount (`WithActor`) | not audited | [authn#119] |
| authn | a failed login before verification | — | none: nothing is verified yet | out of scope (see Exclusions) | [authn#119] |
| authn | the leader-election Lease | — | authn's own ServiceAccount | out of scope (not `*.krateo.io`, and not an RBAC, admission or credential write) | [authn#119] |

The `/delegate` refusals get their own `denial_reason` values in v0.6.0
(`delegation_not_allowed`, `delegation_too_deep`), as does the refusal of an
IdP-asserted `krateo:` group (`platform_group`) ([audit#12]). Until then a
refusal is a `denied` record with no reason, which is valid.

## Agent path

The gateway rows are written by the observability collector's
`logs/gateway-audit` projection (writer `gateway`, scope
`github.com/krateo-platformops/observability/gateway-audit`). It was merged
as `4da2a25` in otel-collector-daemonset 0.1.27, which is rolling out. It
reads the access-log facts that agentgateway-policies emits (0.2.28 or
later for complete records). These rows are placeholders: observability
updates them in a follow-up PR, and [observability#156] tracks the
remaining test gaps. The live `auditschema sql` check follows the roll.

| component | path (what changes) | writer class | identity source | status | owner issue |
|---|---|---|---|---|---|
| agent gateway | an A2A call to an agent (a request with an `a2a.method`) | gateway | the token the gateway verified: `principal` and the `act` chain; `user.name` is the outermost actor | audited | [observability#138], [agentgateway-policies#79] |
| agent gateway | an MCP `tools/call`, `resources/read` or `prompts/get`, and any MCP method on neither the projected nor the excluded list | gateway | as above | audited | [observability#138], [agentgateway-policies#79] |
| agent gateway | an LLM completion | gateway | as above | audited | [observability#138], [agentgateway-policies#79] |
| agent gateway | MCP session plumbing, agent-card fetches, model listing, and requests that matched no route | gateway | as above | out of scope (not an acting hop; counted in `krateo.gateway_audit.excluded`) | [observability#138] |
| cert-replay-hop | the apiserver write a `k8s_*` tool sends, forwarded under `TOKEN_PASSTHROUGH` | action | the token the hop verifies, per event; `WithActor` is never used, because it would name the hop's ServiceAccount | not audited | [agentgateway-policies#79], [kagent#31] |
| kagent tools | helm, istio, cilium, argo and shell tool writes, run on the tool server's own ServiceAccount | — | the tool server's ServiceAccount only | out of scope (see Exclusions) | [installer#412] |
| kagent agents | an agent's tool call | — | the caller's token, passed through to the tool | out of scope (an agent writes only through a tool; its writes are the tool rows above) | [agentiko#160], [installer-agent#28], [incident-agent#26], [snowplow-agent#21] |

The action record at cert-replay-hop shares the gateway's TraceId once the
agent propagates the inbound A2A trace context to the tool call (part 2 of
[kagent#31]). The four agent issues removed the write-capable
`k8s_check_service_connectivity` tool from read-only agents. All four are
closed, and the gateway denies the tool to every caller.

## Controllers

All rows here are writer `controller`. The actor is the controller's own
ServiceAccount, passed with `WithActor`. `object_ref` names the object
written, and `cause_ref` names the CR reconciled ([audit#8], v0.5.0). Each
controller also needs the [installer#413] predicate at the emit site, and a
counter for every write the predicate drops, by reason.

### cdc and core-provider

Neither emits today. [core-provider#423] waits on [plumbing#106] (the
uncapped per-object verdict, merged as plumbing#120) and on audit v0.5.0.
It also renders `spec.principal: controller` on every cdc authn mapping, so
cdc's tokens carry the class `controller`, not `service`.

| component | path (what changes) | writer class | identity source | status | owner issue |
|---|---|---|---|---|---|
| cdc | helm install or upgrade of a Composition's child: create, update or patch | controller | cdc's own ServiceAccount | not audited | [core-provider#423], [plumbing#106] |
| cdc | helm prune of a child the new revision no longer renders: delete | controller | cdc's own ServiceAccount | not audited | [core-provider#423], [plumbing#106] |
| cdc | a kept deletion: a child helm declined to delete (`resource-policy: keep`) | controller | cdc's own ServiceAccount | not audited | [core-provider#423], [plumbing#106] |
| core-provider | the authn mapping `serviceaccount.authn.krateo.io`: create, update | controller | core-provider's own ServiceAccount | not audited | [core-provider#423] |
| core-provider | the spoke mirror Composition: create, update, delete (the update runs on every resync today and must stop first) | controller | core-provider's own ServiceAccount | not audited | [core-provider#423] |
| core-provider | the hub Composition delete | controller | core-provider's own ServiceAccount | not audited | [core-provider#423] |
| core-provider | the migration path that can lose a Composition's spec (`getters.go:371`) | controller | core-provider's own ServiceAccount | not audited | [core-provider#423] |
| core-provider | Roles, ClusterRoles, their bindings, ServiceAccounts and credential Secrets (named exception) | controller | core-provider's own ServiceAccount | not audited | [core-provider#423] |
| core-provider | CRDs, Deployments, labels and status | controller | core-provider's own ServiceAccount | out of scope ([installer#413] condition 1; counted by the excluded-writes counter) | [core-provider#423] |

The installer's pin flips, which prune and recreate leaves, are executed by
cdc and core-provider, so the rows above cover them.

### rest-dynamic-controller and oasgen-provider

| component | path (what changes) | writer class | identity source | status | owner issue |
|---|---|---|---|---|---|
| rest-dynamic-controller | an external `POST`, `PUT`, `PATCH` or `DELETE` to the API a RestDefinition describes (`rest.write`) | controller | none today; its own ServiceAccount is known to the process but not passed | audited, non-conformant (audit v0.3.0: no actor, error text in the body, `Kind` without `Resource`, no verb on delegated sites, emitted after its span ended) | [oasgen-provider#543] |
| oasgen-provider | ClusterRoles, Roles, their bindings and ServiceAccounts (named exception) | controller | oasgen-provider's own ServiceAccount | not audited | [oasgen-provider#543] |
| oasgen-provider | MutatingAdmissionPolicy and its binding (named exception) | controller | oasgen-provider's own ServiceAccount | not audited | [oasgen-provider#543] |
| oasgen-provider | CRDs, Deployments and label patches | controller | oasgen-provider's own ServiceAccount | out of scope ([installer#413] condition 1; counted by the excluded-writes counter) | [oasgen-provider#543] |

### access-review

`main` emits on audit v0.3.0, under the shared scope
`github.com/krateo-platformops/audit` (split by ServiceName). The records
carry no actor, the revoked user is in `user.name`, user names are in the
body, and there is no verb or preview. [access-review#28] moves every site
to schema v1 on v0.5.0, retires `campaign.close` (a second record for the
evidence create), and proposes the rows it will change. v0.6.0 gives
access-review its own scope and adds `object_ref.content_sha256` for the
evidence ConfigMap ([audit#12]).

| component | path (what changes) | writer class | identity source | status | owner issue |
|---|---|---|---|---|---|
| access-review | `campaign.snapshot`: creates the immutable snapshot ConfigMap | controller | none today; the fix passes the controller's ServiceAccount | audited, non-conformant | [access-review#25] |
| access-review | `campaign.evidence`: creates the evidence ConfigMap that closes a campaign | controller | as above | audited, non-conformant | [access-review#25] |
| access-review | `revoke.binding`: deletes a RoleBinding or ClusterRoleBinding, or removes revoked subjects from one (named exception) | controller | as above; the revoked subject belongs in `affected_user` | audited, non-conformant | [access-review#25] |
| access-review | `campaign.remove`: a deleted campaign keeps its snapshot and evidence ConfigMaps (a kept deletion) | controller | as above | audited, non-conformant | [access-review#25] |
| access-review | status writes and unchanged reconciles | controller | as above | out of scope ([installer#413]; counted) | [access-review#25] |

### identity-lifecycle

`main` emits on audit v0.3.0, under the shared scope
`github.com/krateo-platformops/audit`. It records no failure, writes the
affected user in `user.name`, sets no `server.address` on IdP writes, and
puts user names in the body. [identity-lifecycle#27] moves every site to
schema v1 on v0.5.0 and retires the `deprovision` summary record (it
writes nothing of its own).

| component | path (what changes) | writer class | identity source | status | owner issue |
|---|---|---|---|---|---|
| identity-lifecycle | deactivate: disables the account at the IdP | controller | none today (the affected user is written as `user.name`); the fix passes the controller's ServiceAccount | audited, non-conformant | [identity-lifecycle#24] |
| identity-lifecycle | logout: revokes the account's IdP sessions | controller | as above | audited, non-conformant | [identity-lifecycle#24] |
| identity-lifecycle | revoke: deletes the user's RoleBinding or ClusterRoleBinding (named exception) | controller | as above | audited, non-conformant | [identity-lifecycle#24] |
| identity-lifecycle | revoke: deletes the user's downstream identity CR | controller | as above | audited, non-conformant | [identity-lifecycle#24] |
| identity-lifecycle | group membership: adds or removes the user from an IdP group | controller | as above | audited, non-conformant | [identity-lifecycle#24] |
| identity-lifecycle | status writes, unchanged reconciles and idempotent no-ops | controller | as above | out of scope ([installer#413]; counted) | [identity-lifecycle#24] |

## Installer and direct access

| component | path (what changes) | writer class | identity source | status | owner issue |
|---|---|---|---|---|---|
| installer | the `post-install`, `post-upgrade` self-bootstrap hook Job | — | the Job's ServiceAccount, seen only by admission | out of scope (shell hook Job: an AUDIT-5 acceptance case) | [installer#781], [installer#411] |
| installer | the `pre-delete` bootstrap teardown hook Job: deletes the installer CompositionDefinition | — | as above (the self-bootstrap ServiceAccount) | out of scope (shell hook Job: an AUDIT-5 acceptance case) | [installer#781], [installer#411] |
| installer | the `pre-delete` ordered teardown hook Job: deletes Compositions and PVCs | — | as above (cdc's ServiceAccount) | out of scope (shell hook Job: an AUDIT-5 acceptance case) | [installer#781], [installer#411] |
| installer | the `post-delete` cleanup hook Job | — | as above | out of scope (shell hook Job: an AUDIT-5 acceptance case) | [installer#781], [installer#411] |
| installer | pin flips that prune and recreate a Composition's leaves | — | executed by cdc and core-provider | out of scope (recorded as the cdc and core-provider rows) | [installer#781] |
| any client | a direct `kubectl` write to `*.krateo.io`, bypassing every Krateo component | — | the apiserver's authenticated user, seen only by admission | out of scope (AUDIT-5 admission) | [installer#411] |

## Frontend

The portal is not a writer. Every portal write goes through snowplow's
`/call`, so snowplow's `/call` row records it.

| component | path (what changes) | writer class | identity source | status | owner issue |
|---|---|---|---|---|---|
| frontend | a portal write (create, update, delete) through `/call` | — | the signed-in user's token, verified by snowplow | out of scope (not a writer: snowplow's `/call` row records it) | [snowplow#1333] |
| frontend | the second `POST` per write that creates an `auditrecords.audit.krateo.io` CR (a client-written trail) | — | as above | out of scope (not a writer: recorded as a `/call` write; to be retired by AUDIT-8) | [snowplow#1333], [snowplow#850], [installer#414] |

[snowplow#1333] replaces the second `POST` with a request header,
`X-Krateo-Provenance`. snowplow attaches its fields to the `/call` record as
the client-asserted `krateo.audit.client.*` keys, kept apart from the
verified keys ([audit#12], v0.6.0). Identity, actor class, target and
outcome never come from the header.

## Readers

These paths change nothing. They are listed so that no reader is mistaken
for a gap.

| component | path (what changes) | writer class | identity source | status | owner issue |
|---|---|---|---|---|---|
| snowplow | reads: `GET /call`, `POST /call/read`, `GET /list`, `GET /rbac`, `GET /api-info/names`, `GET /capabilities` | — | the caller's verified JWT | out of scope (reads; AUDIT-4 covers mutations) | [installer#410] |
| snowplow | `GET`, `POST /refreshes` (the live-refresh subscription) and `POST /jq` (evaluates over the request body, no I/O) | — | the caller's verified JWT | out of scope (no state changes) | [installer#410] |
| snowplow | widgets served to a caller with no token, as a dedicated impersonated identity that no authenticator can issue; access is RBAC only | — | the dedicated public identity | out of scope (reads only: no mutating path) | [snowplow#1334] |
| sse-proxy | the portal's audit view, read from `krateo_audit` | — | the viewer's token | out of scope (a reader of the trail) | [installer#410] |

## Open questions

Each question names the issue to ask it on. None of these is a row yet.

1. **authn's identity backfill on Secrets.** The AUDIT-4 inventory lists it
   among authn's background writes, beside the certificate renewal and the
   step-up sweep. Does it change a credential Secret's data (then it's a row
   under the named exception), or only its metadata (then it's out of
   scope)? Ask on [authn#119].
2. **ui-token-hop** in agentgateway-policies. Does it forward, or itself
   make, any mutating request? If it does, it needs a row like
   cert-replay-hop. Ask on [agentgateway-policies#79].
3. **oasgen-provider and credential Secrets.** [oasgen-provider#543] puts
   credential Secrets in scope, but the write list read at `fadf5ed3` names
   none. Does oasgen-provider write a credential Secret? Ask on
   [oasgen-provider#543].
4. **identity-lifecycle's AccessRequest** ([identity-lifecycle#28], a draft
   stacked on #27). It adds controller writes (an IdP user create, a group
   join, an action email, a CRM form and contact update), and a public
   intake that creates AccessRequest objects with no verified caller. The
   controller rows land with that PR. Is the intake's create a row, and if
   so, which writer class and which actor? Ask on
   [identity-lifecycle#24].
5. **The preview label on the sandbox Namespace.** The frontend sets the
   label that writers read for `krateo.audit.preview`. Does it set it
   through `/call` (then snowplow's `/call` row covers it), or by another
   path? Ask on [snowplow#1333].

[audit#8]: https://github.com/krateo-platformops/audit/issues/8
[audit#9]: https://github.com/krateo-platformops/audit/issues/9
[audit#12]: https://github.com/krateo-platformops/audit/issues/12
[installer#410]: https://github.com/krateo-platformops/installer/issues/410
[installer#411]: https://github.com/krateo-platformops/installer/issues/411
[installer#412]: https://github.com/krateo-platformops/installer/issues/412
[installer#413]: https://github.com/krateo-platformops/installer/issues/413
[installer#414]: https://github.com/krateo-platformops/installer/issues/414
[installer#781]: https://github.com/krateo-platformops/installer/issues/781
[snowplow#850]: https://github.com/krateo-platformops/snowplow/issues/850
[snowplow#909]: https://github.com/krateo-platformops/snowplow/issues/909
[snowplow#986]: https://github.com/krateo-platformops/snowplow/issues/986
[snowplow#1257]: https://github.com/krateo-platformops/snowplow/issues/1257
[snowplow#1283]: https://github.com/krateo-platformops/snowplow/issues/1283
[snowplow#1291]: https://github.com/krateo-platformops/snowplow/issues/1291
[snowplow#1333]: https://github.com/krateo-platformops/snowplow/issues/1333
[snowplow#1334]: https://github.com/krateo-platformops/snowplow/issues/1334
[authn#119]: https://github.com/krateo-platformops/authn/issues/119
[authn#123]: https://github.com/krateo-platformops/authn/pull/123
[observability#138]: https://github.com/krateo-platformops/observability/issues/138
[observability#156]: https://github.com/krateo-platformops/observability/issues/156
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
