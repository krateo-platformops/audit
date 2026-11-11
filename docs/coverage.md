---
type: Architecture
title: audit — coverage
description: The cross-component audit inventory (AUDIT-4, installer#410): every emit site, per writer class, with its scope, action, target, verb, outcomes and state.
resource: github.com/krateo-platformops/audit
tags: [library, audit, coverage, inventory]
timestamp: 2026-11-11T00:00:00Z
---

# Coverage

The checked-in inventory of who audits what, judged against
[schema v1](./schema.md) (AUDIT-4, krateo-platformops/installer#410;
krateo-platformops/audit#9). There is one table per writer class, and one row
per emit site.

- **Owners add their rows by PR.** A PR that adds or changes an emit site
  updates its rows here in the same change, or in a PR to this repository that
  links it.
- **State comes from merged PRs only.** `done` means the emit site is on the
  owner's main branch through the linked merged PR. `pending` means it is not
  merged yet, and the link points at the open PR or issue. A row never says
  `done` on a plan, a branch or a deploy note.
- **scope** is the instrumentation scope the emitter's logger uses. It must be
  one of the populations in `schema/v1.yaml`, under the same writer, so that
  `auditschema sql` judges the rows by that writer's rules.
  `TestCoverage_EveryRowHasItsPopulation` fails otherwise.
- No identity appears here: component, path and object names only. `<user>`
  stands for the user name embedded in an object's name.

A component's own detail stays with the component. For example, snowplow's
`go/snowplow/docs/architecture/audit-coverage.md` lists what snowplow does not
audit and why.

## request (H)

| owner | scope | writer | krateo.action | target | verb | outcomes | state |
|---|---|---|---|---|---|---|---|
| snowplow | `github.com/krateo-platformops/snowplow/audit` | request | `call` | the object written through `POST/PUT/PATCH/DELETE /call`, on the caller's own credential | create, update, patch, delete | success, failure | done ([snowplow#116](https://github.com/krateo-platformops/snowplow/pull/116)) |
| snowplow | `github.com/krateo-platformops/snowplow/audit` | request | `call.dryRun` | the object of a `/call/dry-run` write (nothing persisted) | create, update, patch | success, failure | done ([snowplow#461](https://github.com/krateo-platformops/snowplow/pull/461)) |
| snowplow | `github.com/krateo-platformops/snowplow/audit` | request | `export` | the object the export reads through the caller's own `/call` | get | success, failure | done ([snowplow#116](https://github.com/krateo-platformops/snowplow/pull/116)) |
| snowplow | `github.com/krateo-platformops/snowplow/audit` | request | `restaction`, `restaction.dryRun` | a RESTAction `api[]` write stage dialled by a customer request: the caller's apiserver object, or the named endpoint (`server.address`) | the stage's write verb | success, failure | done ([snowplow#902](https://github.com/krateo-platformops/snowplow/pull/902)) |
| authn | `github.com/krateo-platformops/authn/audit` | request | `authn.login.{basic,ldap,oauth,oidc,serviceaccount}` | Secret `<user>-clientconfig` | create, update | success, denied, failure | pending ([authn#123](https://github.com/krateo-platformops/authn/pull/123)) |
| authn | `github.com/krateo-platformops/authn/audit` | request | `authn.stepup.oidc` | Secret `<user>-clientconfig-stepup` | create, update | success, denied, failure | pending ([authn#123](https://github.com/krateo-platformops/authn/pull/123)) |
| authn | `github.com/krateo-platformops/authn/audit` | request | `authn.delegate` | the actor's `serviceaccounts.serviceaccount.authn.krateo.io` mapping | get | success, denied, failure | pending ([authn#123](https://github.com/krateo-platformops/authn/pull/123)) |

snowplow writes its `/call` records for an agent on the same scope, as the
action writer (T), per the population. They are not listed apart.

## gateway (G)

| owner | scope | writer | krateo.action | target | verb | outcomes | state |
|---|---|---|---|---|---|---|---|

No rows yet.

## action (T)

| owner | scope | writer | krateo.action | target | verb | outcomes | state |
|---|---|---|---|---|---|---|---|

No rows yet.

## controller (C)

| owner | scope | writer | krateo.action | target | verb | outcomes | state |
|---|---|---|---|---|---|---|---|
| authn | `github.com/krateo-platformops/authn/audit/controller` | controller | `authn.stepup.expired` | Secret `<user>-clientconfig-stepup` | delete | success, failure | pending ([authn#123](https://github.com/krateo-platformops/authn/pull/123)) |
| authn | `github.com/krateo-platformops/authn/audit/controller` | controller | `authn.servicecert.issued` | Secret `authn-clientconfig` | create, update (as sent) | success, failure | pending ([authn#123](https://github.com/krateo-platformops/authn/pull/123)) |
