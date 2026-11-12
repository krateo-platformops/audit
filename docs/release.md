---
type: Runbook
title: audit — release
description: How an audit version ships: an annotated v-prefixed git tag consumed via the Go module proxy; no images, no charts, no OCI artifacts.
resource: github.com/krateo-platformops/audit
tags: [library, release, go-module]
timestamp: 2026-11-11T00:00:00Z
---

# Release

`audit` is **tag-only**. A release is an annotated `vX.Y.Z` git tag on `main`,
consumed through the Go module proxy. No image, chart or OCI artifact is built.

1. Merge to `main` with CI green (`test`: vet + race tests; `security`; `lint-docs`).
2. Tag the merge commit: `git tag -a vX.Y.Z -m "..."` and push the tag.
3. The `release-notes` workflow runs on `v*` tags.
4. Consumers move with `go get github.com/krateo-platformops/audit@vX.Y.Z`.

Go module versions must be `v`-prefixed. A bare `X.Y.Z` tag is not resolvable
by `go get`.

Compatibility: attribute names are the contract, and `schema/v1.yaml` states
them. Renaming or removing one breaks every query and join that uses it. So a
rename is written side by side with the old name for a whole migration window,
and the old name goes only after the window's data shows no row and no reader
still needs it (installer#716 §3.3). For schema v1 that is W1: v0.4.x and
v0.5.x write both, and the release that closes W1 removes the v0.3 names,
once the data shows no row and no reader still needs them. Outside such a
window, renaming or removing an attribute needs a major version.

Adding a key, a writer's value to a per-writer closed set, or a population is
a minor version: every record that was valid stays valid.

A tightening, i.e. a value a rule newly rejects, is a minor version when the
library's own writer paths are proved by test to stay conformant, and the
release note names the tightening and each registered writer's status with
evidence (code file:line). A writer whose current output the tightening
rejects gets that evidence before the tag.

A change to the schema is a change to `schema/v1.yaml` followed by
`go generate ./...`. CI fails when `schema_gen.go` or `docs/schema.md` is
stale.
