---
type: Runbook
title: audit — release
description: How an audit version ships: an annotated v-prefixed git tag consumed via the Go module proxy; no images, no charts, no OCI artifacts.
resource: github.com/krateo-platformops/audit
tags: [library, release, go-module]
timestamp: 2026-10-28T00:00:00Z
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

Compatibility: attribute names are the contract. Renaming or removing one breaks
every query and join that uses it, so that needs a major version.
