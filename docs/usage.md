---
type: Usage
title: audit — usage
description: Install the package, when and how to emit, and how a reconcile's audit row is correlated with the request that caused it.
resource: github.com/krateo-platformops/audit
tags: [library, audit, usage]
timestamp: 2026-10-29T13:55:06Z
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
not echo a response body.

`Emit` enforces the `ServerAddress` rule itself: it reduces the value to
host[:port], so passing the request URL records only its host and port. A value
with no parseable host is omitted, never written raw. That reduction is a
safety net, not permission to put a secret in any other field.

## Correlating a reconcile with the request that caused it

A reconcile has no inbound request, so there is no `session.id` in its baggage.
The link back to the person is the **object's identity**:

- the write that created or changed the object records its `uid`, `generation`
  and `resourceVersion`;
- the controller records the `uid` and the `generation` it acted on (the
  object's `metadata.generation` as read at reconcile start; a status
  `observedGeneration` is not required).

Joining the two on `(k8s.object.uid, k8s.object.generation)` in `krateo_audit`
ties the external write to the user's request and its `session.id`:

- a `kubectl` or GitOps write produces a generation with no request-side record,
  so it is correctly not attributed to anyone's session;
- a resync on an unchanged generation joins to the original write.

A controller that writes its own spec, or a CR without a status subresource, can
bump `generation` itself. Record the `resourceVersion` it read for an exact
match in those cases.
