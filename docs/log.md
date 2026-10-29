---
type: Log
title: audit — log
description: Curated history of the audit package.
resource: github.com/krateo-platformops/audit
tags: [library, audit, log]
timestamp: 2026-10-29T00:00:00Z
---

# Log

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
