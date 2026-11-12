# audit

## What is this

The one emitter, and the one schema, for the canonical **Krateo AuditEvent**.
Every Krateo component that audits what it does writes the same record shape
through this package, whichever runtime it is built on (`provider-runtime` or
`unstructured-runtime`). It depends only on the OpenTelemetry APIs.

Each event is an OTLP LogRecord with EventName `audit` and the attribute
`event.name="audit"`. The shared OTel collector routes those records to the
ClickHouse `krateo_audit` table, which keeps them for 365 days. The
`krateo-audit-worm` chart makes that table tamper-evident.

The record contract is [schema/v1.yaml](schema/v1.yaml) (installer#716): every
attribute a record may carry, and which ones each writer class must write. The
package ships, generated from it:

- `audit.Key*` constants, so no writer spells a key by hand;
- `audit.Check`, the conformance checker, and `audittest`, the helpers for a
  writer's own tests, falsifier included;
- `cmd/auditschema`, the same check for writers not written in Go, and the
  live ClickHouse conformance queries.

It is consumed as a plain Go module. It ships no image, no chart and no CRDs.

## Install

```sh
go get github.com/krateo-platformops/audit@latest
```

Requires Go ≥ 1.26; build with Go ≥ 1.26.10 for a patched standard library (see
[docs/usage.md](docs/usage.md)).

```go
import "github.com/krateo-platformops/audit"

// A controller reports its own ServiceAccount as the actor.
emitter := audit.New(loggerProvider.Logger("github.com/<org>/<component>/audit"),
	audit.WithActor("system:serviceaccount:krateo-system:my-controller", audit.ClassController))

emitter.Emit(ctx, audit.Event{ // ctx carries the active span
	Namespace:        cr.GetNamespace(),
	Group:            "github.krateo.io",
	Version:          "v1alpha1",
	Resource:         "repoes",
	Kind:             "Repo",
	ObjectName:       cr.GetName(),
	ObjectUID:        string(cr.GetUID()),
	ObjectGeneration: cr.GetGeneration(),
	Preview:          audit.PreviewOf(inSandbox), // read from the Namespace's label
	ServerAddress:    "api.github.com",
	Action:           "rest.write", Verb: "post", HTTPMethod: "POST", StatusCode: 201,
	Outcome:          audit.OutcomeSuccess,
})
```

`Emit` never drops a record: one that lacks a key its writer must write, the
actor included, is emitted marked `krateo.audit.incomplete` and counted. A nil `*Emitter`, or one
built with a nil logger, is a no-op.

Test each emit site against the schema:

```go
rec := audittest.NewRecorder(t)
e := audit.New(rec.Logger("test/audit"), audit.WithActor(sa, audit.ClassController))
runTheEmitSite(ctx, e)
audittest.AssertConformant(t, audit.WriterController, rec.Only(t))
audittest.AssertRequiredKeysDetected(t, audit.WriterController, rec.Only(t))
```

## Configure

The package takes three options (`WithActor`, `WithWriter`,
`WithMeterProvider`) and otherwise relies on the process's OTel Logs SDK setup.
Export OTLP logs to the node-local collector (`http://$(HOST_IP):4318`), whose
audit pipeline routes `event.name="audit"` to `krateo_audit`. See
[docs/configuration.md](docs/configuration.md).

## Examples

- [examples/emit-to-stdout](examples/emit-to-stdout/README.md): a runnable
  program that emits one audit record to stdout, with a span on the context,
  and checks it against the schema.

## Docs

- [docs/index.md](docs/index.md): the map of this documentation
- [docs/schema.md](docs/schema.md): the record contract, key by key (generated)
- [docs/usage.md](docs/usage.md): when and how to emit, adopting v0.4, v0.5, v0.6, v0.7, v0.8, v0.9, v0.10, v0.11, v0.12 and v0.13, testing a writer
- [docs/api.md](docs/api.md): the Go API

## Develop & release

```sh
go generate ./...   # after editing schema/v1.yaml
go vet ./...
go test -race -cover ./...
```

`TestGeneratedFilesAreCurrent` fails when `schema_gen.go` or `docs/schema.md`
is stale. Tag-only releases: a `vX.Y.Z` tag on `main`, consumed via the Go
module proxy. See [docs/release.md](docs/release.md).
