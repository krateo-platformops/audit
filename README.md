# audit

## What is this

The one emitter for the canonical **Krateo AuditEvent**. Every Krateo
controller that audits what it does on a person's behalf writes the same record
shape through this package, whichever runtime it is built on
(`provider-runtime` or `unstructured-runtime`). It depends only on the
OpenTelemetry APIs.

Each event is an OTLP LogRecord with `event.name="audit"`. The shared OTel
collector routes those records to the ClickHouse `krateo_audit` table, which
keeps them for 365 days. The `krateo-audit-worm` chart makes that table
tamper-evident.

It is consumed as a plain Go module. It ships no image, no chart and no CRDs.

## Install

```sh
go get github.com/krateo-platformops/audit@latest
```

```go
import "github.com/krateo-platformops/audit"

emitter := audit.New(loggerProvider.Logger("github.com/<org>/<component>/audit"))

emitter.Emit(ctx, audit.Event{ // ctx carries the active span
	UserName:         requester,
	Namespace:        cr.GetNamespace(),
	Kind:             "Repo",
	ObjectName:       cr.GetName(),
	ObjectUID:        string(cr.GetUID()),
	ObjectGeneration: cr.GetGeneration(),
	ServerAddress:    "api.github.com",
	Action:           "rest.write", HTTPMethod: "POST", StatusCode: 201,
	Outcome:          audit.OutcomeSuccess,
})
```

A nil `*Emitter`, or one built with a nil logger, is a no-op.

## Configure

The package has no configuration of its own. Where records go is the process's
OTel Logs SDK setup. Export OTLP logs to the node-local collector
(`http://$(HOST_IP):4318`), whose audit pipeline routes `event.name="audit"` to
`krateo_audit`. See [docs/configuration.md](docs/configuration.md).

## Examples

- [examples/emit-to-stdout](examples/emit-to-stdout/README.md): a runnable
  program that emits one audit record to stdout, with a span on the context.

## Docs

- [docs/index.md](docs/index.md): the map of this documentation
- [docs/usage.md](docs/usage.md): when and how to emit; the correlation rules
- [docs/api.md](docs/api.md): the record contract (every attribute) and the Go API

## Develop & release

```sh
go vet ./...
go test -race -cover ./...
```

Tag-only releases: a `vX.Y.Z` tag on `main`, consumed via the Go module proxy.
See [docs/release.md](docs/release.md).
