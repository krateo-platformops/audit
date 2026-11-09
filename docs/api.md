---
type: API
title: audit — API
description: The exported Go API of the audit package (emitter, schema, checker, claim parser, sanitiser), audittest, cmd/auditschema, and how each Event field maps to a record attribute.
resource: github.com/krateo-platformops/audit
tags: [library, audit, api]
timestamp: 2026-11-09T00:00:00Z
---

# API

The record contract itself, key by key, is [schema.md](./schema.md), generated
from `schema/v1.yaml`.

## Emitter

```go
const EventName = "audit"             // LogRecord EventName and the event.name attribute
const BaggageSessionKey = "session.id"
const SchemaVersion = "1"             // krateo.audit.schema_version (generated)
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
	OutcomeDenied  = "denied"
)

func New(logger log.Logger, opts ...Option) *Emitter
func (e *Emitter) Emit(ctx context.Context, ev Event) // nil-safe

func WithActor(username string, class Class) Option // the actor of every record whose Event names none
func WithWriter(w Writer) Option                    // which writer class's gaps Emit marks, and whether it writes dry_run=false
func WithMeterProvider(mp metric.MeterProvider) Option

const MetricIncomplete = "krateo.audit.records.incomplete" // {marker=...}; marker="actor": emitted with no actor
```

`Emit` is the one writer, and **it never drops a record**:

- **A gap is recorded, never hidden.** A record that lacks a key the writer
  must write is emitted without it, with `krateo.audit.incomplete=<markers>`,
  and each marker is counted under `MetricIncomplete`. That includes the actor:
  an `Event` with no `UserName`, on an Emitter built without `WithActor`, is
  emitted marked `actor`. With `WithWriter`, the declared class's rules decide
  which gaps are marked; without it, a gap is marked only when every writer
  class that can write the key would have to.
- **It rejects nothing.** A key outside the schema is a `Check` finding in the
  writer's tests, never a reason not to emit.
- It sets the LogRecord Timestamp, EventName and severity (`success` or unset →
  INFO, otherwise ERROR), stamps `event.name` and
  `krateo.audit.schema_version`, writes the v0.3 keys beside their
  replacements (W1, see [schema.md](./schema.md)), and makes every string valid
  UTF-8 (`Sanitize`).

## Event

| `Event` field | attribute | notes |
|---|---|---|
| `Message` | LogRecord body | closed-set text: no upstream body, no identity |
| `UserName`, `UserRoles`, `ActorClass` | `user.name`, `user.roles`, `krateo.audit.actor_class` | the actor; when `UserName` is empty and the Emitter has `WithActor`, its principal, and the Event's roles and class are ignored. With neither, the Event's fields are written as given and the record is marked `actor`. A class that is not `Known` is omitted and marked |
| `EndUserID` | `enduser.id` | **Deprecated**: written only when set, as v0.3 did; `Emit` never adds it |
| `OnBehalfOf`, `Delegation` | `krateo.audit.on_behalf_of.user.name`, `krateo.audit.delegation` | a delegated token's `sub` and its act chain, each `Link` written `<class>:<subject>` |
| `ImpersonatedUser`, `ImpersonatedRoles` | `krateo.audit.impersonated_user.{name,roles}` | |
| `AffectedUser` | `krateo.audit.affected_user.name` | the user the action was done to, when that is not the actor |
| `Action` | `krateo.action` | the emit site's literal |
| `Verb` | `krateo.audit.verb` | the apiserver's verb, or the lowercase method |
| `HTTPMethod` | `http.request.method` (+ `http.request.method_original`) | a method semconv does not name, lowercase included, becomes `_OTHER`, and the method as given is written in `http.request.method_original` |
| `StatusCode` | `http.response.status_code` | omitted when 0 |
| `Outcome` | `krateo.audit.outcome` (+ `outcome`) | |
| `Preview` | `krateo.audit.preview` | `PreviewUnknown` (omitted, and marked for any Kubernetes object), `PreviewFalse` (also for a cluster-scoped object), `PreviewTrue`; `PreviewOf(bool)` |
| `DryRun` | `krateo.audit.dry_run` | `true` whenever set. `false` only on a write record (`Verb` in `WriteVerbs()`) of an Emitter declared `WithWriter(WriterRequest)` or `WithWriter(WriterAction)`. Never on a read or a controller record, and never added for an Emitter that declares no writer (a v0.3 caller). The `Action` literal is the caller's either way |
| `Namespace` | `k8s.namespace.name` | |
| `Group`, `Version`, `Resource`, `Subresource`, `Kind`, `ObjectName` | `krateo.audit.object_ref.{api_group,api_version,resource,subresource,kind,name}` (+ `k8s.resource.*`) | a Kubernetes object always names its `Resource` |
| `ObjectUID`, `ObjectGeneration`, `ObjectResourceVersion` | `krateo.audit.object_ref.{uid,generation,resource_version}` (+ `k8s.object.*`) | the join key; generation omitted when 0 |
| `ServerAddress` | `server.address` | **host[:port] only**: `Emit` drops any scheme, userinfo, path, query and fragment, and omits a value with no parseable host |
| `RequestURI`, `SourceIPs`, `UserAgent`, `ReceivedTime` | `krateo.request.uri`, `krateo.request.source_ips`, `user_agent.original`, `krateo.request.received_time_unix_nano` | what a request-serving writer received; the User-Agent is cut at 1024 bytes on a character |
| `RESTActionNamespace`, `RESTActionName`, `RESTActionStage` | `krateo.restaction.{namespace,name,stage}` | |
| read from W3C baggage on `ctx` | `session.id` | |
| set automatically | `krateo.audit.no_trace_context` | `true` when `ctx` carries no valid span |
| the span on `ctx` | TraceId / SpanId | LogRecord fields stamped by the SDK, not attributes |

Unset fields are omitted, never written empty.

## Schema

```go
type Writer string // WriterRequest (H) | WriterGateway (G) | WriterAction (T) | WriterController (C)
type Class string  // ClassHuman | ClassAgent | ClassController | ClassService; (Class).Known()
type Preview uint8 // PreviewUnknown | PreviewFalse | PreviewTrue
type Link struct{ Class Class; Subject string }

const KeyEventName = "event.name" // ... one Key* constant per key, generated

func Keys() []KeySpec                  // every key: type, semconv status, enum, marker, identity, per-writer Requirement
func LookupKey(name string) (KeySpec, bool)
func Writers() []Writer
func Markers() []string                // what krateo.audit.incomplete may list
func Target() TargetRule               // object_ref.resource or server.address, per writer
func Conditions() []Condition          // the conditions Check evaluates on a record
func Populations() []Population        // instrumentation scope -> writer, in krateo_audit
func LegacyControls() []Population
func LegacyKey(key string) string      // the v0.3 twin of a key, during W1
func SchemaYAML() []byte               // schema/v1.yaml
```

## Checker

```go
func Check(w Writer, attrs []attribute.KeyValue) []Violation
func CheckRecord(w Writer, eventName string, attrs []attribute.KeyValue) []Violation // + the LogRecord EventName
func RequiredKeys(w Writer, attrs []attribute.KeyValue) []string                   // what Check requires of this record
func Holds(c Condition, attrs []attribute.KeyValue) bool                            // a condition, as Check evaluates it
func WriteVerbs() []string                                                          // the verbs that make a record a write (condition write)

type Violation struct{ Key string; Reason Reason } // never a value
```

`Reason` is one of `missing`, `incomplete` (absent and marked), `not-in-schema`
(the closed set: any key outside the schema), `not-for-writer` (not
established by, or not applicable to, this writer), `bad-type`, `bad-enum`,
`bad-format`, `empty`, `invalid-utf8`, `duplicate`, `marked-but-present`,
`unexpected` (written outside the condition the schema allows it under, its
`only_when`: `http.request.method_original` with a method other than
`_OTHER`, or with none), `two-targets`, `legacy-without-replacement`,
`legacy-disagrees`,
`affected-user-is-actor`, `unknown-writer`, `bad-event-name`.
`Violation.Key` is an attribute key, `RuleTarget` (`"target"`) or
`KeyLogRecordEventName`.

## The recorded span marker

```go
const SpanKeyRecorded = "krateo.audit.recorded" // on the Server span: the request wrote an audit record

func WithRecordedMarker(ctx context.Context) context.Context // install the holder Emit sets (kept if one is already there)
func Recorded(ctx context.Context) bool                     // did Emit hand a record to the logger on ctx's holder?
func MarkRecorded(ctx context.Context, span trace.Span)     // set SpanKeyRecorded=true on span if so; call before span.End()
func RecordedMiddleware(next http.Handler) http.Handler     // the HTTP server wrapper doing all three; place it inside otelhttp
```

Once the logger has taken a record (it reports itself enabled for it), `Emit`
marks the request:
- **with a holder** on `ctx` (`WithRecordedMarker`, installed by the server
  wrapper), it sets the holder only, never the span on `ctx`. The span active
  at `Emit` time may be a stage's client span. The wrapper then marks the
  Server span from the holder with `MarkRecorded`;
- **without one**, it sets `SpanKeyRecorded=true` on `trace.SpanFromContext(ctx)`,
  which is right when the Server span is the active one.

A nil Emitter or logger, or a disabled logger, marks nothing. The marker is a
boolean, only ever `true`, and never identity (snowplow#848). It is a span
attribute, not a record key: `Check` reports it on a record as `not-in-schema`.
Concurrent `Emit`s on one holder or one span are safe.

## Claim, sanitiser, dual-write

```go
func ParseClaim[P ~string](claim P) (Class, bool) // audit.ParseClaim(ui.ActorPrincipal()); "" or unknown -> ("", false): omit
func Sanitize(kv attribute.KeyValue) attribute.KeyValue // the key and every string, at any depth, valid UTF-8
func SanitizeValue(v attribute.Value) attribute.Value
func WithLegacyKeys(attrs []attribute.KeyValue) []attribute.KeyValue // W1: add each v0.3 twin; removed in v0.5.0
```

`ParseClaim` takes plumbing's `jwtutil.Principal` as it is (any type whose
underlying type is `string`), so this package does not import plumbing.

## audittest

```go
func NewRecorder(t testing.TB) *Recorder // a real sdklog LoggerProvider that keeps every record
func (r *Recorder) Logger(scope string) log.Logger
func (r *Recorder) Records() []sdklog.Record
func (r *Recorder) Only(t testing.TB) sdklog.Record
func (r *Recorder) Reset()

func Attributes(rec sdklog.Record) []attribute.KeyValue
func Without(attrs []attribute.KeyValue, key string) []attribute.KeyValue

func AssertConformant(t testing.TB, w audit.Writer, rec sdklog.Record, opts ...Option)
func AssertViolation(t testing.TB, w audit.Writer, attrs []attribute.KeyValue, key string)
func AssertRemovalDetected(t testing.TB, w audit.Writer, rec sdklog.Record, key string, opts ...Option) // the falsifier
func AssertRequiredKeysDetected(t testing.TB, w audit.Writer, rec sdklog.Record, opts ...Option)       // ... for every required key
func AllowIncomplete(keys ...string) Option
```

## cmd/auditschema

```sh
go run github.com/krateo-platformops/audit/cmd/auditschema check -writer gateway records.json
go run github.com/krateo-platformops/audit/cmd/auditschema sql
```

`check` reads OTLP/JSON (an `ExportLogsServiceRequest`, one LogRecord, or an
array of them) and prints one line per violation, key and reason only. An
input it cannot decode is reported by position, field or key and a reason,
never by its value. Exit 1 when a record breaks the schema, 2 on a usage or
input error. `sql` prints the
`krateo_audit` conformance queries; see [usage](./usage.md#checking-the-live-table).
