// Package audit emits the canonical Krateo AuditEvent as an OTLP LogRecord on
// the shared OTel Collector -> ClickHouse plane. The collector routes
// event.name="audit" records to the krateo_audit table.
//
// It is the one emitter shared by every Krateo controller that audits what it
// does, whichever runtime it is built on (provider-runtime or
// unstructured-runtime): it depends only on the OTel APIs.
//
// Correlation, two keys:
//   - trace_id: the Logs SDK stamps TraceId/SpanId from the span on ctx, joining
//     the audit row to the traces/logs the action caused.
//   - the written object's identity: ObjectUID + ObjectGeneration (and
//     ObjectResourceVersion where known). snowplow records the same three for the
//     write that created or changed an object, so a controller's audit row for
//     the reconcile that acted on that generation joins back to the user's
//     request — and to its session.id — on (uid, generation), without mutating
//     the object.
//
// session.id is read from W3C baggage when present (request-path components);
// a reconcile has no inbound baggage, which is why the object identity exists.
package audit

import (
	"context"

	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/trace"
)

// EventName is the discriminator stamped on every audit record. The collector
// and every query filter on LogAttributes['event.name'] = 'audit'.
const EventName = "audit"

// BaggageSessionKey is the W3C baggage member carrying the business/session
// correlation id (minted by snowplow, never a bespoke header).
const BaggageSessionKey = "session.id"

// Outcome values. Anything other than OutcomeSuccess is emitted at ERROR.
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
	OutcomeDenied  = "denied"
)

// Event is the caller-facing input. Every field is optional; an unset field is
// omitted from the record, never written empty.
//
// Never put a credential in any field. In particular ServerAddress is host[:port]
// only — never a path, query or userinfo, which can carry a secret — and Message
// must not echo an upstream response body.
type Event struct {
	Message string // LogRecord body

	EndUserID string   // enduser.id
	UserName  string   // user.name
	UserRoles []string // user.roles

	Namespace   string // k8s.namespace.name
	Group       string // k8s.resource.group
	Version     string // k8s.resource.version
	Resource    string // k8s.resource.resource
	Subresource string // k8s.resource.subresource
	Kind        string // k8s.resource.kind
	ObjectName  string // k8s.resource.name

	// Identity of the object written or acted on — the Option-B join key.
	ObjectUID             string // k8s.object.uid
	ObjectGeneration      int64  // k8s.object.generation (0 => omitted)
	ObjectResourceVersion string // k8s.object.resource_version

	ServerAddress string // server.address — host[:port] of an external endpoint

	Action     string // krateo.action (logical verb, e.g. "call", "rest.write")
	HTTPMethod string // http.request.method
	StatusCode int    // http.response.status_code (0 => omitted)

	Outcome string // OutcomeSuccess | OutcomeFailure | OutcomeDenied
}

// Emitter wraps one OTel Logs API Logger. Build it once from the process
// LoggerProvider and inject it. A nil Emitter (or one with a nil logger) is a
// no-op, so a component with OTLP logs disabled never panics and needs no
// nil-guard at each call site.
type Emitter struct {
	logger log.Logger
}

// New returns an Emitter bound to logger, typically
// provider.Logger("<your module>/audit").
func New(logger log.Logger) *Emitter { return &Emitter{logger: logger} }

// Emit writes one canonical AuditEvent. ctx should carry the active span (so the
// SDK stamps TraceId/SpanId) and, on a request path, the W3C baggage (so
// session.id is captured).
func (e *Emitter) Emit(ctx context.Context, ev Event) {
	if e == nil || e.logger == nil {
		return
	}

	var rec log.Record
	rec.SetBody(log.StringValue(ev.Message))

	if ev.Outcome == OutcomeSuccess || ev.Outcome == "" {
		rec.SetSeverity(log.SeverityInfo)
		rec.SetSeverityText("INFO")
	} else {
		rec.SetSeverity(log.SeverityError)
		rec.SetSeverityText("ERROR")
	}

	// event.name is written as a LogAttribute: that is the exact key
	// (LogAttributes['event.name']) the collector routes and every query filters on.
	attrs := []log.KeyValue{log.String("event.name", EventName)}
	add := func(k, v string) {
		if v != "" {
			attrs = append(attrs, log.String(k, v))
		}
	}
	add("enduser.id", ev.EndUserID)
	add("user.name", ev.UserName)
	add("k8s.namespace.name", ev.Namespace)
	add("k8s.resource.group", ev.Group)
	add("k8s.resource.version", ev.Version)
	add("k8s.resource.resource", ev.Resource)
	add("k8s.resource.subresource", ev.Subresource)
	add("k8s.resource.kind", ev.Kind)
	add("k8s.resource.name", ev.ObjectName)
	add("k8s.object.uid", ev.ObjectUID)
	add("k8s.object.resource_version", ev.ObjectResourceVersion)
	add("server.address", ev.ServerAddress)
	add("krateo.action", ev.Action)
	add("http.request.method", ev.HTTPMethod)
	add("outcome", ev.Outcome)

	if ev.ObjectGeneration != 0 {
		attrs = append(attrs, log.Int64("k8s.object.generation", ev.ObjectGeneration))
	}
	if len(ev.UserRoles) > 0 {
		vals := make([]log.Value, len(ev.UserRoles))
		for i, r := range ev.UserRoles {
			vals[i] = log.StringValue(r)
		}
		attrs = append(attrs, log.Slice("user.roles", vals...))
	}
	if ev.StatusCode != 0 {
		attrs = append(attrs, log.Int("http.response.status_code", ev.StatusCode))
	}

	if m := baggage.FromContext(ctx).Member(BaggageSessionKey); m.Key() != "" {
		attrs = append(attrs, log.String("session.id", m.Value()))
	}

	// TraceId/SpanId are LogRecord fields the SDK stamps from ctx, not
	// attributes. Flag a record emitted with no trace context so it is findable.
	if sc := trace.SpanContextFromContext(ctx); !sc.IsValid() {
		attrs = append(attrs, log.Bool("krateo.audit.no_trace_context", true))
	}

	rec.AddAttributes(attrs...)
	e.logger.Emit(ctx, rec)
}
