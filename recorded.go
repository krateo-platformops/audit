package audit

import (
	"context"
	"net/http"
	"sync/atomic"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// SpanKeyRecorded is the span attribute that says the request's handler wrote
// an audit record: krateo.audit.recorded=true on the request's Server span.
// observability's tail sampler keeps such traces whole, with one rule for
// every writer (span.attributes["krateo.audit.recorded"] == true).
//
// It is a span attribute, not a record attribute: it is not in schema/v1.yaml,
// and Check reports it on a record as not-in-schema. It is a boolean, only
// ever true, and never carries identity (snowplow#848).
const SpanKeyRecorded = "krateo.audit.recorded"

// recordedMarker is the holder WithRecordedMarker installs: Emit sets it, the
// server wrapper reads it at span end. Concurrent Emits are safe.
type recordedMarker struct{ v atomic.Bool }

type recordedMarkerKey struct{}

// WithRecordedMarker returns ctx carrying a holder that Emit sets when it
// hands a record to the logger. Install it where the request's Server span is
// the active span (the server middleware), then, before that span ends, call
// MarkRecorded with it.
//
// Use it when the span active at Emit time may not be the Server span: a
// handler that emits from inside a client span (a RESTAction stage, an outbound
// call) would otherwise mark that span. With a holder installed, Emit marks the
// holder only, never the span on ctx. A holder already on ctx is kept, so
// nested wrappers share one.
//
// Without a holder, Emit sets SpanKeyRecorded on trace.SpanFromContext(ctx)
// itself, which is right when the Server span is the active one.
func WithRecordedMarker(ctx context.Context) context.Context {
	if markerFrom(ctx) != nil {
		return ctx
	}
	return context.WithValue(ctx, recordedMarkerKey{}, &recordedMarker{})
}

// Recorded reports whether Emit handed a record to the logger on ctx's
// holder. False when no holder is installed.
func Recorded(ctx context.Context) bool {
	m := markerFrom(ctx)
	return m != nil && m.v.Load()
}

// MarkRecorded sets SpanKeyRecorded=true on span when ctx's holder says a
// record was written. Call it on the Server span, before it ends. It does
// nothing when no record was written, so the attribute is only ever true.
func MarkRecorded(ctx context.Context, span trace.Span) {
	if Recorded(ctx) {
		span.SetAttributes(attribute.Bool(SpanKeyRecorded, true))
	}
}

// RecordedMiddleware is the server wrapper for an HTTP writer. It installs the
// holder, runs next, then marks the span that was active when the request
// reached it. Place it inside the middleware that starts the Server span
// (otelhttp.NewHandler), so that span is the active one here.
func RecordedMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := WithRecordedMarker(r.Context())
		server := trace.SpanFromContext(ctx)
		next.ServeHTTP(w, r.WithContext(ctx))
		MarkRecorded(ctx, server)
	})
}

// markRecorded is Emit's half: the holder when one is installed, else the
// span active on ctx.
func markRecorded(ctx context.Context) {
	if m := markerFrom(ctx); m != nil {
		m.v.Store(true)
		return
	}
	trace.SpanFromContext(ctx).SetAttributes(attribute.Bool(SpanKeyRecorded, true))
}

func markerFrom(ctx context.Context) *recordedMarker {
	m, _ := ctx.Value(recordedMarkerKey{}).(*recordedMarker)
	return m
}
