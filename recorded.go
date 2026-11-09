package audit

import (
	"context"
	"log/slog"
	"net/http"
	"sync/atomic"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// SpanKeyRecorded is the span attribute that says a span's work wrote an audit
// record: krateo.audit.recorded=true. observability's tail sampler keeps such
// traces whole, with one rule for every writer
// (span.attributes["krateo.audit.recorded"] == true).
//
// The marker reaches a trace only if the caller's ctx carries a holder or a
// recording span at Emit time. Emit marks the WithRecordedMarker holder when one
// is installed; otherwise the span active on ctx, whatever its kind (a
// controller with no Server span has its client span marked), but only while
// that span records. An ended span drops attributes silently, so Emit does not
// mark it. When neither target exists, the record is still emitted, never
// dropped; the miss is counted under MetricRecordedMarkerUnattached{reason}
// and logged once per process at WARN (slog.Default), naming the key and the
// reason only.
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
// itself, while that span records: right when the Server span is the active
// one, and the only target for a writer with no Server span.
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

// Why Emit could not attach the marker (the reason attribute of
// MetricRecordedMarkerUnattached, and of its one WARN).
const (
	unattachedNoSpan       = "no_span"       // no holder, and no span on ctx
	unattachedNotRecording = "not_recording" // no holder, and the span on ctx has ended or does not record
)

// markRecorded is Emit's half. It marks the holder when one is installed,
// else the span active on ctx, of any kind, but only while that span records:
// an ended span drops attributes silently. It returns "" when the marker is
// attached, else why not.
func markRecorded(ctx context.Context) (unattached string) {
	if m := markerFrom(ctx); m != nil {
		m.v.Store(true)
		return ""
	}
	span := trace.SpanFromContext(ctx)
	if !span.IsRecording() {
		if !span.SpanContext().IsValid() {
			return unattachedNoSpan
		}
		return unattachedNotRecording
	}
	span.SetAttributes(attribute.Bool(SpanKeyRecorded, true))
	return ""
}

// unattachedWarned makes the WARN about an unattached marker once per
// process: the counter carries every occurrence, and one log line is enough
// to point an operator at it.
var unattachedWarned atomic.Bool

// warnUnattached logs, once per process, that a record's marker reached no
// trace. Metadata only: the key and the reason, never a value of the record.
func warnUnattached(reason string) {
	if !unattachedWarned.CompareAndSwap(false, true) {
		return
	}
	slog.Warn("audit: the recorded marker reached no trace (no WithRecordedMarker holder and no recording span on ctx); the record itself was emitted, every miss is counted under "+MetricRecordedMarkerUnattached,
		"key", SpanKeyRecorded, "reason", reason)
}

func markerFrom(ctx context.Context) *recordedMarker {
	m, _ := ctx.Value(recordedMarkerKey{}).(*recordedMarker)
	return m
}
