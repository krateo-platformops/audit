package audit

// krateo.audit.recorded: the span marker that lets observability's tail sampler
// keep a trace whole when its request wrote an audit record. Emit sets it only
// once the logger has taken a record; on the WithRecordedMarker holder when one
// is installed (the Server span is marked from it at span end), else on the
// span active on ctx.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/embedded"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// tracer returns a real SDK tracer whose ended spans sr keeps.
func tracer(t *testing.T) (trace.Tracer, *tracetest.SpanRecorder) {
	t.Helper()
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	return tp.Tracer("test"), sr
}

// recordedOn reports the marker's value on the ended span called name, and
// whether it is there at all.
func recordedOn(t *testing.T, sr *tracetest.SpanRecorder, name string) (value, present bool) {
	t.Helper()
	for _, s := range sr.Ended() {
		if s.Name() != name {
			continue
		}
		for _, kv := range s.Attributes() {
			if string(kv.Key) == SpanKeyRecorded {
				if kv.Value.Type() != attribute.BOOL {
					t.Fatalf("%s on %s is a %v: it must be a boolean, never identity", SpanKeyRecorded, name, kv.Value.Type())
				}
				return kv.Value.AsBool(), true
			}
		}
		return false, false
	}
	t.Fatalf("no ended span %q", name)
	return false, false
}

// fakeLogger is a Logs API logger that reports enabled as told and counts the
// records handed to it.
type fakeLogger struct {
	embedded.Logger
	enabled bool
	emitted atomic.Int64
}

func (l *fakeLogger) Emit(context.Context, otellog.Record) { l.emitted.Add(1) }
func (l *fakeLogger) Enabled(context.Context, otellog.EnabledParameters) bool {
	return l.enabled
}

func recordedEmitter(t *testing.T) *Emitter {
	t.Helper()
	return New(loggerFor(t, &recorder{}), WithActor(testActor, ClassController))
}

var recordedEvent = Event{Action: "x", Verb: "create", ServerAddress: "h", Outcome: OutcomeSuccess}

func TestRecorded_WithoutAHolderEmitMarksTheActiveSpan(t *testing.T) {
	tr, sr := tracer(t)
	ctx, span := tr.Start(context.Background(), "server")
	recordedEmitter(t).Emit(ctx, recordedEvent)
	span.End()
	if v, ok := recordedOn(t, sr, "server"); !ok || !v {
		t.Errorf("%s = %v (present %v) on the active span, want true", SpanKeyRecorded, v, ok)
	}
	// Control: a request whose handler emits nothing carries no marker.
	_, quiet := tr.Start(context.Background(), "quiet")
	quiet.End()
	if _, ok := recordedOn(t, sr, "quiet"); ok {
		t.Errorf("a span with no record carries %s", SpanKeyRecorded)
	}
}

// The handler emits from inside a client span (a RESTAction stage): with the
// holder installed on the server's context, the client span is not marked;
// the Server span is, from the holder, at its end.
func TestRecorded_WithAHolderTheServerSpanIsMarkedNotTheActiveOne(t *testing.T) {
	tr, sr := tracer(t)
	serverCtx, server := tr.Start(context.Background(), "server")
	serverCtx = WithRecordedMarker(serverCtx)
	if Recorded(serverCtx) {
		t.Fatalf("a fresh holder reads recorded")
	}
	stageCtx, stage := tr.Start(serverCtx, "stage", trace.WithSpanKind(trace.SpanKindClient))
	recordedEmitter(t).Emit(stageCtx, recordedEvent)
	stage.End()
	if !Recorded(serverCtx) {
		t.Fatalf("Emit did not set the holder")
	}
	MarkRecorded(serverCtx, server)
	server.End()
	if _, ok := recordedOn(t, sr, "stage"); ok {
		t.Errorf("the client span active at Emit time was marked; the holder must take it")
	}
	if v, ok := recordedOn(t, sr, "server"); !ok || !v {
		t.Errorf("the Server span: %s = %v (present %v), want true", SpanKeyRecorded, v, ok)
	}
	// A nested install keeps the one holder.
	if inner := WithRecordedMarker(serverCtx); !Recorded(inner) {
		t.Errorf("a nested WithRecordedMarker replaced the holder")
	}
}

// A record that does not reach a logger that takes it marks nothing: a nil
// Emitter, a nil logger, or a logger disabled for the record. Emit still hands
// the record to a disabled logger (a record is never dropped here); it only
// does not claim it was recorded.
func TestRecorded_ARecordNotTakenMarksNothing(t *testing.T) {
	disabled := &fakeLogger{enabled: false}
	enabled := &fakeLogger{enabled: true}
	var nilEmitter *Emitter
	for _, tc := range []struct {
		name string
		e    *Emitter
		want bool
	}{
		{"nil emitter", nilEmitter, false},
		{"nil logger", New(nil, WithActor(testActor, ClassController)), false},
		{"disabled logger", New(disabled, WithActor(testActor, ClassController)), false},
		{"enabled logger (control)", New(enabled, WithActor(testActor, ClassController)), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr, sr := tracer(t)
			ctx, span := tr.Start(context.Background(), "server")
			holderCtx := WithRecordedMarker(ctx)
			tc.e.Emit(holderCtx, recordedEvent) // the holder
			tc.e.Emit(ctx, recordedEvent)       // the active span
			span.End()
			if got := Recorded(holderCtx); got != tc.want {
				t.Errorf("holder: recorded = %v, want %v", got, tc.want)
			}
			if v, ok := recordedOn(t, sr, "server"); ok != tc.want || (ok && !v) {
				t.Errorf("span: %s = %v (present %v), want present %v", SpanKeyRecorded, v, ok, tc.want)
			}
		})
	}
	if disabled.emitted.Load() != 2 {
		t.Errorf("the disabled logger was handed %d records, want 2: Emit must not drop them", disabled.emitted.Load())
	}
}

func TestRecorded_ConcurrentEmitsAreSafe(t *testing.T) {
	tr, sr := tracer(t)
	ctx, span := tr.Start(context.Background(), "server")
	holderCtx := WithRecordedMarker(ctx)
	e := recordedEmitter(t)
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); e.Emit(holderCtx, recordedEvent) }() // the holder
		go func() { defer wg.Done(); e.Emit(ctx, recordedEvent) }()       // the span itself
	}
	wg.Wait()
	span.End()
	if !Recorded(holderCtx) {
		t.Errorf("the holder lost the concurrent emits")
	}
	if v, ok := recordedOn(t, sr, "server"); !ok || !v {
		t.Errorf("the span lost the concurrent emits")
	}
}

// RecordedMiddleware, placed inside the middleware that starts the Server span
// (as it is inside otelhttp.NewHandler), marks that span when the handler
// wrote a record, from whatever span the handler emitted in, and only then.
func TestRecordedMiddleware(t *testing.T) {
	for _, tc := range []struct {
		name string
		emit bool
	}{{"handler writes a record", true}, {"handler writes none", false}} {
		t.Run(tc.name, func(t *testing.T) {
			tr, sr := tracer(t)
			e := recordedEmitter(t)
			handler := RecordedMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				stageCtx, stage := tr.Start(r.Context(), "stage", trace.WithSpanKind(trace.SpanKindClient))
				if tc.emit {
					e.Emit(stageCtx, recordedEvent)
				}
				stage.End()
			}))
			// What otelhttp does around it: start the Server span, end it after.
			outer := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx, server := tr.Start(r.Context(), "server", trace.WithSpanKind(trace.SpanKindServer))
				handler.ServeHTTP(w, r.WithContext(ctx))
				server.End()
			})
			outer.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/call", nil))
			v, ok := recordedOn(t, sr, "server")
			if ok != tc.emit || (ok && !v) {
				t.Errorf("Server span: %s = %v (present %v), want present %v", SpanKeyRecorded, v, ok, tc.emit)
			}
			if _, ok := recordedOn(t, sr, "stage"); ok {
				t.Errorf("the stage span was marked")
			}
		})
	}
}
