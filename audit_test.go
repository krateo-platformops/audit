package audit

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// recorder is an in-memory exporter behind a real LoggerProvider, so these
// tests exercise the actual OTel Logs SDK pipeline (Record construction,
// TraceId/SpanId stamping from ctx), not a fake logger.
type recorder struct{ records []sdklog.Record }

func (r *recorder) Export(_ context.Context, recs []sdklog.Record) error {
	r.records = append(r.records, recs...)
	return nil
}
func (r *recorder) Shutdown(context.Context) error   { return nil }
func (r *recorder) ForceFlush(context.Context) error { return nil }

func newEmitter(t *testing.T) (*Emitter, *recorder) {
	t.Helper()
	rec := &recorder{}
	lp := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(rec)))
	t.Cleanup(func() { _ = lp.Shutdown(context.Background()) })
	return New(lp.Logger("test")), rec
}

func attrs(r sdklog.Record) map[string]attribute.Value {
	out := map[string]attribute.Value{}
	r.WalkAttributes(func(kv attribute.KeyValue) bool {
		out[string(kv.Key)] = kv.Value
		return true
	})
	return out
}

func only(t *testing.T, rec *recorder) sdklog.Record {
	t.Helper()
	if len(rec.records) != 1 {
		t.Fatalf("records = %d, want 1", len(rec.records))
	}
	return rec.records[0]
}

func spanCtx(t *testing.T) context.Context {
	t.Helper()
	tp := sdktrace.NewTracerProvider()
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	ctx, span := tp.Tracer("test").Start(context.Background(), "op")
	t.Cleanup(func() { span.End() })
	return ctx
}

func TestEmit_CanonicalRecord(t *testing.T) {
	e, rec := newEmitter(t)
	ctx := spanCtx(t)
	m, err := baggage.NewMember(BaggageSessionKey, "sess-123")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := baggage.New(m)
	ctx = baggage.ContextWithBaggage(ctx, b)

	e.Emit(ctx, Event{
		Message: "created repo", UserName: "mario.rossi", EndUserID: "mario.rossi",
		Namespace: "tenant-a", Group: "github.krateo.io", Version: "v1alpha1",
		Resource: "repoes", Kind: "Repo", ObjectName: "demo",
		Action: "rest.write", HTTPMethod: "POST", StatusCode: 201, Outcome: OutcomeSuccess,
		ServerAddress: "api.github.com",
	})

	r := only(t, rec)
	a := attrs(r)
	want := map[string]string{
		"event.name": "audit", "user.name": "mario.rossi", "enduser.id": "mario.rossi",
		"k8s.namespace.name": "tenant-a", "k8s.resource.group": "github.krateo.io",
		"k8s.resource.version": "v1alpha1", "k8s.resource.resource": "repoes",
		"k8s.resource.kind": "Repo", "k8s.resource.name": "demo",
		"krateo.action": "rest.write", "http.request.method": "POST",
		"outcome": "success", "server.address": "api.github.com", "session.id": "sess-123",
	}
	for k, v := range want {
		if got := a[k].AsString(); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if got := a["http.response.status_code"].AsInt64(); got != 201 {
		t.Errorf("http.response.status_code = %d, want 201", got)
	}
	if r.Severity() != otellog.SeverityInfo || r.SeverityText() != "INFO" {
		t.Errorf("severity = %v/%q, want Info/INFO", r.Severity(), r.SeverityText())
	}
	if r.Body().AsString() != "created repo" {
		t.Errorf("body = %q", r.Body().AsString())
	}
	if !r.TraceID().IsValid() {
		t.Errorf("TraceId not stamped from the span on ctx")
	}
	if _, flagged := a["krateo.audit.no_trace_context"]; flagged {
		t.Errorf("no_trace_context must not be set when a span is present")
	}
}

// The Option-B join key must use exactly the attribute names snowplow records
// (snowplow#957), or the (uid, generation) join silently never matches.
func TestEmit_ObjectIdentityForTheJoin(t *testing.T) {
	e, rec := newEmitter(t)
	e.Emit(spanCtx(t), Event{
		ObjectUID: "0b6c1f4e-9a1c-4c51-8d0a-1f2e3d4c5b6a", ObjectGeneration: 7,
		ObjectResourceVersion: "123456", Outcome: OutcomeSuccess,
	})
	a := attrs(only(t, rec))
	if got := a["k8s.object.uid"].AsString(); got != "0b6c1f4e-9a1c-4c51-8d0a-1f2e3d4c5b6a" {
		t.Errorf("k8s.object.uid = %q", got)
	}
	if got := a["k8s.object.generation"].AsInt64(); got != 7 {
		t.Errorf("k8s.object.generation = %d, want 7", got)
	}
	if got := a["k8s.object.resource_version"].AsString(); got != "123456" {
		t.Errorf("k8s.object.resource_version = %q", got)
	}
}

func TestEmit_OmitsUnsetFields(t *testing.T) {
	e, rec := newEmitter(t)
	e.Emit(spanCtx(t), Event{Action: "call"})
	a := attrs(only(t, rec))
	for _, k := range []string{
		"user.name", "enduser.id", "user.roles", "k8s.namespace.name", "k8s.resource.name",
		"k8s.object.uid", "k8s.object.generation", "k8s.object.resource_version",
		"server.address", "http.request.method", "http.response.status_code", "outcome", "session.id",
	} {
		if _, ok := a[k]; ok {
			t.Errorf("%s present but was never set", k)
		}
	}
	if a["event.name"].AsString() != "audit" || a["krateo.action"].AsString() != "call" {
		t.Errorf("discriminator/action missing: %v", a)
	}
}

func TestEmit_NonSuccessIsError(t *testing.T) {
	for _, o := range []string{OutcomeFailure, OutcomeDenied} {
		e, rec := newEmitter(t)
		e.Emit(spanCtx(t), Event{Outcome: o})
		r := only(t, rec)
		if r.Severity() != otellog.SeverityError || r.SeverityText() != "ERROR" {
			t.Errorf("outcome %q: severity = %v/%q, want Error/ERROR", o, r.Severity(), r.SeverityText())
		}
	}
}

func TestEmit_RolesAreASlice(t *testing.T) {
	e, rec := newEmitter(t)
	e.Emit(spanCtx(t), Event{UserRoles: []string{"admins", "devs"}})
	v := attrs(only(t, rec))["user.roles"]
	if v.Type() != attribute.SLICE {
		t.Fatalf("user.roles kind = %v, want Slice", v.Type())
	}
	s := v.AsSlice()
	if len(s) != 2 || s[0].AsString() != "admins" || s[1].AsString() != "devs" {
		t.Errorf("user.roles = %v", s)
	}
}

func TestEmit_NoTraceContextIsFlagged(t *testing.T) {
	e, rec := newEmitter(t)
	e.Emit(context.Background(), Event{Action: "call"})
	r := only(t, rec)
	if r.TraceID().IsValid() {
		t.Errorf("TraceId stamped without a span on ctx")
	}
	if !attrs(r)["krateo.audit.no_trace_context"].AsBool() {
		t.Errorf("a record with no trace context must carry krateo.audit.no_trace_context=true")
	}
}

func TestEmit_NilSafe(t *testing.T) {
	var nilEmitter *Emitter
	nilEmitter.Emit(context.Background(), Event{Action: "call"}) // must not panic
	New(nil).Emit(context.Background(), Event{Action: "call"})   // must not panic
}
