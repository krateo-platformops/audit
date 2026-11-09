package audit

// The v0.4.0 emitter (installer#716): the actor rule and its count, the
// markers and their count, the schema stamp, EventName, the W1 dual-write,
// delegation, preview and the request facts.

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// counted returns the sum of instrument name's points whose attribute key
// equals value.
func counted(t *testing.T, r *sdkmetric.ManualReader, name, key, value string) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := r.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	var n int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			for _, p := range m.Data.(metricdata.Sum[int64]).DataPoints {
				if v, ok := p.Attributes.Value(attribute.Key(key)); ok && v.AsString() == value {
					n += p.Value
				}
			}
		}
	}
	return n
}

// WithSessionIDForTest returns ctx whose baggage carries session.id = id.
func WithSessionIDForTest(t *testing.T, ctx context.Context, id string) context.Context {
	t.Helper()
	m, err := baggage.NewMember(BaggageSessionKey, id)
	if err != nil {
		t.Fatal(err)
	}
	b, err := baggage.New(m)
	if err != nil {
		t.Fatal(err)
	}
	return baggage.ContextWithBaggage(ctx, b)
}

func newBareEmitter(t *testing.T, opts ...Option) (*Emitter, *recorder, *sdkmetric.ManualReader) {
	t.Helper()
	rec := &recorder{}
	lp := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(rec)))
	t.Cleanup(func() { _ = lp.Shutdown(context.Background()) })
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })
	return New(lp.Logger("test"), append([]Option{WithMeterProvider(mp)}, opts...)...), rec, reader
}

// Gap a: a record that names no actor is never dropped. It is emitted without
// user.name, marked actor, and counted (installer#407: the trail records
// everything; a lost record is worse than an incomplete one).
func TestEmit_NoActorIsEmittedMarkedAndCounted(t *testing.T) {
	e, rec, reader := newBareEmitter(t)
	e.Emit(spanCtx(t), Event{Action: "rest.write", Verb: "post", ServerAddress: "api.example.com", Outcome: OutcomeSuccess})
	e.Emit(spanCtx(t), Event{UserRoles: []string{"g"}, Action: "x", Verb: "get", ServerAddress: "h"}) // roles, but no one named
	if len(rec.records) != 2 {
		t.Fatalf("%d records emitted without an actor, want 2: a record is never dropped", len(rec.records))
	}
	for i, r := range rec.records {
		a := attrs(r)
		if _, ok := a[KeyUserName]; ok {
			t.Errorf("record %d: user.name written with no actor", i)
		}
		if m := strings.Split(a[KeyIncomplete].AsString(), ","); !slices.Contains(m, "actor") {
			t.Errorf("record %d: incomplete = %q, want it to name actor", i, a[KeyIncomplete].AsString())
		}
		if a[KeyAction].AsString() == "" || a[KeySchemaVersion].AsString() != SchemaVersion {
			t.Errorf("record %d lost the rest of its record: %v", i, a)
		}
	}
	// The Event's fields are written as given: v0.3 wrote user.roles without user.name too.
	if got := attrs(rec.records[1])[KeyUserRoles].AsStringSlice(); !slices.Equal(got, []string{"g"}) {
		t.Errorf("user.roles = %v, want the Event's", got)
	}
	if got := counted(t, reader, MetricIncomplete, "marker", "actor"); got != 2 {
		t.Errorf("%s{marker=actor} = %d, want 2", MetricIncomplete, got)
	}
	// Check still reports it, as incomplete: a writer's tests see the gap.
	var kvs []attribute.KeyValue
	rec.records[0].WalkAttributes(func(kv attribute.KeyValue) bool { kvs = append(kvs, kv); return true })
	if !slices.Contains(Check(WriterController, kvs), Violation{Key: KeyUserName, Reason: ReasonIncomplete}) {
		t.Errorf("Check does not report the missing actor as incomplete: %v", Check(WriterController, kvs))
	}
	// Control: an event with an actor is not marked actor.
	e.Emit(spanCtx(t), Event{UserName: "alice", Action: "x", Verb: "get", ServerAddress: "h"})
	if slices.Contains(strings.Split(attrs(rec.records[2])[KeyIncomplete].AsString(), ","), "actor") || counted(t, reader, MetricIncomplete, "marker", "actor") != 2 {
		t.Errorf("an event with an actor was marked actor: %q", attrs(rec.records[2])[KeyIncomplete].AsString())
	}
}

func TestEmit_ActorPrecedence(t *testing.T) {
	e, rec, _ := newBareEmitter(t, WithActor("system:serviceaccount:ns:ctrl", ClassController))
	e.Emit(spanCtx(t), Event{Action: "x"})
	e.Emit(spanCtx(t), Event{UserName: "alice", UserRoles: []string{"devs"}, ActorClass: ClassHuman, Action: "x"})
	e.Emit(spanCtx(t), Event{UserRoles: []string{"devs"}, ActorClass: ClassHuman, Action: "x"})
	if len(rec.records) != 3 {
		t.Fatalf("records = %d", len(rec.records))
	}
	for i, want := range []struct{ name, class string }{
		{"system:serviceaccount:ns:ctrl", "controller"},
		{"alice", "human"},
		{"system:serviceaccount:ns:ctrl", "controller"}, // the event names no actor: its roles and class are not mixed in
	} {
		a := attrs(rec.records[i])
		if a[KeyUserName].AsString() != want.name || a[KeyActorClass].AsString() != want.class {
			t.Errorf("record %d: actor %q/%q, want %q/%q", i, a[KeyUserName].AsString(), a[KeyActorClass].AsString(), want.name, want.class)
		}
		if _, roles := a[KeyUserRoles]; roles != (i == 1) {
			t.Errorf("record %d: user.roles present = %v", i, roles)
		}
	}
}

// D2: a class that is not one of the four is omitted, never defaulted, and the
// record is marked and counted.
func TestEmit_UnknownClassIsOmittedAndMarked(t *testing.T) {
	for _, c := range []Class{"", "Human", "robot"} {
		e, rec, reader := newBareEmitter(t)
		e.Emit(spanCtx(t), Event{UserName: "alice", ActorClass: c, Action: "call", Verb: "create", ServerAddress: "h"})
		a := attrs(only(t, rec))
		if v, ok := a[KeyActorClass]; ok {
			t.Errorf("class %q: actor_class = %q, want it omitted", c, v.AsString())
		}
		if got := a[KeyIncomplete].AsString(); got != "actor_class" {
			t.Errorf("class %q: incomplete = %q, want actor_class", c, got)
		}
		if got := counted(t, reader, MetricIncomplete, "marker", "actor_class"); got != 1 {
			t.Errorf("class %q: %s{marker=actor_class} = %d, want 1", c, MetricIncomplete, got)
		}
	}
}

func TestEmit_StampsTheSchema(t *testing.T) {
	e, rec := newEmitter(t)
	e.Emit(spanCtx(t), Event{Action: "x"})
	r := only(t, rec)
	if r.EventName() != EventName {
		t.Errorf("LogRecord EventName = %q, want %q", r.EventName(), EventName)
	}
	a := attrs(r)
	if a[KeyEventName].AsString() != EventName || a[KeySchemaVersion].AsString() != SchemaVersion {
		t.Errorf("event.name = %q, schema_version = %q", a[KeyEventName].AsString(), a[KeySchemaVersion].AsString())
	}
	if r.Timestamp().IsZero() {
		t.Errorf("Timestamp not set")
	}
}

// W1: every v0.4 key with a v0.3 name is written under both, with one value.
func TestEmit_DualWritesTheV03Keys(t *testing.T) {
	e, rec := newEmitter(t)
	e.Emit(spanCtx(t), Event{
		UserName: "alice", Namespace: "ns", Group: "g.io", Version: "v1", Resource: "repoes", Subresource: "status",
		Kind: "Repo", ObjectName: "r", ObjectUID: "u", ObjectGeneration: 3, ObjectResourceVersion: "9",
		Outcome: OutcomeFailure, Action: "x",
	})
	a := attrs(only(t, rec))
	n := 0
	for _, k := range Keys() {
		if !k.DualWrite {
			continue
		}
		n++
		old, okOld := a[k.Name]
		cur, okCur := a[k.ReplacedBy]
		if !okOld || !okCur || old.String() != cur.String() || old.Type() != cur.Type() {
			t.Errorf("%s = %v (%v), %s = %v (%v): want both, equal", k.Name, old.String(), okOld, k.ReplacedBy, cur.String(), okCur)
		}
	}
	// outcome, six k8s.resource.* and three k8s.object.*: enduser.id is not
	// one of them (below).
	if n != 10 {
		t.Errorf("%d dual-written v0.3 keys, want 10", n)
	}
}

// enduser.id is written only where it is written today: by a caller that sets
// EndUserID (snowplow, identity-lifecycle). Emit never adds it.
func TestEmit_EndUserIDOnlyWhenTheCallerSetsIt(t *testing.T) {
	e, rec := newEmitter(t)
	e.Emit(spanCtx(t), Event{UserName: "alice", Action: "x"})
	e.Emit(spanCtx(t), Event{UserName: "alice", EndUserID: "alice", Action: "x"})
	e.Emit(spanCtx(t), Event{UserName: "alice", EndUserID: "bob", Action: "x"})
	if v, ok := attrs(rec.records[0])[KeyLegacyEndUserID]; ok {
		t.Errorf("enduser.id = %q added to a record whose caller never set it", v.AsString())
	}
	if got := attrs(rec.records[1])[KeyLegacyEndUserID].AsString(); got != "alice" {
		t.Errorf("enduser.id = %q, want the caller's", got)
	}
	// A value that differs from the actor is kept, and Check reports it.
	r := rec.records[2]
	if got := attrs(r)[KeyLegacyEndUserID].AsString(); got != "bob" {
		t.Errorf("enduser.id = %q, want the caller's", got)
	}
	var kvs []attribute.KeyValue
	r.WalkAttributes(func(kv attribute.KeyValue) bool { kvs = append(kvs, kv); return true })
	if !slices.Contains(Check(WriterController, kvs), Violation{Key: KeyLegacyEndUserID, Reason: ReasonLegacyDisagrees}) {
		t.Errorf("Check does not flag enduser.id disagreeing with user.name")
	}
}

func TestEmit_DelegationAndAffectedUser(t *testing.T) {
	e, rec := newEmitter(t)
	e.Emit(spanCtx(t), Event{
		UserName: "svc-bot", ActorClass: ClassAgent, OnBehalfOf: "alice",
		Delegation:   []Link{{ClassAgent, "svc-bot"}, {"", "relay"}, {Class("bogus"), "x"}, {ClassHuman, "alice"}},
		AffectedUser: "carol", Action: "x",
	})
	a := attrs(only(t, rec))
	if got := a[KeyDelegation].AsStringSlice(); !slices.Equal(got, []string{"agent:svc-bot", ":relay", ":x", "human:alice"}) {
		t.Errorf("delegation = %v", got)
	}
	if a[KeyOnBehalfOf].AsString() != "alice" || a[KeyAffectedUser].AsString() != "carol" {
		t.Errorf("on_behalf_of = %q, affected_user = %q", a[KeyOnBehalfOf].AsString(), a[KeyAffectedUser].AsString())
	}
}

func TestEmit_Preview(t *testing.T) {
	for _, tc := range []struct {
		p          Preview
		ns         string
		want       string // "" = absent
		incomplete bool
	}{
		{PreviewTrue, "krateo-preview", "true", false},
		{PreviewFalse, "tenant-a", "false", false},
		{PreviewUnknown, "tenant-a", "", true},
		{PreviewUnknown, "", "", false}, // cluster-scoped: nothing to mark
	} {
		e, rec := newEmitter(t)
		e.Emit(spanCtx(t), Event{Action: "x", Verb: "create", Namespace: tc.ns, Version: "v1", Resource: "configmaps", Preview: tc.p})
		a := attrs(only(t, rec))
		got := ""
		if v, ok := a[KeyPreview]; ok {
			got = v.String()
		}
		if got != tc.want {
			t.Errorf("preview %d in %q: %q, want %q", tc.p, tc.ns, got, tc.want)
		}
		if m := strings.Contains(a[KeyIncomplete].AsString(), "preview"); m != tc.incomplete {
			t.Errorf("preview %d in %q: marked = %v, want %v", tc.p, tc.ns, m, tc.incomplete)
		}
	}
}

func TestEmit_MarkersFollowTheWriter(t *testing.T) {
	ev := Event{UserName: "alice", ActorClass: ClassHuman, Action: "call", Verb: "create", ServerAddress: "h"}
	e, rec, _ := newBareEmitter(t)
	e.Emit(spanCtx(t), ev)
	if _, marked := attrs(only(t, rec))[KeyIncomplete]; marked {
		t.Errorf("no writer declared: a missing method is no gap for a controller, and must not be marked")
	}
	e, rec, reader := newBareEmitter(t, WithWriter(WriterRequest))
	e.Emit(spanCtx(t), ev)
	if got := attrs(only(t, rec))[KeyIncomplete].AsString(); got != "method" {
		t.Errorf("request writer: incomplete = %q, want method", got)
	}
	if counted(t, reader, MetricIncomplete, "marker", "method") != 1 {
		t.Errorf("the method gap is not counted")
	}
}

func TestEmit_HTTPMethodAsSemconvRecordsIt(t *testing.T) {
	for in, want := range map[string]string{"POST": "POST", "PATCH": "PATCH", "post": "_OTHER", "PROPFIND": "_OTHER"} {
		e, rec := newEmitter(t)
		e.Emit(spanCtx(t), Event{Action: "x", HTTPMethod: in})
		if got := attrs(only(t, rec))[KeyHTTPMethod].AsString(); got != want {
			t.Errorf("method %q recorded as %q, want %q", in, got, want)
		}
	}
}

func TestEmit_RequestFacts(t *testing.T) {
	e, rec := newEmitter(t)
	at := time.Unix(1700000000, 42)
	e.Emit(spanCtx(t), Event{
		Action: "call", RequestURI: "/call?name=x", SourceIPs: []string{"203.0.113.7", "10.0.0.1"},
		UserAgent: strings.Repeat("u", 2000), ReceivedTime: at,
		RESTActionNamespace: "ns", RESTActionName: "ra", RESTActionStage: "s1",
	})
	a := attrs(only(t, rec))
	if a[KeyRequestURI].AsString() != "/call?name=x" || !slices.Equal(a[KeySourceIPs].AsStringSlice(), []string{"203.0.113.7", "10.0.0.1"}) {
		t.Errorf("uri/source_ips = %q/%v", a[KeyRequestURI].AsString(), a[KeySourceIPs].AsStringSlice())
	}
	if ua := a[KeyUserAgent].AsString(); len(ua) != maxUserAgentLength+len(userAgentTruncateSuffix) {
		t.Errorf("user agent length %d", len(ua))
	}
	if a[KeyRequestReceivedTime].AsInt64() != at.UnixNano() {
		t.Errorf("received time = %d", a[KeyRequestReceivedTime].AsInt64())
	}
	if a[KeyRESTActionNamespace].AsString() != "ns" || a[KeyRESTActionName].AsString() != "ra" || a[KeyRESTActionStage].AsString() != "s1" {
		t.Errorf("restaction = %v", a)
	}
}

// Emit's output conforms for each Go writer class, for the record each one
// writes. The external audittest arms add the falsifier.
func TestEmit_OutputConforms(t *testing.T) {
	for _, tc := range []struct {
		w    Writer
		opts []Option
		ev   Event
	}{
		{WriterController, nil, Event{Action: "rest.write", Verb: "post", HTTPMethod: "POST", StatusCode: 201, Outcome: OutcomeSuccess,
			Namespace: "ns", Group: "github.krateo.io", Version: "v1alpha1", Resource: "repoes", Kind: "Repo", ObjectName: "r",
			ObjectUID: "u", ObjectGeneration: 2, ServerAddress: "https://api.github.com/x", Preview: PreviewFalse}},
		{WriterAction, []Option{WithActor("kagent-tools", ClassAgent)}, Event{Action: "tool.call", Verb: "create", Outcome: OutcomeSuccess,
			Namespace: "ns", Version: "v1", Resource: "configmaps", ObjectName: "cm", Preview: PreviewTrue}},
		{WriterRequest, []Option{WithWriter(WriterRequest)}, Event{UserName: "alice", UserRoles: []string{"devs"}, ActorClass: ClassHuman,
			Action: "call", Verb: "create", HTTPMethod: "POST", StatusCode: 201, Outcome: OutcomeSuccess,
			Namespace: "ns", Version: "v1", Resource: "configmaps", ObjectName: "cm", Preview: PreviewFalse,
			RequestURI: "/call", SourceIPs: []string{"10.0.0.1"}}},
	} {
		e, rec := newEmitter(t, tc.opts...)
		ctx := spanCtx(t)
		if tc.w != WriterController { // a reconcile has no inbound baggage
			ctx = WithSessionIDForTest(t, ctx, "s-1")
		}
		e.Emit(ctx, tc.ev)
		r := only(t, rec)
		var kvs []attribute.KeyValue
		r.WalkAttributes(func(kv attribute.KeyValue) bool { kvs = append(kvs, kv); return true })
		if vs := CheckRecord(tc.w, r.EventName(), kvs); len(vs) > 0 {
			t.Errorf("%s: %v", tc.w, vs)
		}
	}
}
