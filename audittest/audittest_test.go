package audittest_test

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/krateo-platformops/audit"
	"github.com/krateo-platformops/audit/audittest"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func spanCtx(t *testing.T) context.Context {
	t.Helper()
	tp := sdktrace.NewTracerProvider()
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	ctx, span := tp.Tracer("test").Start(context.Background(), "op")
	t.Cleanup(func() { span.End() })
	return ctx
}

func sessionCtx(t *testing.T) context.Context {
	t.Helper()
	m, _ := baggage.NewMember(audit.BaggageSessionKey, "sess-1")
	b, _ := baggage.New(m)
	return baggage.ContextWithBaggage(spanCtx(t), b)
}

const sa = "system:serviceaccount:krateo-system:controller"

// Each Go writer's records, as the callers will write them after adopting
// v0.4.0, conform; and every key the writer must write is load-bearing.
func TestWriters_ConformAndEveryRequiredKeyIsDetected(t *testing.T) {
	for _, tc := range []struct {
		name  string
		w     audit.Writer
		opts  []audit.Option
		ctx   func(*testing.T) context.Context
		ev    audit.Event
		allow []string
	}{
		{
			name: "rest-dynamic-controller external write", w: audit.WriterController,
			opts: []audit.Option{audit.WithActor(sa, audit.ClassController)}, ctx: spanCtx,
			ev: audit.Event{Message: "external write succeeded", Action: "rest.write", Verb: "post", HTTPMethod: "POST", StatusCode: 201,
				Outcome: audit.OutcomeSuccess, Namespace: "tenant-a", Group: "github.krateo.io", Version: "v1alpha1",
				Resource: "repoes", Kind: "Repo", ObjectName: "demo", ObjectUID: "uid-1", ObjectGeneration: 3,
				ServerAddress: "https://api.github.com/orgs/x/repos", Preview: audit.PreviewFalse},
		},
		{
			name: "access-review revoke", w: audit.WriterController,
			opts: []audit.Option{audit.WithActor(sa, audit.ClassController)}, ctx: spanCtx,
			ev: audit.Event{Message: "grant revoked", AffectedUser: "alice", Action: "revoke", Verb: "delete",
				Outcome: audit.OutcomeSuccess, Namespace: "tenant-a", Group: "rbac.authorization.k8s.io", Version: "v1",
				Resource: "rolebindings", Kind: "RoleBinding", ObjectName: "alice-edit", Preview: audit.PreviewFalse},
		},
		{
			name: "identity-lifecycle deactivation (cluster-scoped IdP action)", w: audit.WriterController,
			opts: []audit.Option{audit.WithActor(sa, audit.ClassController)}, ctx: spanCtx,
			ev: audit.Event{Message: "account disabled", AffectedUser: "bob", Action: "deactivate", Verb: "post",
				Outcome: audit.OutcomeSuccess, ServerAddress: "idp.example.com"},
		},
		{
			name: "tool executor", w: audit.WriterAction,
			opts: []audit.Option{audit.WithActor("kagent-tools", audit.ClassAgent)}, ctx: sessionCtx,
			ev: audit.Event{Action: "tool.k8s.create", Verb: "create", Outcome: audit.OutcomeSuccess,
				Namespace: "krateo-preview", Version: "v1", Resource: "configmaps", ObjectName: "draft", Preview: audit.PreviewTrue},
		},
		{
			name: "snowplow /call, delegated token", w: audit.WriterRequest,
			opts: []audit.Option{audit.WithWriter(audit.WriterRequest)}, ctx: sessionCtx,
			ev: audit.Event{UserName: "svc-bot", ActorClass: audit.ClassAgent, OnBehalfOf: "alice",
				Delegation: []audit.Link{{Class: audit.ClassAgent, Subject: "svc-bot"}, {Class: audit.ClassHuman, Subject: "alice"}},
				Action:     "call", Verb: "create", HTTPMethod: "POST", StatusCode: 201, Outcome: audit.OutcomeSuccess,
				Namespace: "tenant-a", Version: "v1", Resource: "configmaps", ObjectName: "cm", Preview: audit.PreviewFalse,
				RequestURI: "/call?name=cm", SourceIPs: []string{"10.0.0.1"}, UserAgent: "portal/1.0"},
		},
		{
			name: "snowplow /call, token minted before the principal claim", w: audit.WriterRequest,
			opts: []audit.Option{audit.WithWriter(audit.WriterRequest)}, ctx: sessionCtx,
			ev: audit.Event{UserName: "alice", UserRoles: []string{"devs"}, Action: "call", Verb: "get", HTTPMethod: "GET",
				StatusCode: 200, Outcome: audit.OutcomeSuccess, ServerAddress: "api.example.com",
				RequestURI: "/call", SourceIPs: []string{"10.0.0.1"}},
			allow: []string{audit.KeyActorClass},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := audittest.NewRecorder(t)
			e := audit.New(rec.Logger("test/audit"), tc.opts...)
			e.Emit(tc.ctx(t), tc.ev)
			r := rec.Only(t)
			opts := []audittest.Option{audittest.AllowIncomplete(tc.allow...)}
			audittest.AssertConformant(t, tc.w, r, opts...)
			audittest.AssertRequiredKeysDetected(t, tc.w, r, opts...)
		})
	}
}

// fakeTB records failures instead of failing, so the helpers' own failures
// can be asserted. Fatalf ends the goroutine, as testing.T's does.
type fakeTB struct {
	testing.TB
	mu   sync.Mutex
	msgs []string
}

func (f *fakeTB) Helper() {}
func (f *fakeTB) Errorf(format string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.msgs = append(f.msgs, fmt.Sprintf(format, args...))
}
func (f *fakeTB) Fatalf(format string, args ...any) {
	f.Errorf(format, args...)
	runtime.Goexit()
}

// failures runs fn against a fakeTB and returns what it reported.
func failures(t *testing.T, fn func(tb testing.TB)) []string {
	f := &fakeTB{TB: t}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		fn(f)
	}()
	wg.Wait()
	return f.msgs
}

func controllerRecord(t *testing.T, ev audit.Event) (*audittest.Recorder, audit.Writer) {
	rec := audittest.NewRecorder(t)
	audit.New(rec.Logger("test/audit"), audit.WithActor(sa, audit.ClassController)).Emit(spanCtx(t), ev)
	return rec, audit.WriterController
}

func TestAssertConformant_FailsOnABreach(t *testing.T) {
	rec, w := controllerRecord(t, audit.Event{Action: "rest.write", ServerAddress: "h", Outcome: audit.OutcomeSuccess}) // no verb
	r := rec.Only(t)
	msgs := failures(t, func(tb testing.TB) { audittest.AssertConformant(tb, w, r) })
	if len(msgs) != 1 || !strings.Contains(msgs[0], audit.KeyVerb+": incomplete") {
		t.Errorf("AssertConformant on a record without a verb reported %q", msgs)
	}
	if msgs := failures(t, func(tb testing.TB) { audittest.AssertConformant(tb, w, r, audittest.AllowIncomplete(audit.KeyVerb)) }); len(msgs) != 0 {
		t.Errorf("AllowIncomplete(verb) still fails: %q", msgs)
	}
}

func TestAssertRemovalDetected_FailsWhenTheRemovalIsNotCaught(t *testing.T) {
	rec, w := controllerRecord(t, audit.Event{Action: "rest.write", Verb: "post", ServerAddress: "h", Outcome: audit.OutcomeSuccess, StatusCode: 201})
	r := rec.Only(t)
	// http.response.status_code is conditional on what the record cannot show:
	// removing it is not detected, and the falsifier must say so.
	msgs := failures(t, func(tb testing.TB) { audittest.AssertRemovalDetected(tb, w, r, audit.KeyHTTPStatusCode) })
	if len(msgs) == 0 || !strings.Contains(msgs[0], "is not detected") {
		t.Errorf("removing an optional key was reported as detected: %q", msgs)
	}
	// Positive control: a required key is caught.
	if msgs := failures(t, func(tb testing.TB) { audittest.AssertRemovalDetected(tb, w, r, audit.KeyVerb) }); len(msgs) != 0 {
		t.Errorf("removing verb: %q", msgs)
	}
	// A key the record does not carry proves nothing.
	if msgs := failures(t, func(tb testing.TB) { audittest.AssertRemovalDetected(tb, w, r, audit.KeyPreview) }); len(msgs) != 1 || !strings.Contains(msgs[0], "does not carry") {
		t.Errorf("removing an absent key: %q", msgs)
	}
}

func TestAssertRemovalDetected_NeedsAConformantRecord(t *testing.T) {
	rec, w := controllerRecord(t, audit.Event{Action: "rest.write", ServerAddress: "h", Outcome: audit.OutcomeSuccess}) // no verb
	r := rec.Only(t)
	msgs := failures(t, func(tb testing.TB) { audittest.AssertRemovalDetected(tb, w, r, audit.KeyAction) })
	if len(msgs) != 1 || !strings.Contains(msgs[0], "needs a conformant record") {
		t.Errorf("falsifier on a non-conformant record: %q", msgs)
	}
}

func TestAssertViolation(t *testing.T) {
	attrs := []attribute.KeyValue{attribute.String("krateo.audit.bogus", "x")}
	if msgs := failures(t, func(tb testing.TB) {
		audittest.AssertViolation(tb, audit.WriterController, attrs, "krateo.audit.bogus")
	}); len(msgs) != 0 {
		t.Errorf("an unknown key is not a violation: %q", msgs)
	}
	if msgs := failures(t, func(tb testing.TB) { audittest.AssertViolation(tb, audit.WriterController, attrs, audit.KeyObjectKind) }); len(msgs) != 1 {
		t.Errorf("AssertViolation passed for a key with no violation: %q", msgs)
	}
}

// The helpers' messages name keys and reasons, never a value.
func TestHelpers_NeverPrintAValue(t *testing.T) {
	const secret = "carol.identity.marker"
	rec, w := controllerRecord(t, audit.Event{Action: secret, AffectedUser: secret, ObjectName: secret, Outcome: "nope-" + secret})
	r := rec.Only(t)
	all := failures(t, func(tb testing.TB) { audittest.AssertConformant(tb, w, r) })
	all = append(all, failures(t, func(tb testing.TB) { audittest.AssertRemovalDetected(tb, w, r, audit.KeyAction) })...)
	if len(all) == 0 {
		t.Fatal("precondition: the record should fail")
	}
	for _, m := range all {
		if strings.Contains(m, secret) {
			t.Errorf("a helper printed a value: %q", m)
		}
	}
}
