package audittest

import (
	"context"
	"slices"
	"testing"

	"github.com/krateo-platformops/audit"
	"go.opentelemetry.io/otel/baggage"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// audit#26: relatedTo derives the per-action relation from the schema, and
// only that: krateo.action is related to every key whose closed set the
// writer declares per action, for that writer only, and no other key's
// change relates to them.
func TestRelatedTo_PerActionSetsFollowTheAction(t *testing.T) {
	var perAction []string // keys with a per-action set for the request writer, read from the schema
	for _, k := range audit.Keys() {
		if len(k.Writers[audit.WriterRequest].ActionValues) > 0 {
			perAction = append(perAction, k.Name)
		}
	}
	if !slices.Contains(perAction, audit.KeyCheckResult) {
		t.Fatalf("precondition: the request writer declares no per-action set for check_result: %v", perAction)
	}
	for _, tc := range []struct {
		name string
		w    audit.Writer
		key  string
		want bool
	}{
		{"request, krateo.action", audit.WriterRequest, audit.KeyAction, true},
		{"request, krateo.audit.verb", audit.WriterRequest, audit.KeyVerb, false},
		{"request, user.name", audit.WriterRequest, audit.KeyUserName, false},
		{"controller, krateo.action (no per-action set)", audit.WriterController, audit.KeyAction, false},
		{"gateway, krateo.action (no per-action set)", audit.WriterGateway, audit.KeyAction, false},
	} {
		related := relatedTo(tc.w, tc.key, nil, nil)
		for _, k := range perAction {
			if related[k] != tc.want {
				t.Errorf("%s: %s related = %v, want %v", tc.name, k, related[k], tc.want)
			}
		}
	}
}

// v0.9.0 (audit#23): a per-action set (krateo.audit.check_result) is
// exercised on a record of its action, so a value outside the set of
// authn.username.check is caught as bad-enum and nothing else is. Method
// GET, derived from verb get, as the schema defines http.request.method.
func TestAssertEnumsDetected_ExercisesThePerActionSet(t *testing.T) {
	var got []string
	enumsTested = func(keys []string) { got = keys }
	t.Cleanup(func() { enumsTested = nil })

	tp := sdktrace.NewTracerProvider()
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	ctx, span := tp.Tracer("test").Start(context.Background(), "usernames.check")
	defer span.End()
	m, _ := baggage.NewMember(audit.BaggageSessionKey, "sess-1")
	b, _ := baggage.New(m)
	ctx = baggage.ContextWithBaggage(ctx, b)

	rec := NewRecorder(t)
	audit.New(rec.Logger("test/audit"), audit.WithWriter(audit.WriterRequest)).Emit(ctx, audit.Event{
		UserName: "system:serviceaccount:example-system:example-controller", ActorClass: audit.ClassService,
		Action: "authn.username.check", Verb: "get", HTTPMethod: "GET", Outcome: audit.OutcomeSuccess,
		CheckResult: audit.CheckResultNameClaimed, Namespace: "example-system", Version: "v1", Resource: "secrets",
		ObjectName: "example-user-clientconfig", Preview: audit.PreviewFalse, RequestURI: "/usernames/check",
		SourceIPs: []string{"192.0.2.10"}})
	AssertEnumsDetected(t, audit.WriterRequest, rec.Only(t))
	if !slices.Contains(got, audit.KeyCheckResult) {
		t.Errorf("AssertEnumsDetected did not exercise %s: %v", audit.KeyCheckResult, got)
	}
}

// AssertEnumsDetected exercises every closed set the record carries: the
// key-level enums, and the writer's own set for the denial reason. Without
// this pin, a helper that skipped the per-writer sets would stay green on
// every record, since verb and outcome keep it busy.
func TestAssertEnumsDetected_ExercisesTheWritersOwnSet(t *testing.T) {
	var got []string
	enumsTested = func(keys []string) { got = keys }
	t.Cleanup(func() { enumsTested = nil })

	tp := sdktrace.NewTracerProvider()
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	ctx, span := tp.Tracer("test").Start(context.Background(), "reconcile")
	defer span.End()

	rec := NewRecorder(t)
	audit.New(rec.Logger("test/audit"),
		audit.WithWriter(audit.WriterController),
		audit.WithActor("system:serviceaccount:example-system:example-controller", audit.ClassController),
	).Emit(ctx, audit.Event{Action: "helm.uninstall", Verb: "delete", Outcome: audit.OutcomeDenied,
		DenialReason: audit.DenialReasonKeptResourcePolicy, ServerAddress: "api.example.com"})
	AssertEnumsDetected(t, audit.WriterController, rec.Only(t))

	// Every key on the record with a closed set for the controller, written
	// out by hand, not derived from the schema the helper reads.
	want := []string{audit.KeyEventName, audit.KeySchemaVersion, audit.KeyActorClass, audit.KeyVerb,
		audit.KeyOutcome, audit.KeyDenialReason, audit.KeyLegacyOutcome}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("AssertEnumsDetected exercised\n %v\nwant\n %v", got, want)
	}
}

// The client keys' closed sets are exercised too: source on an accepted
// header's record, rejected on a rejected one's.
func TestAssertEnumsDetected_ExercisesTheClientSets(t *testing.T) {
	var got []string
	enumsTested = func(keys []string) { got = append(got, keys...) }
	t.Cleanup(func() { enumsTested = nil })

	tp := sdktrace.NewTracerProvider()
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	ctx, span := tp.Tracer("test").Start(context.Background(), "call")
	defer span.End()

	for _, c := range []audit.ClientProvenance{
		{Source: audit.ClientSourcePortal, ConfirmationID: "00000000-0000-4000-8000-0000000000aa"},
		{Rejected: audit.ClientRejectedVersion},
	} {
		rec := NewRecorder(t)
		audit.New(rec.Logger("test/audit"), audit.WithWriter(audit.WriterAction), audit.WithActor("example-agent", audit.ClassAgent)).
			Emit(ctx, audit.Event{Action: "tool.call", Verb: "post", Outcome: audit.OutcomeSuccess, ServerAddress: "api.example.com", Client: c})
		AssertEnumsDetected(t, audit.WriterAction, rec.Only(t))
	}
	for _, k := range []string{audit.KeyClientSource, audit.KeyClientRejected} {
		if !slices.Contains(got, k) {
			t.Errorf("AssertEnumsDetected did not exercise %s: %v", k, got)
		}
	}
}
