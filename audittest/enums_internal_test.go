package audittest

import (
	"context"
	"slices"
	"testing"

	"github.com/krateo-platformops/audit"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

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
