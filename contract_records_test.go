package audit_test

import (
	"context"
	"testing"

	"github.com/krateo-platformops/audit"
	"github.com/krateo-platformops/audit/audittest"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// The example records docs/schema.md shows, built with the library's own
// types. internal/schemagen copies each region between a `schema.md: <name>`
// line and a `schema.md: end` line into the doc as it is, and the tests below
// emit and check exactly that code: the doc cannot show a record the checker
// rejects, and a change here without `go generate` fails
// TestGeneratedFilesAreCurrent. No real identity: every name is an example.

func controllerEmitter(logger log.Logger) *audit.Emitter {
	// schema.md: controller-emitter
	e := audit.New(logger,
		audit.WithWriter(audit.WriterController),
		audit.WithActor("system:serviceaccount:example-system:example-controller", audit.ClassController),
	)
	// schema.md: end
	return e
}

func keptDeletion() audit.Event {
	// schema.md: kept-deletion
	ev := audit.Event{
		Action:       "helm.uninstall",
		Verb:         "delete",
		Outcome:      audit.OutcomeDenied,
		DenialReason: audit.DenialReasonKeptResourcePolicy,
		// No request was sent: no HTTPMethod, no StatusCode. No Message: the
		// reason is DenialReason, not the body.

		// object_ref: the child helm kept.
		Namespace:  "example-ns",
		Version:    "v1",
		Resource:   "persistentvolumeclaims",
		Kind:       "PersistentVolumeClaim",
		ObjectName: "example-data",
		Preview:    audit.PreviewFalse, // the Namespace's krateo.io/purpose label, read from the apiserver

		// cause_ref: the resource whose reconcile declined the delete.
		Cause: audit.CauseRef{
			Group:      "composition.krateo.io",
			Version:    "v1-2-0",
			Resource:   "exampleapps",
			Namespace:  "example-ns",
			Name:       "example-composition",
			UID:        "00000000-0000-4000-8000-0000000000c1",
			Generation: 5,
		},
	}
	// schema.md: end
	return ev
}

func prunedChild() audit.Event {
	// schema.md: pruned-child
	ev := audit.Event{
		Action:     "helm.upgrade",
		Verb:       "delete",
		HTTPMethod: "DELETE",
		Outcome:    audit.OutcomeSuccess,
		// StatusCode: the apiserver's answer, when the client returns it.

		// object_ref: the child helm deleted.
		Namespace:  "example-ns",
		Group:      "apps",
		Version:    "v1",
		Resource:   "deployments",
		Kind:       "Deployment",
		ObjectName: "example-worker",
		// ObjectUID: the child's uid, when the controller knows it.
		Preview: audit.PreviewFalse,

		// cause_ref: the resource whose reconcile pruned the child, at the
		// generation it reconciled.
		Cause: audit.CauseRef{
			Group:      "composition.krateo.io",
			Version:    "v1-2-0",
			Resource:   "exampleapps",
			Namespace:  "example-ns",
			Name:       "example-composition",
			UID:        "00000000-0000-4000-8000-0000000000c1",
			Generation: 4,
		},
	}
	// schema.md: end
	return ev
}

// Each example record conforms, every key the controller must write on it is
// load-bearing, every closed set on it is enforced, and it says what the doc
// says it says.
func TestContractRecords(t *testing.T) {
	tp := sdktrace.NewTracerProvider()
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	for _, tc := range []struct {
		name string
		ev   audit.Event
		want map[string]attribute.Value // "" value: the key is absent
	}{
		{"kept deletion", keptDeletion(), map[string]attribute.Value{
			audit.KeyVerb:            attribute.StringValue("delete"),
			audit.KeyOutcome:         attribute.StringValue("denied"),
			audit.KeyDenialReason:    attribute.StringValue("kept_resource_policy"),
			audit.KeyObjectResource:  attribute.StringValue("persistentvolumeclaims"),
			audit.KeyObjectName:      attribute.StringValue("example-data"),
			audit.KeyCauseResource:   attribute.StringValue("exampleapps"),
			audit.KeyCauseUID:        attribute.StringValue("00000000-0000-4000-8000-0000000000c1"),
			audit.KeyCauseGeneration: attribute.Int64Value(5),
			audit.KeyHTTPMethod:      {},
			audit.KeyHTTPStatusCode:  {},
		}},
		{"pruned child", prunedChild(), map[string]attribute.Value{
			audit.KeyVerb:            attribute.StringValue("delete"),
			audit.KeyOutcome:         attribute.StringValue("success"),
			audit.KeyDenialReason:    {},
			audit.KeyHTTPMethod:      attribute.StringValue("DELETE"),
			audit.KeyObjectResource:  attribute.StringValue("deployments"),
			audit.KeyObjectName:      attribute.StringValue("example-worker"),
			audit.KeyCauseResource:   attribute.StringValue("exampleapps"),
			audit.KeyCauseUID:        attribute.StringValue("00000000-0000-4000-8000-0000000000c1"),
			audit.KeyCauseGeneration: attribute.Int64Value(4),
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := audittest.NewRecorder(t)
			ctx, span := tp.Tracer("test").Start(context.Background(), "reconcile")
			controllerEmitter(rec.Logger("example-controller/audit")).Emit(ctx, tc.ev)
			span.End()
			r := rec.Only(t)
			audittest.AssertConformant(t, audit.WriterController, r)
			audittest.AssertRequiredKeysDetected(t, audit.WriterController, r)
			audittest.AssertEnumsDetected(t, audit.WriterController, r)

			got := map[string]attribute.Value{}
			for _, kv := range audittest.Attributes(r) {
				got[string(kv.Key)] = kv.Value
			}
			for k, v := range tc.want {
				g, ok := got[k]
				switch {
				case v.Type() == attribute.INVALID && ok:
					t.Errorf("%s is on the record", k)
				case v.Type() != attribute.INVALID && (!ok || g != v):
					t.Errorf("%s = %v, want %v", k, g.Emit(), v.Emit())
				}
			}
			if b := r.Body().AsString(); b != "" {
				t.Errorf("the body is %q, want none: the reason is the denial_reason key", b)
			}
			// The cause is the join key, and the written object is not it.
			if got[audit.KeyObjectResource] == got[audit.KeyCauseResource] {
				t.Errorf("object_ref and cause_ref name the same resource")
			}
		})
	}
}
