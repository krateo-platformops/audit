// Writes, with audit v0.5.0's own Emit, the records each writer class emits
// on v0.5.0 (cause_ref, the per-writer denial reasons, authn's own scope), as
// OTLP/JSON, after checking them with v0.5.0's own Check.
package v050gen

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/krateo-platformops/audit"
	"github.com/krateo-platformops/audit/audittest"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

const sa = "system:serviceaccount:example-system:example-controller"

type tc struct {
	name  string
	opts  []audit.Option
	sess  bool
	ev    audit.Event
	allow []string
}

var campaign = audit.CauseRef{Group: "accessreview.krateo.io", Version: "v1alpha1", Resource: "campaigns", Namespace: "example-ns",
	Name: "example-campaign", UID: "00000000-0000-4000-8000-0000000000c1", Generation: 2}

var cases = map[audit.Writer][]tc{
	audit.WriterController: {
		{name: "evidence ConfigMap create", opts: []audit.Option{audit.WithActor(sa, audit.ClassController), audit.WithWriter(audit.WriterController)},
			ev: audit.Event{Action: "campaign.evidence", Verb: "create", HTTPMethod: "POST", StatusCode: 201, Outcome: audit.OutcomeSuccess,
				Namespace: "example-ns", Version: "v1", Resource: "configmaps", Kind: "ConfigMap", ObjectName: "example-evidence",
				ObjectUID: "00000000-0000-4000-8000-000000000003", ObjectResourceVersion: "77", Preview: audit.PreviewFalse, Cause: campaign}},
		{name: "kept deletion", opts: []audit.Option{audit.WithActor(sa, audit.ClassController), audit.WithWriter(audit.WriterController)},
			ev: audit.Event{Action: "helm.uninstall", Verb: "delete", Outcome: audit.OutcomeDenied, DenialReason: audit.DenialReasonKeptResourcePolicy,
				Namespace: "example-ns", Version: "v1", Resource: "persistentvolumeclaims", ObjectName: "example-data", Preview: audit.PreviewFalse,
				Cause: audit.CauseRef{Group: "composition.krateo.io", Version: "v1-2-0", Resource: "exampleapps", Namespace: "example-ns",
					Name: "example-composition", UID: "00000000-0000-4000-8000-0000000000c2", Generation: 5}}},
		{name: "revoked binding", opts: []audit.Option{audit.WithActor(sa, audit.ClassController), audit.WithWriter(audit.WriterController)},
			ev: audit.Event{AffectedUser: "example-user", Action: "revoke.binding", Verb: "delete", HTTPMethod: "DELETE", StatusCode: 200,
				Outcome: audit.OutcomeSuccess, Namespace: "example-ns", Group: "rbac.authorization.k8s.io", Version: "v1",
				Resource: "rolebindings", Kind: "RoleBinding", ObjectName: "example-binding", Preview: audit.PreviewFalse, Cause: campaign}},
	},
	audit.WriterRequest: {
		{name: "authn login writes the credential Secret", opts: []audit.Option{audit.WithWriter(audit.WriterRequest)}, sess: true,
			ev: audit.Event{UserName: "example-user", UserRoles: []string{"example-group"}, ActorClass: audit.ClassHuman,
				Action: "authn.login.oidc", Verb: "update", HTTPMethod: "PUT", StatusCode: 200, Outcome: audit.OutcomeSuccess,
				Namespace: "example-system", Version: "v1", Resource: "secrets", ObjectName: "example-credential",
				ObjectUID: "00000000-0000-4000-8000-000000000004", ObjectResourceVersion: "42", Preview: audit.PreviewFalse,
				RequestURI: "/oidc/callback", SourceIPs: []string{"192.0.2.10"}}},
		{name: "authn login refused", opts: []audit.Option{audit.WithWriter(audit.WriterRequest)}, sess: true,
			ev: audit.Event{UserName: "example-user", ActorClass: audit.ClassHuman, Action: "authn.login.oidc", Verb: "update", HTTPMethod: "PUT",
				Outcome: audit.OutcomeDenied, DenialReason: audit.DenialReasonGroupNotAllowed,
				Namespace: "example-system", Version: "v1", Resource: "secrets", ObjectName: "example-credential", Preview: audit.PreviewFalse,
				RequestURI: "/oidc/callback", SourceIPs: []string{"192.0.2.10"}}},
		{name: "call refused before the wire", opts: []audit.Option{audit.WithWriter(audit.WriterRequest)}, sess: true,
			ev: audit.Event{UserName: "example-user", ActorClass: audit.ClassHuman, Action: "call", Verb: "post", HTTPMethod: "POST",
				Outcome: audit.OutcomeDenied, ServerAddress: "api.example.com", RequestURI: "/call", SourceIPs: []string{"192.0.2.10"}}},
		{name: "call, a portal create", opts: []audit.Option{audit.WithWriter(audit.WriterRequest)}, sess: true,
			ev: audit.Event{UserName: "example-user", ActorClass: audit.ClassHuman, Action: "call", Verb: "create", HTTPMethod: "POST", StatusCode: 201,
				Outcome: audit.OutcomeSuccess, Namespace: "example-ns", Version: "v1", Resource: "configmaps", ObjectName: "example-cm",
				ObjectUID: "00000000-0000-4000-8000-000000000005", ObjectGeneration: 1, ObjectResourceVersion: "678", Preview: audit.PreviewFalse,
				RequestURI: "/call?name=example-cm", SourceIPs: []string{"192.0.2.10"}, UserAgent: "example-portal/1.0"}},
	},
	audit.WriterAction: {
		{name: "tool executor create", opts: []audit.Option{audit.WithActor("example-agent", audit.ClassAgent), audit.WithWriter(audit.WriterAction)}, sess: true,
			ev: audit.Event{Action: "tool.k8s.create", Verb: "create", Outcome: audit.OutcomeSuccess, DryRun: true,
				Namespace: "example-preview", Version: "v1", Resource: "configmaps", ObjectName: "example-draft", Preview: audit.PreviewTrue}},
	},
}

func TestWrite(t *testing.T) {
	out := os.Getenv("OUT")
	if out == "" {
		t.Skip("OUT unset")
	}
	tp := sdktrace.NewTracerProvider()
	defer tp.Shutdown(context.Background())
	for w, cs := range cases {
		var lrs []any
		for _, c := range cs {
			ctx, span := tp.Tracer("gen").Start(context.Background(), c.name)
			if c.sess {
				m, _ := baggage.NewMember(audit.BaggageSessionKey, "example-session")
				b, _ := baggage.New(m)
				ctx = baggage.ContextWithBaggage(ctx, b)
			}
			rec := audittest.NewRecorder(t)
			audit.New(rec.Logger("example/audit"), c.opts...).Emit(ctx, c.ev)
			span.End()
			r := rec.Only(t)
			audittest.AssertConformant(t, w, r, audittest.AllowIncomplete(c.allow...))
			lrs = append(lrs, logRecord(r))
		}
		doc := map[string]any{"resourceLogs": []any{map[string]any{"scopeLogs": []any{map[string]any{
			"scope": map[string]any{"name": "example/audit"}, "logRecords": lrs}}}}}
		b, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(out, string(w)+".json"), append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func logRecord(r sdklog.Record) map[string]any {
	var attrs []any
	for _, kv := range audittest.Attributes(r) {
		attrs = append(attrs, map[string]any{"key": string(kv.Key), "value": value(kv.Value)})
	}
	return map[string]any{"eventName": r.EventName(), "body": map[string]any{"stringValue": r.Body().AsString()}, "attributes": attrs}
}

func value(v attribute.Value) map[string]any {
	switch v.Type() {
	case attribute.STRING:
		return map[string]any{"stringValue": v.AsString()}
	case attribute.BOOL:
		return map[string]any{"boolValue": v.AsBool()}
	case attribute.INT64:
		return map[string]any{"intValue": strconv.FormatInt(v.AsInt64(), 10)}
	case attribute.STRINGSLICE:
		var vs []any
		for _, s := range v.AsStringSlice() {
			vs = append(vs, map[string]any{"stringValue": s})
		}
		return map[string]any{"arrayValue": map[string]any{"values": vs}}
	}
	panic("unhandled type " + v.Type().String())
}
