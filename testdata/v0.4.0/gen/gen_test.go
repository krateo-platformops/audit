// Writes, with audit v0.4.0's own Emit, the records each writer class emits
// today, as OTLP/JSON, after checking them with v0.4.0's own Check.
package v040gen

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

var cases = map[audit.Writer][]tc{
	audit.WriterController: {
		{name: "external write naming the reconciled CR", opts: []audit.Option{audit.WithActor(sa, audit.ClassController), audit.WithWriter(audit.WriterController)},
			ev: audit.Event{Message: "external write succeeded", Action: "rest.write", Verb: "post", HTTPMethod: "POST", StatusCode: 201,
				Outcome: audit.OutcomeSuccess, Namespace: "example-ns", Group: "example.krateo.io", Version: "v1alpha1",
				Resource: "examplerepos", Kind: "ExampleRepo", ObjectName: "example-repo", ObjectUID: "00000000-0000-4000-8000-000000000001", ObjectGeneration: 3,
				ObjectResourceVersion: "12345", ServerAddress: "https://api.example.com/v1/repos", Preview: audit.PreviewFalse}},
		{name: "grant revoked", opts: []audit.Option{audit.WithActor(sa, audit.ClassController)},
			ev: audit.Event{Message: "grant revoked", AffectedUser: "example-user", Action: "revoke", Verb: "delete",
				Outcome: audit.OutcomeSuccess, Namespace: "example-ns", Group: "rbac.authorization.k8s.io", Version: "v1",
				Resource: "rolebindings", Kind: "RoleBinding", ObjectName: "example-binding", Preview: audit.PreviewFalse}},
		{name: "external action denied", opts: []audit.Option{audit.WithActor(sa, audit.ClassController)},
			ev: audit.Event{Message: "account disabled", AffectedUser: "example-user", Action: "deactivate", Verb: "post",
				Outcome: audit.OutcomeDenied, ServerAddress: "idp.example.com"}},
	},
	audit.WriterAction: {
		{name: "tool executor create", opts: []audit.Option{audit.WithActor("example-agent", audit.ClassAgent), audit.WithWriter(audit.WriterAction)}, sess: true,
			ev: audit.Event{Action: "tool.k8s.create", Verb: "create", Outcome: audit.OutcomeSuccess, DryRun: true,
				Namespace: "example-preview", Version: "v1", Resource: "configmaps", ObjectName: "example-draft", Preview: audit.PreviewTrue}},
	},
	audit.WriterRequest: {
		{name: "call, delegated token", opts: []audit.Option{audit.WithWriter(audit.WriterRequest)}, sess: true,
			ev: audit.Event{UserName: "example-agent", ActorClass: audit.ClassAgent, OnBehalfOf: "example-user",
				Delegation: []audit.Link{{Class: audit.ClassAgent, Subject: "example-agent"}, {Class: audit.ClassHuman, Subject: "example-user"}},
				Action:     "call", Verb: "create", HTTPMethod: "POST", StatusCode: 201, Outcome: audit.OutcomeSuccess,
				Namespace: "example-ns", Version: "v1", Resource: "configmaps", ObjectName: "example-cm", ObjectUID: "00000000-0000-4000-8000-000000000002",
				ObjectGeneration: 1, ObjectResourceVersion: "678", Preview: audit.PreviewFalse,
				RequestURI: "/call?name=example-cm", SourceIPs: []string{"192.0.2.10"}, UserAgent: "example-portal/1.0"}},
		{name: "call refused", opts: []audit.Option{audit.WithWriter(audit.WriterRequest)}, sess: true,
			ev: audit.Event{Message: "not sent: the destination policy refused the address", UserName: "example-user", UserRoles: []string{"example-group"}, ActorClass: audit.ClassHuman,
				Action: "call", Verb: "post", HTTPMethod: "POST", Outcome: audit.OutcomeDenied, ServerAddress: "api.example.com",
				RequestURI: "/call", SourceIPs: []string{"192.0.2.10"}}},
		{name: "read, token without the principal claim", opts: []audit.Option{audit.WithWriter(audit.WriterRequest)}, sess: true,
			ev: audit.Event{UserName: "example-user", UserRoles: []string{"example-group"}, Action: "call", Verb: "get", HTTPMethod: "GET",
				StatusCode: 200, Outcome: audit.OutcomeSuccess, ServerAddress: "api.example.com",
				RequestURI: "/call", SourceIPs: []string{"192.0.2.10"}}, allow: []string{audit.KeyActorClass}},
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
