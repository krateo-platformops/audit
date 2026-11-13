// Writes, with audit v0.13.0's own Emit, the records each writer class emits
// on v0.6.0 to v0.13.0 (the content hash, client provenance and its rejection,
// a delegated request, denied records with no status code, every request
// denial reason v0.6.0 to v0.8.0 added, v0.9.x's username checks: each
// check result, username_check_not_allowed, a failed lookup, and v0.10.0's
// two denial reasons, invalid_request and name_not_issued; v0.12.0's
// endpointRef stage, refusals with and without an address, the url.path
// target and a controller named by ServiceAccountActor), and v0.13.0's
// rbac_not_allowed refusal of a non-resource path, as OTLP/JSON, after
// checking them with v0.13.0's own Check.
package v0130gen

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

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

var (
	request = []audit.Option{audit.WithWriter(audit.WriterRequest)}
	ctrl    = []audit.Option{audit.WithActor(audit.ServiceAccountActor("example-system", "example-controller"), audit.ClassController), audit.WithWriter(audit.WriterController)}
	ips     = []string{"192.0.2.10"}
)

// secretRefusal is authn's denied record on the user's credential Secret:
// no status code, since no authority answered.
func secretRefusal(action, uri, reason string) audit.Event {
	return audit.Event{UserName: "example-user", ActorClass: audit.ClassHuman, Action: action, Verb: "update", HTTPMethod: "PUT",
		Outcome: audit.OutcomeDenied, DenialReason: reason, Namespace: "example-system", Version: "v1", Resource: "secrets",
		ObjectName: "example-user-clientconfig", Preview: audit.PreviewFalse, RequestURI: uri, SourceIPs: ips}
}

// mappingRefusal is authn's denied ServiceAccount login: the mapping
// resource, no mapping named (there is none, or no single one).
func mappingRefusal(reason string) audit.Event {
	return audit.Event{UserName: sa, ActorClass: audit.ClassService, Action: "authn.login.serviceaccount", Verb: "create", HTTPMethod: "POST",
		Outcome: audit.OutcomeDenied, DenialReason: reason, Namespace: "example-system", Group: "serviceaccount.authn.krateo.io",
		Version: "v1alpha1", Resource: "serviceaccounts", Preview: audit.PreviewFalse, RequestURI: "/serviceaccount/login", SourceIPs: ips}
}

// usernameCheck is authn's record of one /usernames/check decision (v0.9.0):
// a read of the checked name's clientconfig Secret, verb get.
func usernameCheck(outcome, result, reason string, code int) audit.Event {
	return audit.Event{UserName: sa, ActorClass: audit.ClassService, Action: "authn.username.check", Verb: "get", HTTPMethod: "GET",
		Outcome: outcome, CheckResult: result, DenialReason: reason, StatusCode: code,
		Namespace: "example-system", Version: "v1", Resource: "secrets", ObjectName: "example-user-clientconfig",
		Preview: audit.PreviewFalse, RequestURI: "/usernames/check", SourceIPs: ips}
}

var cases = map[audit.Writer][]tc{
	audit.WriterRequest: {
		// v0.9.0: the username check, one record per check result, the
		// not-opted-in refusal, and a failed lookup with the apiserver's 503.
		{name: "check: available", opts: request, sess: true, ev: usernameCheck(audit.OutcomeSuccess, audit.CheckResultAvailable, "", 0)},
		{name: "check: reserved", opts: request, sess: true, ev: usernameCheck(audit.OutcomeSuccess, audit.CheckResultReserved, "", 0)},
		{name: "check: name_claimed", opts: request, sess: true, ev: usernameCheck(audit.OutcomeSuccess, audit.CheckResultNameClaimed, "", 0)},
		{name: "check: name_held_legacy", opts: request, sess: true, ev: usernameCheck(audit.OutcomeSuccess, audit.CheckResultNameHeldLegacy, "", 0)},
		{name: "check: name_provisioned", opts: request, sess: true, ev: usernameCheck(audit.OutcomeSuccess, audit.CheckResultNameProvisioned, "", 0)},
		{name: "check: name_bound", opts: request, sess: true, ev: usernameCheck(audit.OutcomeSuccess, audit.CheckResultNameBound, "", 0)},
		{name: "check: invalid", opts: request, sess: true, ev: usernameCheck(audit.OutcomeSuccess, audit.CheckResultInvalid, "", 0)},
		{name: "check refused: not opted in", opts: request, sess: true,
			ev: usernameCheck(audit.OutcomeDenied, "", audit.DenialReasonUsernameCheckNotAllowed, 0)},
		{name: "check failed: the lookup answered 503", opts: request, sess: true, ev: usernameCheck(audit.OutcomeFailure, "", "", 503)},
		// v0.10.0: a body with no username (the Secret resource, no name, the
		// lookup's verb), and a sign-in for a username authn would issue in
		// another form (the Secret resource, no name).
		{name: "check refused: invalid request", opts: request, sess: true, ev: func() audit.Event {
			e := usernameCheck(audit.OutcomeDenied, "", audit.DenialReasonInvalidRequest, 0)
			e.ObjectName = ""
			return e
		}()},
		{name: "sign-in refused: name not issued", opts: request, sess: true, ev: func() audit.Event {
			e := secretRefusal("authn.login.basic", "/basic", audit.DenialReasonNameNotIssued)
			e.ObjectName = ""
			return e
		}()},
		{name: "portal create with its content hash and provenance", opts: request, sess: true,
			ev: audit.Event{UserName: "example-user", ActorClass: audit.ClassHuman, Action: "call", Verb: "create", HTTPMethod: "POST", StatusCode: 201,
				Outcome: audit.OutcomeSuccess, Namespace: "example-ns", Version: "v1", Resource: "configmaps", ObjectName: "example-evidence",
				ContentSHA256: "c1:2bbf0a0f3ccc266c6ee429376afbd9a20714a80d5b03a753bbb29ec8c1fee232", Preview: audit.PreviewFalse,
				RequestURI: "/call", SourceIPs: ips,
				Client: audit.ClientProvenance{Source: audit.ClientSourcePortal, ConfirmationID: "00000000-0000-4000-8000-0000000000aa",
					ConfirmedSet: &audit.ConfirmedSet{Count: 3, Irreversible: true, SHA256: "0a08bb91090b111f15a045b6061bccc4d0b8488d85f99ba57d8632e17061c277", Op: 2},
					RequestedAt:  time.Date(2026, 11, 11, 10, 0, 0, 123e6, time.UTC)}}},
		{name: "portal create with a rejected header", opts: request, sess: true,
			ev: audit.Event{UserName: "example-user", ActorClass: audit.ClassHuman, Action: "call", Verb: "create", HTTPMethod: "POST", StatusCode: 201,
				Outcome: audit.OutcomeSuccess, Namespace: "example-ns", Version: "v1", Resource: "configmaps", ObjectName: "example-cm",
				Preview: audit.PreviewFalse, RequestURI: "/call", SourceIPs: ips, Client: audit.ClientProvenance{Rejected: audit.ClientRejectedSchema}}},
		{name: "an agent's delegated call", opts: request, sess: true,
			ev: audit.Event{UserName: "example-agent", ActorClass: audit.ClassAgent, OnBehalfOf: "example-user",
				Delegation: []audit.Link{{Class: audit.ClassAgent, Subject: "example-agent"}, {Class: audit.ClassHuman, Subject: "example-user"}},
				Action:     "call", Verb: "get", HTTPMethod: "GET", StatusCode: 200, Outcome: audit.OutcomeSuccess,
				Namespace: "example-ns", Version: "v1", Resource: "configmaps", ObjectName: "example-cm", Preview: audit.PreviewFalse,
				RequestURI: "/call", SourceIPs: ips}},
		// v0.6.0: the krateo: group refusal; v0.6.0/v0.7.0: the /delegate refusals.
		{name: "a krateo: group refused", opts: request, sess: true, ev: secretRefusal("authn.login.ldap", "/ldap", audit.DenialReasonPlatformGroup)},
		{name: "delegation not allowed", opts: request, sess: true,
			ev: audit.Event{UserName: "example-agent", ActorClass: audit.ClassAgent, Action: "authn.delegate", Verb: "get", HTTPMethod: "GET",
				Outcome: audit.OutcomeDenied, DenialReason: audit.DenialReasonDelegationNotAllowed, Namespace: "example-system",
				Group: "serviceaccount.authn.krateo.io", Version: "v1alpha1", Resource: "serviceaccounts", ObjectName: "example-agent-mapping",
				Preview: audit.PreviewFalse, RequestURI: "/delegate", SourceIPs: ips}},
		{name: "an expired subject token", opts: request, sess: true,
			ev: audit.Event{UserName: "example-agent", ActorClass: audit.ClassAgent, Action: "authn.delegate", Verb: "get", HTTPMethod: "GET",
				Outcome: audit.OutcomeDenied, DenialReason: audit.DenialReasonSubjectTokenExpired, Namespace: "example-system",
				Group: "serviceaccount.authn.krateo.io", Version: "v1alpha1", Resource: "serviceaccounts", ObjectName: "example-agent-mapping",
				Preview: audit.PreviewFalse, RequestURI: "/delegate", SourceIPs: ips}},
		// v0.6.0: a verified identity with no username: the Secret resource, no name.
		{name: "no username", opts: request, sess: true, ev: func() audit.Event {
			e := secretRefusal("authn.login.oidc", "/oidc/callback", audit.DenialReasonNameMissing)
			e.ObjectName = ""
			return e
		}()},
		// v0.8.0: refusals after the identity verified.
		{name: "step-up below the asked assurance", opts: request, sess: true,
			ev: secretRefusal("authn.stepup", "/stepup", audit.DenialReasonInsufficientAssurance)},
		{name: "no mapping", opts: request, sess: true, ev: mappingRefusal(audit.DenialReasonNoMapping)},
		{name: "not a ServiceAccount", opts: request, sess: true, ev: mappingRefusal(audit.DenialReasonNotAServiceAccount)},
		{name: "a mapping lookup that failed, the apiserver answered", opts: request, sess: true, ev: func() audit.Event {
			e := mappingRefusal("")
			e.Outcome, e.StatusCode = audit.OutcomeFailure, 503
			return e
		}()},
		// v0.12.0: a RESTAction stage through an endpointRef, and snowplow's refusals.
		{name: "stage through an endpointRef", opts: request, sess: true,
			ev: audit.Event{UserName: "example-user", ActorClass: audit.ClassHuman, Action: "restaction", Verb: "post", HTTPMethod: "POST", StatusCode: 201,
				Outcome: audit.OutcomeSuccess, ServerAddress: "api.example.com", RESTActionNamespace: "example-ns", RESTActionName: "example-restaction",
				RESTActionStage: "example-stage", EndpointRefNamespace: "example-ns", EndpointRefName: "example-endpoint", RequestURI: "/call", SourceIPs: ips}},
		{name: "stage refused: destination", opts: request, sess: true,
			ev: audit.Event{UserName: "example-user", ActorClass: audit.ClassHuman, Action: "restaction", Verb: "post", HTTPMethod: "POST",
				Outcome: audit.OutcomeDenied, DenialReason: audit.DenialReasonDestinationRefused, ServerAddress: "api.example.com",
				RESTActionNamespace: "example-ns", RESTActionName: "example-restaction", RESTActionStage: "example-stage",
				EndpointRefNamespace: "example-ns", EndpointRefName: "example-endpoint", RequestURI: "/call", SourceIPs: ips}},
		{name: "stage refused before resolution: no address", opts: request, sess: true, allow: []string{"target"},
			ev: audit.Event{UserName: "example-user", ActorClass: audit.ClassHuman, Action: "restaction", Verb: "post", HTTPMethod: "POST",
				Outcome: audit.OutcomeDenied, DenialReason: audit.DenialReasonEndpointRefMalformed,
				RESTActionNamespace: "example-ns", RESTActionName: "example-restaction", RESTActionStage: "example-stage", RequestURI: "/call", SourceIPs: ips}},
		{name: "shadow-parity toggle: a non-resource path", opts: request, sess: true,
			ev: audit.Event{UserName: "example-user", ActorClass: audit.ClassHuman, Action: "debug.shadowParity", Verb: "post", HTTPMethod: "POST", StatusCode: 200,
				Outcome: audit.OutcomeSuccess, URLPath: "/debug/shadow-parity", RequestURI: "/debug/shadow-parity", SourceIPs: ips}},
		// v0.13.0: the writer's own RBAC refusal of a non-resource path, no status code.
		{name: "shadow-parity toggle refused: rbac_not_allowed", opts: request, sess: true,
			ev: audit.Event{UserName: "example-user", ActorClass: audit.ClassHuman, Action: "debug.shadowParity", Verb: "post", HTTPMethod: "POST",
				Outcome: audit.OutcomeDenied, DenialReason: audit.DenialReasonRbacNotAllowed, URLPath: "/debug/shadow-parity",
				RequestURI: "/debug/shadow-parity", SourceIPs: ips}},
	},
	audit.WriterController: {
		{name: "evidence ConfigMap create, hashed", opts: ctrl,
			ev: audit.Event{Action: "campaign.evidence", Verb: "create", HTTPMethod: "POST", StatusCode: 201, Outcome: audit.OutcomeSuccess,
				Namespace: "example-ns", Version: "v1", Resource: "configmaps", Kind: "ConfigMap", ObjectName: "example-evidence",
				ObjectUID: "00000000-0000-4000-8000-000000000003", ObjectResourceVersion: "77", Preview: audit.PreviewFalse,
				ContentSHA256: "c1:2bbf0a0f3ccc266c6ee429376afbd9a20714a80d5b03a753bbb29ec8c1fee232",
				Cause: audit.CauseRef{Group: "accessreview.krateo.io", Version: "v1alpha1", Resource: "campaigns", Namespace: "example-ns",
					Name: "example-campaign", UID: "00000000-0000-4000-8000-0000000000c1", Generation: 2}}},
		{name: "kept deletion", opts: ctrl,
			ev: audit.Event{Action: "helm.uninstall", Verb: "delete", Outcome: audit.OutcomeDenied, DenialReason: audit.DenialReasonKeptResourcePolicy,
				Namespace: "example-ns", Version: "v1", Resource: "persistentvolumeclaims", ObjectName: "example-data", Preview: audit.PreviewFalse,
				Cause: audit.CauseRef{Group: "composition.krateo.io", Version: "v1-2-0", Resource: "exampleapps", Namespace: "example-ns",
					Name: "example-composition", UID: "00000000-0000-4000-8000-0000000000c2", Generation: 5}}},
	},
	audit.WriterAction: {
		{name: "tool executor dry-run create with provenance", opts: []audit.Option{audit.WithActor("example-agent", audit.ClassAgent), audit.WithWriter(audit.WriterAction)}, sess: true,
			ev: audit.Event{Action: "tool.k8s.create", Verb: "create", Outcome: audit.OutcomeSuccess, DryRun: true,
				Namespace: "example-preview", Version: "v1", Resource: "configmaps", ObjectName: "example-draft", Preview: audit.PreviewTrue,
				Client: audit.ClientProvenance{Source: audit.ClientSourcePortal, AgentSessionID: "example-agent-session"}}},
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
