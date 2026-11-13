package main

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/krateo-platformops/audit"
	"go.opentelemetry.io/otel/attribute"
)

// A v0.14.1 record stays valid under v0.15.0: the records audit v0.14.1's
// own Emit wrote (testdata/v0.14.1/gen) get exactly the report v0.14.1's
// auditschema gave them, and the same exit code.
func TestCheck_V0141RecordsStayValid(t *testing.T) { recordsStayValid(t, "v0.14.1") }

// An OIDC login authn recorded with the verified identity's claim (v0.15.0).
const claimedLogin = `{"eventName":"audit","attributes":[
  {"key":"event.name","value":{"stringValue":"audit"}},
  {"key":"krateo.audit.schema_version","value":{"stringValue":"1"}},
  {"key":"user.name","value":{"stringValue":"example-user"}},
  {"key":"krateo.audit.actor_class","value":{"stringValue":"human"}},
  {"key":"krateo.audit.identity.claim","value":{"stringValue":"[\"oidc\",\"https://idp.example.com/realms/krateo\",\"00000000-0000-4000-8000-000000000001\"]"}},
  {"key":"krateo.action","value":{"stringValue":"authn.login.oidc"}},
  {"key":"krateo.audit.verb","value":{"stringValue":"update"}},
  {"key":"http.request.method","value":{"stringValue":"PUT"}},
  {"key":"krateo.audit.dry_run","value":{"boolValue":false}},
  {"key":"krateo.audit.outcome","value":{"stringValue":"denied"}},
  {"key":"krateo.audit.denial_reason","value":{"stringValue":"name_claimed"}},
  {"key":"krateo.audit.preview","value":{"boolValue":false}},
  {"key":"k8s.namespace.name","value":{"stringValue":"example-system"}},
  {"key":"krateo.audit.object_ref.api_version","value":{"stringValue":"v1"}},
  {"key":"krateo.audit.object_ref.resource","value":{"stringValue":"secrets"}},
  {"key":"krateo.audit.object_ref.name","value":{"stringValue":"example-user-clientconfig"}},
  {"key":"krateo.request.uri","value":{"stringValue":"/oidc/callback"}},
  {"key":"krateo.request.source_ips","value":{"arrayValue":{"values":[{"stringValue":"192.0.2.10"}]}}},
  {"key":"session.id","value":{"stringValue":"example-session"}}
]}`

// A /delegate exchange that issued a token for a requested audience
// (v0.15.0).
const issuedForAudience = `{"eventName":"audit","attributes":[
  {"key":"event.name","value":{"stringValue":"audit"}},
  {"key":"krateo.audit.schema_version","value":{"stringValue":"1"}},
  {"key":"user.name","value":{"stringValue":"example-agent"}},
  {"key":"krateo.audit.actor_class","value":{"stringValue":"service"}},
  {"key":"krateo.audit.on_behalf_of.user.name","value":{"stringValue":"example-user"}},
  {"key":"krateo.audit.delegation","value":{"arrayValue":{"values":[{"stringValue":"service:example-agent"},{"stringValue":"human:example-user"}]}}},
  {"key":"krateo.action","value":{"stringValue":"authn.delegate"}},
  {"key":"krateo.audit.verb","value":{"stringValue":"create"}},
  {"key":"http.request.method","value":{"stringValue":"POST"}},
  {"key":"krateo.audit.dry_run","value":{"boolValue":false}},
  {"key":"krateo.audit.outcome","value":{"stringValue":"success"}},
  {"key":"krateo.audit.token.audience","value":{"stringValue":"agentiko"}},
  {"key":"krateo.audit.preview","value":{"boolValue":false}},
  {"key":"k8s.namespace.name","value":{"stringValue":"example-system"}},
  {"key":"krateo.audit.object_ref.api_group","value":{"stringValue":"serviceaccount.authn.krateo.io"}},
  {"key":"krateo.audit.object_ref.api_version","value":{"stringValue":"v1alpha1"}},
  {"key":"krateo.audit.object_ref.resource","value":{"stringValue":"serviceaccounts"}},
  {"key":"krateo.audit.object_ref.subresource","value":{"stringValue":"token"}},
  {"key":"krateo.audit.object_ref.name","value":{"stringValue":"example-agent"}},
  {"key":"krateo.request.uri","value":{"stringValue":"/delegate"}},
  {"key":"krateo.request.source_ips","value":{"arrayValue":{"values":[{"stringValue":"192.0.2.10"}]}}},
  {"key":"session.id","value":{"stringValue":"example-session"}}
]}`

// A public visitor's write, served as snowplow's public identity (v0.15.0).
const publicWrite = `{"eventName":"audit","attributes":[
  {"key":"event.name","value":{"stringValue":"audit"}},
  {"key":"krateo.audit.schema_version","value":{"stringValue":"1"}},
  {"key":"user.name","value":{"stringValue":"krateo:public"}},
  {"key":"user.roles","value":{"arrayValue":{"values":[{"stringValue":"system:unauthenticated"}]}}},
  {"key":"krateo.audit.actor_class","value":{"stringValue":"public"}},
  {"key":"krateo.action","value":{"stringValue":"call"}},
  {"key":"krateo.audit.verb","value":{"stringValue":"create"}},
  {"key":"http.request.method","value":{"stringValue":"POST"}},
  {"key":"krateo.audit.dry_run","value":{"boolValue":false}},
  {"key":"krateo.audit.outcome","value":{"stringValue":"success"}},
  {"key":"http.response.status_code","value":{"intValue":"201"}},
  {"key":"krateo.audit.preview","value":{"boolValue":false}},
  {"key":"k8s.namespace.name","value":{"stringValue":"example-ns"}},
  {"key":"krateo.audit.object_ref.api_version","value":{"stringValue":"v1"}},
  {"key":"krateo.audit.object_ref.resource","value":{"stringValue":"configmaps"}},
  {"key":"krateo.audit.object_ref.name","value":{"stringValue":"example-cm"}},
  {"key":"krateo.request.uri","value":{"stringValue":"/call"}},
  {"key":"krateo.request.source_ips","value":{"arrayValue":{"values":[{"stringValue":"192.0.2.10"}]}}},
  {"key":"session.id","value":{"stringValue":"example-session"}}
]}`

// `auditschema check` accepts and rejects what Check does for the v0.15.0
// rules, naming keys and reasons, never a value.
func TestCheck_V0150Rules(t *testing.T) {
	sub := func(base, old, new string) string {
		t.Helper()
		out := strings.Replace(base, old, new, 1)
		if out == base {
			t.Fatalf("precondition: %q does not occur", old)
		}
		return out
	}
	const claim = `"[\"oidc\",\"https://idp.example.com/realms/krateo\",\"00000000-0000-4000-8000-000000000001\"]"`
	const issued = `{"key":"krateo.audit.outcome","value":{"stringValue":"success"}},`
	refusedAs := func(reason string) string {
		return sub(issuedForAudience, issued, `{"key":"krateo.audit.outcome","value":{"stringValue":"denied"}},{"key":"krateo.audit.denial_reason","value":{"stringValue":"`+reason+`"}},`)
	}
	for _, tc := range []struct {
		name, writer, record string
		want                 []string
	}{
		{"a refused login with the verified claim", "request", claimedLogin, nil},
		{"a claim with spaces EncodeClaim never writes", "request", sub(claimedLogin, claim, `"[\"oidc\", \"https://idp.example.com/realms/krateo\", \"00000000-0000-4000-8000-000000000001\"]"`),
			[]string{"krateo.audit.identity.claim: bad-format"}},
		{"a claim of a strategy no sign-in verifies", "request", sub(claimedLogin, `\"oidc\"`, `\"self\"`), []string{"krateo.audit.identity.claim: bad-format"}},
		{"a claim beside the public class", "request", sub(claimedLogin, `"human"`, `"public"`), []string{"krateo.audit.identity.claim: unexpected"}},
		{"an issued token's audience", "request", issuedForAudience, nil},
		{"an https audience", "request", sub(issuedForAudience, `"agentiko"`, `"https://agentiko.example.com/mcp"`), nil},
		{"an audience with a query", "request", sub(issuedForAudience, `"agentiko"`, `"https://agentiko.example.com/?tenant=example"`), []string{"krateo.audit.token.audience: bad-format"}},
		{"an audience with userinfo", "request", sub(issuedForAudience, `"agentiko"`, `"https://example-user@agentiko.example.com"`), []string{"krateo.audit.token.audience: bad-format"}},
		{"an uppercase audience", "request", sub(issuedForAudience, `"agentiko"`, `"Agentiko"`), []string{"krateo.audit.token.audience: bad-format"}},
		{"a refused audience", "request", refusedAs("audience_not_allowed"), nil},
		{"an audience beside invalid_request", "request", refusedAs("invalid_request"), []string{"krateo.audit.token.audience: unexpected"}},
		{"subject_not_signed_in", "request", sub(refusedAs("subject_not_signed_in"), `{"key":"krateo.audit.token.audience","value":{"stringValue":"agentiko"}},`, ""), nil},
		{"subject_not_signed_in with a status code", "request",
			sub(sub(refusedAs("subject_not_signed_in"), `{"key":"krateo.audit.token.audience","value":{"stringValue":"agentiko"}},`, ""),
				`{"key":"krateo.audit.preview"`, `{"key":"http.response.status_code","value":{"intValue":"403"}},{"key":"krateo.audit.preview"`),
			[]string{"http.response.status_code: unexpected"}},
		{"a public visitor's write", "request", publicWrite, nil},
		{"the public class beside on_behalf_of", "request",
			sub(publicWrite, `{"key":"krateo.action"`, `{"key":"krateo.audit.on_behalf_of.user.name","value":{"stringValue":"example-user"}},{"key":"krateo.audit.delegation","value":{"arrayValue":{"values":[{"stringValue":"human:example-user"}]}}},{"key":"krateo.action"`),
			[]string{"krateo.audit.on_behalf_of.user.name: unexpected", "krateo.audit.delegation: unexpected"}},
		{"the public class on a controller", "controller", sub(keptRecord, `"controller"}}`, `"public"}}`), []string{"krateo.audit.actor_class: bad-enum"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errs := runIt(t, tc.record, "check", "-writer", tc.writer)
			if errs != "" {
				t.Fatalf("stderr: %s", errs)
			}
			var got []string
			for _, l := range regexp.MustCompile(`(?m)^stdin: record 0: (.*)$`).FindAllStringSubmatch(out, -1) {
				got = append(got, l[1])
			}
			if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
				t.Errorf("violations:\n got %q\nwant %q", got, tc.want)
			}
			if wantCode := map[bool]int{true: 0, false: 1}[len(tc.want) == 0]; code != wantCode {
				t.Errorf("exit %d, want %d", code, wantCode)
			}
			for _, value := range []string{"idp.example.com", "agentiko", "example-user", "krateo:public"} {
				if strings.Contains(out, value) {
					t.Errorf("the output carries the value %q:\n%s", value, out)
				}
			}
		})
	}
}

// The live rules for the v0.15.0 keys, executed: the request writer's
// unexpected_ columns for the claim, on_behalf_of and delegation count a
// public actor's record, the audience's counts it off an issued token or an
// audience_not_allowed refusal, and only the request writer's actor class
// set holds public. Each as Check reports it.
func TestSQL_V0150RulesCountWhatCheckReports(t *testing.T) {
	_, sql, _ := runIt(t, "", "sql")
	req := rulesQuery(t, sql, audit.WriterRequest)
	s := attribute.String
	for _, tc := range []struct {
		col, key string
		attrs    []attribute.KeyValue
		want     bool
	}{
		{alias("unexpected", audit.KeyIdentityClaim), audit.KeyIdentityClaim,
			[]attribute.KeyValue{s(audit.KeyActorClass, "public"), s(audit.KeyIdentityClaim, `["oidc","iss","sub"]`)}, true},
		{alias("unexpected", audit.KeyIdentityClaim), audit.KeyIdentityClaim,
			[]attribute.KeyValue{s(audit.KeyActorClass, "human"), s(audit.KeyIdentityClaim, `["oidc","iss","sub"]`)}, false},
		{alias("unexpected", audit.KeyOnBehalfOf), audit.KeyOnBehalfOf,
			[]attribute.KeyValue{s(audit.KeyActorClass, "public"), s(audit.KeyOnBehalfOf, "example-user")}, true},
		{alias("unexpected", audit.KeyOnBehalfOf), audit.KeyOnBehalfOf,
			[]attribute.KeyValue{s(audit.KeyActorClass, "agent"), s(audit.KeyOnBehalfOf, "example-user")}, false},
		{alias("unexpected", audit.KeyDelegation), audit.KeyDelegation,
			[]attribute.KeyValue{s(audit.KeyActorClass, "public"), attribute.StringSlice(audit.KeyDelegation, []string{"human:example-user"})}, true},
		{alias("unexpected", audit.KeyTokenAudience), audit.KeyTokenAudience,
			[]attribute.KeyValue{s(audit.KeyOutcome, "success"), s(audit.KeyTokenAudience, "agentiko")}, false},
		{alias("unexpected", audit.KeyTokenAudience), audit.KeyTokenAudience,
			[]attribute.KeyValue{s(audit.KeyOutcome, "denied"), s(audit.KeyDenialReason, "audience_not_allowed"), s(audit.KeyTokenAudience, "agentiko")}, false},
		{alias("unexpected", audit.KeyTokenAudience), audit.KeyTokenAudience,
			[]attribute.KeyValue{s(audit.KeyOutcome, "denied"), s(audit.KeyDenialReason, "invalid_request"), s(audit.KeyTokenAudience, "agentiko")}, true},
		{alias("unexpected", audit.KeyTokenAudience), audit.KeyTokenAudience,
			[]attribute.KeyValue{s(audit.KeyOutcome, "failure"), s(audit.KeyTokenAudience, "agentiko")}, true},
	} {
		pred := countIfOf(t, req, tc.col)
		counted, err := evalSQL(pred, rowOf(tc.attrs))
		if err != nil {
			t.Fatalf("%s: %v\n%s", tc.col, err, pred)
		}
		reported := slices.Contains(audit.Check(audit.WriterRequest, tc.attrs), audit.Violation{Key: tc.key, Reason: audit.ReasonUnexpected})
		if counted != tc.want || reported != tc.want {
			t.Errorf("%s on %v: SQL counts %v, Check reports %v; want %v", tc.col, rowOf(tc.attrs), counted, reported, tc.want)
		}
	}
	for _, w := range []audit.Writer{audit.WriterRequest, audit.WriterGateway, audit.WriterController} {
		pred := countIfOf(t, rulesQuery(t, sql, w), alias("bad", audit.KeyActorClass))
		counted, err := evalSQL(pred, rowOf([]attribute.KeyValue{s(audit.KeyActorClass, "public")}))
		if err != nil {
			t.Fatalf("%s: %v", w, err)
		}
		if want := w != audit.WriterRequest; counted != want {
			t.Errorf("%s: bad actor class public counted %v, want %v", w, counted, want)
		}
	}
}
