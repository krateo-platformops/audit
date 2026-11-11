package main

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/krateo-platformops/audit"
	"go.opentelemetry.io/otel/attribute"
)

// A portal /call create as OTLP/JSON: a ConfigMap written with its content
// hash and the portal's provenance.
const portalWrite = `{"eventName":"audit","attributes":[
  {"key":"event.name","value":{"stringValue":"audit"}},
  {"key":"krateo.audit.schema_version","value":{"stringValue":"1"}},
  {"key":"user.name","value":{"stringValue":"example-user"}},
  {"key":"krateo.audit.actor_class","value":{"stringValue":"human"}},
  {"key":"krateo.action","value":{"stringValue":"call"}},
  {"key":"krateo.audit.verb","value":{"stringValue":"create"}},
  {"key":"http.request.method","value":{"stringValue":"POST"}},
  {"key":"http.response.status_code","value":{"intValue":"201"}},
  {"key":"krateo.audit.outcome","value":{"stringValue":"success"}},
  {"key":"krateo.audit.dry_run","value":{"boolValue":false}},
  {"key":"krateo.audit.preview","value":{"boolValue":false}},
  {"key":"k8s.namespace.name","value":{"stringValue":"example-ns"}},
  {"key":"krateo.audit.object_ref.api_version","value":{"stringValue":"v1"}},
  {"key":"krateo.audit.object_ref.resource","value":{"stringValue":"configmaps"}},
  {"key":"krateo.audit.object_ref.name","value":{"stringValue":"example-evidence"}},
  {"key":"krateo.audit.object_ref.content_sha256","value":{"stringValue":"c1:2bbf0a0f3ccc266c6ee429376afbd9a20714a80d5b03a753bbb29ec8c1fee232"}},
  {"key":"krateo.request.uri","value":{"stringValue":"/call"}},
  {"key":"krateo.request.source_ips","value":{"arrayValue":{"values":[{"stringValue":"192.0.2.10"}]}}},
  {"key":"session.id","value":{"stringValue":"example-session"}},
  {"key":"krateo.audit.client.source","value":{"stringValue":"portal"}},
  {"key":"krateo.audit.client.confirmation_id","value":{"stringValue":"00000000-0000-4000-8000-0000000000aa"}},
  {"key":"krateo.audit.client.confirmed_set.count","value":{"intValue":"3"}},
  {"key":"krateo.audit.client.confirmed_set.irreversible","value":{"boolValue":true}},
  {"key":"krateo.audit.client.confirmed_set.sha256","value":{"stringValue":"0a08bb91090b111f15a045b6061bccc4d0b8488d85f99ba57d8632e17061c277"}},
  {"key":"krateo.audit.client.confirmed_set.op","value":{"intValue":"2"}},
  {"key":"krateo.audit.client.requested_at","value":{"stringValue":"2026-11-11T10:00:00.123Z"}}
]}`

const (
	portalSource   = `{"key":"krateo.audit.client.source","value":{"stringValue":"portal"}},`
	portalOp       = `{"key":"krateo.audit.client.confirmed_set.op","value":{"intValue":"2"}},`
	portalStatus   = `{"key":"http.response.status_code","value":{"intValue":"201"}},`
	portalOutcome  = `{"key":"krateo.audit.outcome","value":{"stringValue":"success"}},`
	portalResource = `{"key":"krateo.audit.object_ref.resource","value":{"stringValue":"configmaps"}},`
	clientKeysFrom = `{"key":"krateo.audit.client.source"`
)

// A v0.5.0 record stays valid: the records audit v0.5.0's own Emit wrote, per
// writer (testdata/v0.5.0/gen: cause_ref, a kept deletion, authn's login and
// refusal on a Secret, denied records without a status code), get exactly the
// report v0.5.0's auditschema gave them, and the same exit code.
func TestCheck_V050RecordsStayValid(t *testing.T) { recordsStayValid(t, "v0.5.0") }

// `auditschema check` accepts and rejects what Check does for every v0.6.0
// rule, naming keys and reasons, never a value.
func TestCheck_V060Rules(t *testing.T) {
	sub := func(base, old, new string) string {
		t.Helper()
		out := strings.Replace(base, old, new, 1)
		if out == base {
			t.Fatalf("precondition: %q does not occur", old)
		}
		return out
	}
	// The rejected header's record: the client keys replaced by rejected.
	i := strings.Index(portalWrite, clientKeysFrom)
	rejected := portalWrite[:i] + `{"key":"krateo.audit.client.rejected","value":{"stringValue":"schema"}}` + "\n]}"
	denied := sub(authnDenied, authnReason, `{"key":"krateo.audit.denial_reason","value":{"stringValue":"platform_group"}},`)
	for _, tc := range []struct {
		name, writer, record string
		want                 []string
	}{
		{"a portal write", "request", portalWrite, nil},
		{"a rejected header", "request", rejected, nil},
		{"authn refuses a krateo: group", "request", denied, nil},
		{"authn refuses a delegation", "request", sub(denied, "platform_group", "delegation_not_allowed"), nil},
		{"authn refuses a missing username, no Secret named", "request",
			sub(sub(denied, "platform_group", "name_missing"), `{"key":"krateo.audit.object_ref.name","value":{"stringValue":"example-user-clientconfig"}},`, ""), nil},
		{"a missing username recorded as a failure", "request",
			sub(sub(denied, "platform_group", "name_missing"), authnOutcome, `{"key":"krateo.audit.outcome","value":{"stringValue":"failure"}},`),
			[]string{"krateo.audit.denial_reason: unexpected"}},
		// v0.6.1 (audit#18): /delegate's refused subject token.
		{"authn refuses an expired subject token", "request", sub(denied, "platform_group", "subject_token_expired"), nil},
		{"authn refuses an invalid subject token", "request", sub(denied, "platform_group", "subject_token_invalid"), nil},
		{"an invalid subject token with a status code", "request", sub(sub(denied, "platform_group", "subject_token_invalid"), authnOutcome, authnOutcome+portalStatus),
			[]string{"http.response.status_code: unexpected"}},
		{"an expired subject token recorded as a failure", "request",
			sub(sub(denied, "platform_group", "subject_token_expired"), authnOutcome, `{"key":"krateo.audit.outcome","value":{"stringValue":"failure"}},`),
			[]string{"krateo.audit.denial_reason: unexpected"}},
		{"an invalid subject token on a controller", "controller", sub(sub(controllerRecord, pruned, keptOutcome), "kept_resource_policy", "subject_token_invalid"),
			[]string{"krateo.audit.denial_reason: bad-enum"}},
		{"a missing username on a controller", "controller", sub(sub(controllerRecord, pruned, keptOutcome), "kept_resource_policy", "name_missing"),
			[]string{"krateo.audit.denial_reason: bad-enum"}},
		{"an unknown request reason", "request", sub(denied, "platform_group", "krateo_group"), []string{"krateo.audit.denial_reason: bad-enum"}},
		{"a status code on a denied record", "request", sub(denied, authnOutcome, authnOutcome+portalStatus), []string{"http.response.status_code: unexpected"}},
		{"a content hash of a Secret", "request", sub(portalWrite, portalResource, `{"key":"krateo.audit.object_ref.resource","value":{"stringValue":"secrets"}},`),
			[]string{"krateo.audit.object_ref.content_sha256: not-for-target"}},
		{"a rejected header with its source", "request", sub(rejected, `{"key":"krateo.audit.client.rejected"`, portalSource+`{"key":"krateo.audit.client.rejected"`),
			[]string{"krateo.audit.client.source: unexpected"}},
		{"op not below count", "request", sub(portalWrite, portalOp, `{"key":"krateo.audit.client.confirmed_set.op","value":{"intValue":"3"}},`),
			[]string{"krateo.audit.client.confirmed_set.op: out-of-range"}},
		{"provenance without its source", "request", sub(portalWrite, portalSource, ""), []string{"krateo.audit.client.source: missing"}},
		{"a status code on a portal write refused", "request", sub(portalWrite, portalOutcome, `{"key":"krateo.audit.outcome","value":{"stringValue":"denied"}},`),
			[]string{"http.response.status_code: unexpected"}},
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
			for _, value := range []string{"example-user", "2bbf0a0f", "0a08bb91", "00000000-0000-4000", "platform_group", "krateo_group"} {
				if strings.Contains(out, value) {
					t.Errorf("the output carries the value %q:\n%s", value, out)
				}
			}
		})
	}
}

// The live queries carry the v0.6.0 rules, executed on rows: the status code
// is counted on a denied row only, the content hash on a credential target
// only, and a client key beside rejected; the new scopes are judged as
// controller rows.
func TestSQL_V060(t *testing.T) {
	_, sql, _ := runIt(t, "", "sql")
	s, i := attribute.String, attribute.Int64
	for _, w := range []audit.Writer{audit.WriterRequest, audit.WriterGateway, audit.WriterController} {
		q := rulesQuery(t, sql, w)
		pred := countIfOf(t, q, alias("unexpected", audit.KeyHTTPStatusCode))
		for outcome, want := range map[string]bool{audit.OutcomeDenied: true, audit.OutcomeSuccess: false, audit.OutcomeFailure: false} {
			got, err := evalSQL(pred, rowOf([]attribute.KeyValue{s(audit.KeyOutcome, outcome), i(audit.KeyHTTPStatusCode, 403)}))
			if err != nil || got != want {
				t.Errorf("%s: a status code on a %s row counted %v, %v; want %v", w, outcome, got, err, want)
			}
		}
	}
	for _, w := range []audit.Writer{audit.WriterRequest, audit.WriterController} {
		pred := countIfOf(t, rulesQuery(t, sql, w), alias("not_for_target", audit.KeyObjectContentSHA256))
		for _, tc := range []struct {
			group, resource, sub string
			want                 bool
		}{{"", "secrets", "", true}, {"", "secrets", "status", true}, {"", "serviceaccounts", "token", true}, {"authentication.k8s.io", "tokenreviews", "", true},
			{"", "serviceaccounts", "", false}, {"", "configmaps", "", false}, {"example.krateo.io", "secrets", "", false}, {"authentication.k8s.io", "selfsubjectreviews", "", false}} {
			row := []attribute.KeyValue{s(audit.KeyObjectContentSHA256, "x"), s(audit.KeyObjectResource, tc.resource)}
			if tc.group != "" {
				row = append(row, s(audit.KeyObjectAPIGroup, tc.group))
			}
			if tc.sub != "" {
				row = append(row, s(audit.KeyObjectSubresource, tc.sub))
			}
			if got, err := evalSQL(pred, rowOf(row)); err != nil || got != tc.want {
				t.Errorf("%s: a content hash on %s/%s/%s counted %v, %v; want %v", w, tc.group, tc.resource, tc.sub, got, err, tc.want)
			}
		}
	}
	q := rulesQuery(t, sql, audit.WriterRequest)
	for _, k := range []string{audit.KeyClientSource, audit.KeyClientConfirmationID, audit.KeyClientConfirmedSetOp} {
		pred := countIfOf(t, q, alias("unexpected", k))
		for _, tc := range []struct {
			row  []attribute.KeyValue
			want bool
		}{
			{[]attribute.KeyValue{s(audit.KeyVerb, "create"), s(k, "v")}, false},
			{[]attribute.KeyValue{s(audit.KeyVerb, "create"), s(k, "v"), s(audit.KeyClientRejected, "schema")}, true},
			{[]attribute.KeyValue{s(audit.KeyVerb, "get"), s(k, "v")}, true},
		} {
			if got, err := evalSQL(pred, rowOf(tc.row)); err != nil || got != tc.want {
				t.Errorf("%s on %v counted %v, %v; want %v", k, rowOf(tc.row), got, err, tc.want)
			}
		}
	}
	if !strings.Contains(q, "AS "+alias("unmet", audit.KeyClientSource)) || !strings.Contains(q, "AS "+alias("bad", audit.KeyClientRejected)) {
		t.Errorf("the request rules lack the source condition or the rejected set")
	}
	if strings.Contains(rulesQuery(t, sql, audit.WriterGateway), "AS "+alias("unexpected", audit.KeyClientSource)) {
		t.Errorf("the gateway's rules judge client keys it cannot write, other than as not_for_writer")
	}

	scopeList := regexp.MustCompile(`AND ScopeName IN \(([^)]*)\)`)
	scopes := scopeList.FindStringSubmatch(rulesQuery(t, sql, audit.WriterController))
	requestScopes := scopeList.FindStringSubmatch(rulesQuery(t, sql, audit.WriterRequest))
	for _, sc := range []string{"github.com/krateo-platformops/access-review/audit", "github.com/krateo-platformops/identity-lifecycle/audit", "github.com/krateo-platformops/audit",
		"github.com/krateo-platformops/composition-dynamic-controller/audit", "github.com/krateo-platformops/core-provider/audit"} {
		if scopes == nil || !strings.Contains(scopes[1], "'"+sc+"'") {
			t.Errorf("the controller's rules do not read %s", sc)
		}
		if requestScopes == nil || strings.Contains(requestScopes[1], "'"+sc+"'") {
			t.Errorf("the request writer's rules read the controller scope %s", sc)
		}
	}
	if !slices.ContainsFunc(audit.Populations(), func(p audit.Population) bool {
		return p.Scope == "github.com/krateo-platformops/audit" && strings.Contains(p.Who, "historical")
	}) {
		t.Errorf("the shared scope's row no longer says it is kept for historical rows")
	}
}
