package main

import (
	"regexp"
	"strings"
	"testing"

	"github.com/krateo-platformops/audit"
)

// A v0.13.0 record stays valid under v0.14.0: the records audit v0.13.0's
// own Emit wrote (testdata/v0.13.0/gen) get exactly the report v0.13.0's
// auditschema gave them, and the same exit code.
func TestCheck_V0130RecordsStayValid(t *testing.T) { recordsStayValid(t, "v0.13.0") }

// oasgen-provider's scope (oasgen-provider#543) is read by the controller's
// live rules only.
func TestSQL_OasgenProviderScopeIsController(t *testing.T) {
	_, sql, _ := runIt(t, "", "sql")
	scopeList := regexp.MustCompile(`AND ScopeName IN \(([^)]*)\)`)
	const sc = "'github.com/krateo-platformops/oasgen-provider/audit'"
	if m := scopeList.FindStringSubmatch(rulesQuery(t, sql, audit.WriterController)); m == nil || !strings.Contains(m[1], sc) {
		t.Errorf("the controller's rules do not read %s", sc)
	}
	for _, w := range []audit.Writer{audit.WriterRequest, audit.WriterGateway} { // the action writer has no population, so no rules query
		if m := scopeList.FindStringSubmatch(rulesQuery(t, sql, w)); m != nil && strings.Contains(m[1], sc) {
			t.Errorf("the %s writer's rules read the controller scope %s", w, sc)
		}
	}
}

// authn's backfill leaving a credential Secret's username annotation as found
// (v0.14.0): a denied controller update, kept_existing_value, the key it kept.
const keptRecord = `{"eventName":"audit","attributes":[
  {"key":"event.name","value":{"stringValue":"audit"}},
  {"key":"krateo.audit.schema_version","value":{"stringValue":"1"}},
  {"key":"user.name","value":{"stringValue":"system:serviceaccount:example-system:example-controller"}},
  {"key":"krateo.audit.actor_class","value":{"stringValue":"controller"}},
  {"key":"krateo.action","value":{"stringValue":"authn.identity.inconsistent"}},
  {"key":"krateo.audit.verb","value":{"stringValue":"update"}},
  {"key":"krateo.audit.outcome","value":{"stringValue":"denied"}},
  {"key":"krateo.audit.denial_reason","value":{"stringValue":"kept_existing_value"}},
  {"key":"krateo.audit.authorization_key","value":{"stringValue":"annotation:authn.krateo.io/username"}},
  {"key":"krateo.audit.preview","value":{"boolValue":false}},
  {"key":"k8s.namespace.name","value":{"stringValue":"example-system"}},
  {"key":"krateo.audit.object_ref.api_version","value":{"stringValue":"v1"}},
  {"key":"krateo.audit.object_ref.resource","value":{"stringValue":"secrets"}},
  {"key":"krateo.audit.object_ref.name","value":{"stringValue":"example-user-clientconfig"}}
]}`

// A username check whose claimant holds the name (v0.14.0).
const claimantCheck = `{"eventName":"audit","attributes":[
  {"key":"event.name","value":{"stringValue":"audit"}},
  {"key":"krateo.audit.schema_version","value":{"stringValue":"1"}},
  {"key":"user.name","value":{"stringValue":"system:serviceaccount:example-system:example-controller"}},
  {"key":"krateo.audit.actor_class","value":{"stringValue":"service"}},
  {"key":"krateo.action","value":{"stringValue":"authn.username.check"}},
  {"key":"krateo.audit.verb","value":{"stringValue":"get"}},
  {"key":"http.request.method","value":{"stringValue":"GET"}},
  {"key":"krateo.audit.outcome","value":{"stringValue":"success"}},
  {"key":"krateo.audit.check_result","value":{"stringValue":"name_claimed_by_claimant"}},
  {"key":"krateo.audit.preview","value":{"boolValue":false}},
  {"key":"k8s.namespace.name","value":{"stringValue":"example-system"}},
  {"key":"krateo.audit.object_ref.api_version","value":{"stringValue":"v1"}},
  {"key":"krateo.audit.object_ref.resource","value":{"stringValue":"secrets"}},
  {"key":"krateo.audit.object_ref.name","value":{"stringValue":"example-user-clientconfig"}},
  {"key":"krateo.request.uri","value":{"stringValue":"/usernames/check"}},
  {"key":"krateo.request.source_ips","value":{"arrayValue":{"values":[{"stringValue":"192.0.2.10"}]}}},
  {"key":"session.id","value":{"stringValue":"example-session"}}
]}`

// `auditschema check` accepts and rejects what Check does for the v0.14.0
// rules, naming keys and reasons, never a value.
func TestCheck_V0140Rules(t *testing.T) {
	sub := func(base, old, new string) string {
		t.Helper()
		out := strings.Replace(base, old, new, 1)
		if out == base {
			t.Fatalf("precondition: %q does not occur", old)
		}
		return out
	}
	const key = `{"key":"krateo.audit.authorization_key","value":{"stringValue":"annotation:authn.krateo.io/username"}},`
	for _, tc := range []struct {
		name, writer, record string
		want                 []string
	}{
		{"a kept annotation", "controller", keptRecord, nil},
		{"a kept label", "controller", sub(keptRecord, "annotation:authn.krateo.io/username", "label:authn.krateo.io/principal"), nil},
		{"the reason without the key", "controller", sub(keptRecord, key, ""), []string{"krateo.audit.authorization_key: missing"}},
		{"the key beside another reason", "controller", sub(keptRecord, `"kept_existing_value"`, `"kept_resource_policy"`),
			[]string{"krateo.audit.authorization_key: unexpected"}},
		{"an undeclared key", "controller", sub(keptRecord, "annotation:authn.krateo.io/username", "annotation:example.com/note"),
			[]string{"krateo.audit.authorization_key: bad-enum"}},
		{"a username check, the claimant's claim", "request", claimantCheck, nil},
		{"a username check, another's claim", "request", sub(claimantCheck, "name_claimed_by_claimant", "name_claimed_by_another"), nil},
		{"a claimant result on another action", "request", sub(claimantCheck, `"authn.username.check"`, `"call"`),
			[]string{"krateo.audit.check_result: not-for-action"}},
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
			for _, value := range []string{"example-user", "example.com/note"} {
				if strings.Contains(out, value) {
					t.Errorf("the output carries the value %q:\n%s", value, out)
				}
			}
		})
	}
}
