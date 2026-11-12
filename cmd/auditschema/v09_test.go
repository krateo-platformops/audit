package main

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/krateo-platformops/audit"
	"go.opentelemetry.io/otel/attribute"
)

// authn's record of a completed username check (audit#23) as OTLP/JSON: a
// request row, verb get, targeting the clientconfig Secret the name guard
// protects, outcome success, with the check's result.
const usernameCheck = `{"eventName":"audit","attributes":[
  {"key":"event.name","value":{"stringValue":"audit"}},
  {"key":"krateo.audit.schema_version","value":{"stringValue":"1"}},
  {"key":"user.name","value":{"stringValue":"system:serviceaccount:example-system:example-controller"}},
  {"key":"krateo.audit.actor_class","value":{"stringValue":"service"}},
  {"key":"krateo.action","value":{"stringValue":"authn.username.check"}},
  {"key":"krateo.audit.verb","value":{"stringValue":"get"}},
  {"key":"http.request.method","value":{"stringValue":"GET"}},
  {"key":"krateo.audit.outcome","value":{"stringValue":"success"}},
  {"key":"krateo.audit.check_result","value":{"stringValue":"name_claimed"}},
  {"key":"krateo.audit.preview","value":{"boolValue":false}},
  {"key":"k8s.namespace.name","value":{"stringValue":"example-system"}},
  {"key":"krateo.audit.object_ref.api_version","value":{"stringValue":"v1"}},
  {"key":"krateo.audit.object_ref.resource","value":{"stringValue":"secrets"}},
  {"key":"krateo.audit.object_ref.name","value":{"stringValue":"example-user-clientconfig"}},
  {"key":"krateo.request.uri","value":{"stringValue":"/usernames/check"}},
  {"key":"krateo.request.source_ips","value":{"arrayValue":{"values":[{"stringValue":"192.0.2.10"}]}}},
  {"key":"session.id","value":{"stringValue":"example-session"}}
]}`

const (
	checkAction      = `{"key":"krateo.action","value":{"stringValue":"authn.username.check"}},`
	checkResult      = `{"key":"krateo.audit.check_result","value":{"stringValue":"name_claimed"}},`
	checkOutcome     = `{"key":"krateo.audit.outcome","value":{"stringValue":"success"}},`
	notAllowedReason = `{"key":"krateo.audit.denial_reason","value":{"stringValue":"username_check_not_allowed"}},`
)

// A v0.8.0 record stays valid: the records audit v0.8.0's own Emit wrote, per
// writer (testdata/v0.8.0/gen: the content hash, client provenance and its
// rejection, a delegated call, the request denial reasons v0.6.0 to v0.8.0
// added, a failure row, a kept deletion), get exactly the report v0.8.0's
// auditschema gave them, and the same exit code.
func TestCheck_V080RecordsStayValid(t *testing.T) { recordsStayValid(t, "v0.8.0") }

// `auditschema check` accepts and rejects what Check does for the v0.9.0
// rule: krateo.audit.check_result, one of the closed values of the record's
// action, and on no other action. It names keys and reasons, never a value.
func TestCheck_V090CheckResult(t *testing.T) {
	sub := func(base, old, new string) string {
		t.Helper()
		out := strings.Replace(base, old, new, 1)
		if out == base {
			t.Fatalf("precondition: %q does not occur", old)
		}
		return out
	}
	// authn refuses a caller whose mapping has not opted in: denied, the
	// checked name's Secret, no status code, no result.
	notAllowed := sub(sub(usernameCheck, checkOutcome, `{"key":"krateo.audit.outcome","value":{"stringValue":"denied"}},`), checkResult, notAllowedReason)
	result := func(v string) string {
		if v == "name_claimed" { // the fixture's own result
			return usernameCheck
		}
		return sub(usernameCheck, checkResult, `{"key":"krateo.audit.check_result","value":{"stringValue":"`+v+`"}},`)
	}
	type tcase struct {
		name, writer, record string
		want                 []string
	}
	var cases []tcase
	for _, v := range []string{"available", "reserved", "name_claimed", "name_held_legacy", "name_provisioned", "name_bound", "invalid"} {
		cases = append(cases, tcase{"the result " + v, "request", result(v), nil})
	}
	cases = append(cases,
		tcase{"no result", "request", sub(usernameCheck, checkResult, ""), nil},
		tcase{"a result outside the set", "request", result("taken"), []string{"krateo.audit.check_result: bad-enum"}},
		tcase{"a denial reason as the result", "request", result("name_reserved"), []string{"krateo.audit.check_result: bad-enum"}},
		tcase{"on a login", "request", sub(usernameCheck, checkAction, `{"key":"krateo.action","value":{"stringValue":"authn.login.basic"}},`),
			[]string{"krateo.audit.check_result: not-for-action"}},
		tcase{"with no action", "request", sub(usernameCheck, checkAction, ""),
			[]string{"krateo.audit.check_result: not-for-action", "krateo.action: missing"}},
		tcase{"on a controller", "controller", sub(controllerRecord, pruned, pruned+checkResult),
			[]string{"krateo.audit.check_result: not-for-writer"}},
		// A result only on a success: the check ran.
		tcase{"a result on a failed lookup", "request", sub(usernameCheck, checkOutcome, `{"key":"krateo.audit.outcome","value":{"stringValue":"failure"}},`),
			[]string{"krateo.audit.check_result: unexpected"}},
		tcase{"a failed lookup without a result", "request",
			sub(sub(usernameCheck, checkOutcome, `{"key":"krateo.audit.outcome","value":{"stringValue":"failure"}},`), checkResult, ""), nil},
		tcase{"the mapping has not opted in", "request", notAllowed, nil},
		tcase{"not opted in, with a result", "request", sub(notAllowed, notAllowedReason, notAllowedReason+checkResult),
			[]string{"krateo.audit.check_result: unexpected"}},
		tcase{"not opted in, with a status code", "request", sub(notAllowed, notAllowedReason, notAllowedReason+`{"key":"http.response.status_code","value":{"intValue":"403"}},`),
			[]string{"http.response.status_code: unexpected"}},
		tcase{"no mapping, on the check", "request", sub(sub(sub(notAllowed, "username_check_not_allowed", "no_mapping"),
			`{"key":"krateo.audit.object_ref.resource","value":{"stringValue":"secrets"}},`,
			`{"key":"krateo.audit.object_ref.api_group","value":{"stringValue":"serviceaccount.authn.krateo.io"}},{"key":"krateo.audit.object_ref.resource","value":{"stringValue":"serviceaccounts"}},`),
			`{"key":"krateo.audit.object_ref.name","value":{"stringValue":"example-user-clientconfig"}},`, ""), nil},
		tcase{"not opted in, on a controller", "controller", sub(sub(controllerRecord, pruned, keptOutcome), "kept_resource_policy", "username_check_not_allowed"),
			[]string{"krateo.audit.denial_reason: bad-enum"}},
	)
	for _, tc := range cases {
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
			for _, value := range []string{"example-user", "taken", "authn.login.basic"} {
				if strings.Contains(out, value) {
					t.Errorf("the output carries the value %q:\n%s", value, out)
				}
			}
		})
	}
}

// The live detectors for the check result, executed: the request writer's
// bad_ and not_for_action_ columns count a row exactly when Check reports
// bad-enum or not-for-action on it, written out by hand per row. The other
// writers judge the key only as not_for_writer.
func TestSQL_CheckResultCountsWhatCheckReports(t *testing.T) {
	_, sql, _ := runIt(t, "", "sql")
	q := rulesQuery(t, sql, audit.WriterRequest)
	bad := countIfOf(t, q, alias("bad", audit.KeyCheckResult))
	notFor := countIfOf(t, q, alias("not_for_action", audit.KeyCheckResult))
	s := attribute.String
	for _, tc := range []struct {
		name           string
		row            []attribute.KeyValue
		badEnum, notFA bool
	}{
		{"available on the check", []attribute.KeyValue{s(audit.KeyAction, "authn.username.check"), s(audit.KeyCheckResult, "available")}, false, false},
		{"invalid on the check", []attribute.KeyValue{s(audit.KeyAction, "authn.username.check"), s(audit.KeyCheckResult, "invalid")}, false, false},
		{"outside the set on the check", []attribute.KeyValue{s(audit.KeyAction, "authn.username.check"), s(audit.KeyCheckResult, "taken")}, true, false},
		{"a result on a login", []attribute.KeyValue{s(audit.KeyAction, "authn.login.basic"), s(audit.KeyCheckResult, "available")}, false, true},
		{"outside the set on a login", []attribute.KeyValue{s(audit.KeyAction, "authn.login.basic"), s(audit.KeyCheckResult, "taken")}, false, true},
		{"a result with no action", []attribute.KeyValue{s(audit.KeyCheckResult, "available")}, false, true},
		{"the check with no result", []attribute.KeyValue{s(audit.KeyAction, "authn.username.check")}, false, false},
	} {
		gotBad, err := evalSQL(bad, rowOf(tc.row))
		if err != nil {
			t.Fatalf("%s: %v\n%s", tc.name, err, bad)
		}
		gotNotFor, err := evalSQL(notFor, rowOf(tc.row))
		if err != nil {
			t.Fatalf("%s: %v\n%s", tc.name, err, notFor)
		}
		vs := audit.Check(audit.WriterRequest, tc.row)
		reportedBad := slices.Contains(vs, audit.Violation{Key: audit.KeyCheckResult, Reason: audit.ReasonBadEnum})
		reportedNotFor := slices.Contains(vs, audit.Violation{Key: audit.KeyCheckResult, Reason: audit.ReasonNotForAction})
		if gotBad != tc.badEnum || reportedBad != tc.badEnum || gotNotFor != tc.notFA || reportedNotFor != tc.notFA {
			t.Errorf("%s: SQL bad %v / not_for_action %v, Check bad-enum %v / not-for-action %v; want %v / %v",
				tc.name, gotBad, gotNotFor, reportedBad, reportedNotFor, tc.badEnum, tc.notFA)
		}
	}
	// A result only on a success: the unexpected_ column counts it on a
	// denied, a failed or an outcome-less row, as Check reports it.
	unexpected := countIfOf(t, q, alias("unexpected", audit.KeyCheckResult))
	for _, outcome := range []string{audit.OutcomeSuccess, audit.OutcomeFailure, audit.OutcomeDenied, ""} {
		for _, withResult := range []bool{true, false} {
			row := []attribute.KeyValue{s(audit.KeyAction, "authn.username.check")}
			if outcome != "" {
				row = append(row, s(audit.KeyOutcome, outcome))
			}
			if withResult {
				row = append(row, s(audit.KeyCheckResult, "available"))
			}
			counted, err := evalSQL(unexpected, rowOf(row))
			if err != nil {
				t.Fatalf("%v\n%s", err, unexpected)
			}
			reported := slices.Contains(audit.Check(audit.WriterRequest, row), audit.Violation{Key: audit.KeyCheckResult, Reason: audit.ReasonUnexpected})
			if want := withResult && outcome != audit.OutcomeSuccess; counted != want || reported != want {
				t.Errorf("outcome %q, result %v: SQL counts %v, Check reports %v; want %v", outcome, withResult, counted, reported, want)
			}
		}
	}
	for _, w := range []audit.Writer{audit.WriterGateway, audit.WriterController} {
		r := rulesQuery(t, sql, w)
		if strings.Contains(r, "AS "+alias("bad", audit.KeyCheckResult)) || strings.Contains(r, "AS "+alias("not_for_action", audit.KeyCheckResult)) {
			t.Errorf("%s: the rules judge the check result by its sets; it is not_for_writer there", w)
		}
		if !strings.Contains(countIfOf(t, r, "not_for_writer"), "'"+audit.KeyCheckResult+"'") {
			t.Errorf("%s: the check result is missing from not_for_writer", w)
		}
	}
}
