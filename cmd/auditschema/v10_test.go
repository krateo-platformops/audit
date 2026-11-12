package main

import (
	"regexp"
	"strings"
	"testing"
)

// A v0.9.1 record stays valid: the records audit v0.9.1's own Emit wrote, per
// writer (testdata/v0.9.1/gen: authn's username checks, each check result,
// username_check_not_allowed, and the v0.6.0 to v0.8.0 shapes), get exactly the
// report v0.9.1's auditschema gave them, and the same exit code.
func TestCheck_V091RecordsStayValid(t *testing.T) { recordsStayValid(t, "v0.9.1") }

// `auditschema check` accepts invalid_request on authn's denied username
// check and rejects it elsewhere (v0.10.0, audit#29), naming keys and
// reasons, never a value.
func TestCheck_V0100InvalidRequest(t *testing.T) {
	sub := func(base, old, new string) string {
		t.Helper()
		out := strings.Replace(base, old, new, 1)
		if out == base {
			t.Fatalf("precondition: %q does not occur", old)
		}
		return out
	}
	const reason = `{"key":"krateo.audit.denial_reason","value":{"stringValue":"invalid_request"}},`
	// authn's refusal: denied, the Secret resource with no name, no result.
	refused := sub(sub(sub(usernameCheck, checkOutcome, `{"key":"krateo.audit.outcome","value":{"stringValue":"denied"}},`), checkResult, reason),
		`{"key":"krateo.audit.object_ref.name","value":{"stringValue":"example-user-clientconfig"}},`, "")
	// A sign-in refused with name_not_issued: authn's denied login, the
	// Secret resource with no name.
	notIssued := sub(sub(sub(authnDenied, "name_held_legacy", "name_not_issued"),
		`{"key":"krateo.audit.object_ref.name","value":{"stringValue":"example-user-clientconfig"}},`, ""),
		`"authn.login.oidc"`, `"authn.login.basic"`)
	for _, tc := range []struct {
		name, writer, record string
		want                 []string
	}{
		{"the refusal", "request", refused, nil},
		{"with a status code", "request", sub(refused, reason, reason+`{"key":"http.response.status_code","value":{"intValue":"400"}},`),
			[]string{"http.response.status_code: unexpected"}},
		{"with a check result", "request", sub(refused, reason, reason+checkResult), []string{"krateo.audit.check_result: unexpected"}},
		{"on a success", "request", sub(refused, `{"key":"krateo.audit.outcome","value":{"stringValue":"denied"}},`, checkOutcome),
			[]string{"krateo.audit.denial_reason: unexpected"}},
		{"on a controller", "controller", sub(sub(controllerRecord, pruned, keptOutcome), "kept_resource_policy", "invalid_request"),
			[]string{"krateo.audit.denial_reason: bad-enum"}},
		// name_not_issued: a sign-in for a username authn would issue in
		// another form, naming the Secret resource with no name.
		{"name not issued", "request", notIssued, nil},
		{"name not issued, with a status code", "request",
			sub(notIssued, `{"key":"krateo.audit.denial_reason","value":{"stringValue":"name_not_issued"}},`,
				`{"key":"krateo.audit.denial_reason","value":{"stringValue":"name_not_issued"}},{"key":"http.response.status_code","value":{"intValue":"403"}},`),
			[]string{"http.response.status_code: unexpected"}},
		{"name not issued, on a controller", "controller", sub(sub(controllerRecord, pruned, keptOutcome), "kept_resource_policy", "name_not_issued"),
			[]string{"krateo.audit.denial_reason: bad-enum"}},
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
			if strings.Contains(out, "example-user") {
				t.Errorf("the output carries an identity value:\n%s", out)
			}
		})
	}
}
