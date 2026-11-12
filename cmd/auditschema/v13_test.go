package main

import (
	"regexp"
	"strings"
	"testing"
)

// A v0.12.0 record stays valid under v0.13.0: the records audit v0.12.0's
// own Emit wrote (testdata/v0.12.0/gen) get exactly the report v0.12.0's
// auditschema gave them, and the same exit code (the one record refused
// before resolution is marked target, and reported so).
func TestCheck_V0120RecordsStayValid(t *testing.T) { recordsStayValid(t, "v0.12.0") }

// `auditschema check` on rbac_not_allowed (v0.13.0): snowplow's DebugAuthz
// refusing POST /debug/shadow-parity is a denied path record with the reason
// and no status code. An authority's 403 is not this reason.
func TestCheck_V0130RBACNotAllowed(t *testing.T) {
	sub := func(base, old, new string) string {
		t.Helper()
		out := strings.Replace(base, old, new, 1)
		if out == base {
			t.Fatalf("precondition: %q does not occur", old)
		}
		return out
	}
	const reason = `{"key":"krateo.audit.denial_reason","value":{"stringValue":"rbac_not_allowed"}},`
	refused := sub(sub(shadowParity, `"stringValue":"success"`, `"stringValue":"denied"`), `{"key":"krateo.audit.dry_run"`,
		reason+`{"key":"krateo.audit.dry_run"`)
	for _, tc := range []struct {
		name, writer, record string
		want                 []string
	}{
		{"DebugAuthz refusing the path", "request", refused, nil},
		{"with the writer's own 403", "request", sub(refused, reason, reason+`{"key":"http.response.status_code","value":{"intValue":"403"}},`),
			[]string{"http.response.status_code: unexpected"}},
		{"on a failure", "request", sub(refused, `"stringValue":"denied"`, `"stringValue":"failure"`),
			[]string{"krateo.audit.denial_reason: unexpected"}},
		{"on a controller", "controller", sub(sub(controllerRecord, pruned, keptOutcome), "kept_resource_policy", "rbac_not_allowed"),
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
		})
	}
}
