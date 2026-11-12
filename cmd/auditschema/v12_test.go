package main

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/krateo-platformops/audit"
	"go.opentelemetry.io/otel/attribute"
)

// A v0.11.0 record stays valid under v0.12.0: the records audit v0.11.0's
// own Emit wrote (testdata/v0.11.0/gen) get exactly the report v0.11.0's
// auditschema gave them, and the same exit code.
func TestCheck_V0110RecordsStayValid(t *testing.T) { recordsStayValid(t, "v0.11.0") }

// snowplow's POST /debug/shadow-parity as OTLP/JSON: a non-resource path is
// the target (v0.12.0).
const shadowParity = `{"eventName":"audit","attributes":[
  {"key":"event.name","value":{"stringValue":"audit"}},
  {"key":"krateo.audit.schema_version","value":{"stringValue":"1"}},
  {"key":"user.name","value":{"stringValue":"example-user"}},
  {"key":"krateo.audit.actor_class","value":{"stringValue":"human"}},
  {"key":"krateo.action","value":{"stringValue":"debug.shadowParity"}},
  {"key":"krateo.audit.verb","value":{"stringValue":"post"}},
  {"key":"http.request.method","value":{"stringValue":"POST"}},
  {"key":"krateo.audit.outcome","value":{"stringValue":"success"}},
  {"key":"krateo.audit.dry_run","value":{"boolValue":false}},
  {"key":"url.path","value":{"stringValue":"/debug/shadow-parity"}},
  {"key":"krateo.request.uri","value":{"stringValue":"/debug/shadow-parity"}},
  {"key":"krateo.request.source_ips","value":{"arrayValue":{"values":[{"stringValue":"192.0.2.10"}]}}},
  {"key":"session.id","value":{"stringValue":"example-session"}}
]}`

// `auditschema check` accepts and rejects what Check does for the v0.12.0
// rules, naming keys and reasons, never a value.
func TestCheck_V0120Rules(t *testing.T) {
	sub := func(base, old, new string) string {
		t.Helper()
		out := strings.Replace(base, old, new, 1)
		if out == base {
			t.Fatalf("precondition: %q does not occur", old)
		}
		return out
	}
	const path = `{"key":"url.path","value":{"stringValue":"/debug/shadow-parity"}},`
	endpoint := sub(shadowParity, path, `{"key":"server.address","value":{"stringValue":"api.example.com"}},`+
		`{"key":"krateo.audit.endpoint_ref.namespace","value":{"stringValue":"example-ns"}},`+
		`{"key":"krateo.audit.endpoint_ref.name","value":{"stringValue":"example-endpoint"}},`)
	for _, tc := range []struct {
		name, writer, record string
		want                 []string
	}{
		{"a non-resource path", "request", shadowParity, nil},
		{"a path beside an endpoint", "request", sub(shadowParity, path, path+`{"key":"server.address","value":{"stringValue":"api.example.com"}},`),
			[]string{"target: two-targets"}},
		{"a stage through an endpointRef", "request", endpoint, nil},
		{"a per-user Secret named", "request", sub(endpoint, `"example-endpoint"`, `"example-user-clientconfig"`),
			[]string{"krateo.audit.endpoint_ref.name: bad-format"}},
		{"an endpointRef on a path record", "request", sub(shadowParity, path, path+`{"key":"krateo.audit.endpoint_ref.name","value":{"stringValue":"example-endpoint"}},`),
			[]string{"krateo.audit.endpoint_ref.name: unexpected"}},
		{"a snowplow refusal", "request", sub(sub(endpoint, `"stringValue":"success"`, `"stringValue":"denied"`), `{"key":"krateo.audit.dry_run"`,
			`{"key":"krateo.audit.denial_reason","value":{"stringValue":"destination_refused"}},{"key":"krateo.audit.dry_run"`), nil},
		{"a snowplow refusal on a controller", "controller", sub(sub(controllerRecord, pruned, keptOutcome), "kept_resource_policy", "step_up_required"),
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
			for _, value := range []string{"example-user", "example-endpoint"} {
				if strings.Contains(out, value) {
					t.Errorf("the output carries the value %q:\n%s", value, out)
				}
			}
		})
	}
}

// The live target columns, executed: each writer's no_target, two_targets
// and target_marked_incomplete count a row exactly when Check reports the
// target missing, two targets, or incomplete, over every combination of the
// three target keys and the marker. A path is the request writer's target
// only.
func TestSQL_TargetColumnsCountWhatCheckReports(t *testing.T) {
	_, sql, _ := runIt(t, "", "sql")
	s := attribute.String
	keys := []attribute.KeyValue{s(audit.KeyObjectResource, "configmaps"), s(audit.KeyServerAddress, "api.example.com"), s(audit.KeyURLPath, "/x")}
	cols := map[string]audit.Reason{"no_target": audit.ReasonMissing, "two_targets": audit.ReasonTwoTargets, "target_marked_incomplete": audit.ReasonIncomplete}
	for _, w := range []audit.Writer{audit.WriterRequest, audit.WriterGateway, audit.WriterController} {
		q := rulesQuery(t, sql, w)
		for col, reason := range cols {
			if w == audit.WriterController && col == "two_targets" {
				if strings.Contains(q, "AS two_targets") {
					t.Errorf("controller: a two_targets column, but its records may name two")
				}
				continue
			}
			pred := countIfOf(t, q, col)
			counted, notCounted := 0, 0
			for mask := 0; mask < 16; mask++ {
				var row []attribute.KeyValue
				for i, kv := range keys {
					if mask&(1<<i) != 0 {
						row = append(row, kv)
					}
				}
				if mask&8 != 0 {
					row = append(row, s(audit.KeyIncomplete, "target"))
				}
				got, err := evalSQL(pred, rowOf(row))
				if err != nil {
					t.Fatalf("%s %s: %v\n%s", w, col, err, pred)
				}
				want := slices.Contains(audit.Check(w, row), audit.Violation{Key: audit.RuleTarget, Reason: reason})
				if got != want {
					t.Errorf("%s %s on mask %04b: SQL counts %v, Check reports %s %v", w, col, mask, got, reason, want)
				}
				if got {
					counted++
				} else {
					notCounted++
				}
			}
			if counted == 0 || notCounted == 0 {
				t.Errorf("%s %s: counted %d, not counted %d; the arm needs both", w, col, counted, notCounted)
			}
		}
	}
}
