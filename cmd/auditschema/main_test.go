package main

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/krateo-platformops/audit"
)

// A gateway projection record as OTLP/JSON, conformant to schema 1.
const gatewayRecord = `{"resourceLogs":[{"scopeLogs":[{"scope":{"name":"github.com/krateo-platformops/observability/gateway-audit"},"logRecords":[{
  "eventName":"audit",
  "attributes":[
    {"key":"event.name","value":{"stringValue":"audit"}},
    {"key":"krateo.audit.schema_version","value":{"stringValue":"1"}},
    {"key":"user.name","value":{"stringValue":"alice.identity.marker"}},
    {"key":"enduser.id","value":{"stringValue":"alice.identity.marker"}},
    {"key":"user.roles","value":{"arrayValue":{"values":[{"stringValue":"devs"}]}}},
    {"key":"krateo.audit.actor_class","value":{"stringValue":"human"}},
    {"key":"krateo.action","value":{"stringValue":"gateway.mcp"}},
    {"key":"krateo.audit.verb","value":{"stringValue":"post"}},
    {"key":"http.request.method","value":{"stringValue":"POST"}},
    {"key":"http.response.status_code","value":{"intValue":"200"}},
    {"key":"krateo.audit.outcome","value":{"stringValue":"success"}},
    {"key":"outcome","value":{"stringValue":"success"}},
    {"key":"server.address","value":{"stringValue":"mcp.example.com:8443"}},
    {"key":"krateo.request.source_ips","value":{"arrayValue":{"values":[{"stringValue":"10.0.0.1"}]}}},
    {"key":"krateo.audit.gateway.route","value":{"stringValue":"agents/mcp"}},
    {"key":"krateo.audit.gateway.mcp_tool","value":{"stringValue":"list_pods"}},
    {"key":"krateo.audit.asserted.agent_host","value":{"stringValue":"kagent-a"}}
  ]}]}]}]}`

func runIt(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func TestCheck_ConformantGatewayRecord(t *testing.T) {
	code, out, errs := runIt(t, gatewayRecord, "check", "-writer", "gateway")
	if code != 0 {
		t.Fatalf("exit %d\n%s%s", code, out, errs)
	}
	if !strings.Contains(out, "0 of 1 record(s) break schema 1") {
		t.Errorf("output: %q", out)
	}
}

func TestCheck_ReportsBreachesByKeyNeverByValue(t *testing.T) {
	bad := strings.Replace(gatewayRecord, `"krateo.audit.verb","value":{"stringValue":"post"}`, `"krateo.audit.verb","value":{"stringValue":"POST"}`, 1)
	bad = strings.Replace(bad, `{"key":"krateo.audit.gateway.route","value":{"stringValue":"agents/mcp"}},`, `{"key":"krateo.audit.object_ref.name","value":{"stringValue":"alice.identity.marker"}},`, 1)
	bad = strings.Replace(bad, `"eventName":"audit"`, `"eventName":"request"`, 1)
	if bad == gatewayRecord {
		t.Fatal("precondition: the mutation did not apply")
	}
	code, out, _ := runIt(t, bad, "check", "-writer", "gateway")
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, out)
	}
	for _, want := range []string{
		"record 0: krateo.audit.verb: bad-enum",
		"record 0: krateo.audit.object_ref.name: not-for-writer",
		"record 0: krateo.audit.gateway.route: missing",
		"record 0: LogRecord.EventName: bad-event-name",
		"1 of 1 record(s) break schema 1 for writer gateway",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "alice.identity.marker") {
		t.Errorf("the output carries a value:\n%s", out)
	}
}

func TestCheck_InputShapes(t *testing.T) {
	single := `{"eventName":"audit","attributes":[{"key":"user.name","value":{"stringValue":"u"}}]}`
	for name, in := range map[string]string{
		"one LogRecord":  single,
		"an array":       "[" + single + "," + single + "]",
		"a full request": gatewayRecord,
	} {
		code, out, errs := runIt(t, in, "check", "-writer", "controller")
		if code != 1 && code != 0 {
			t.Errorf("%s: exit %d: %s", name, code, errs)
		}
		if !regexp.MustCompile(`of [12] record\(s\)`).MatchString(out) {
			t.Errorf("%s: %q", name, out)
		}
	}
	v, err := (jsonAnyValue{IntValue: []byte("42")}).value()
	if err != nil || v.AsInt64() != 42 {
		t.Errorf("a numeric intValue: %v, %v", v, err)
	}
	kv, err := decodeRecords(strings.NewReader(`{"attributes":[{"key":"m","value":{"kvlistValue":{"values":[{"key":"k","value":{"doubleValue":1.5}}]}}},{"key":"b","value":{"bytesValue":"/w=="}},{"key":"e","value":{}}]}`))
	if err != nil || len(kv) != 1 || len(kv[0].attrs) != 3 {
		t.Fatalf("decode: %v %v", kv, err)
	}
	if got := string(kv[0].attrs[1].Value.AsByteSlice()); got != "\xff" {
		t.Errorf("bytesValue = %q", got)
	}
}

func TestCheck_UsageAndInputErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		stdin string
		args  []string
	}{
		"no command":     {"", nil},
		"unknown writer": {gatewayRecord, []string{"check", "-writer", "human"}},
		"no writer":      {gatewayRecord, []string{"check"}},
		"not JSON":       {"nope", []string{"check", "-writer", "gateway"}},
		"no record":      {`{"resourceLogs":[]}`, []string{"check", "-writer", "gateway"}},
		"bad intValue":   {`{"attributes":[{"key":"x","value":{"intValue":"x"}}]}`, []string{"check", "-writer", "gateway"}},
		"missing file":   {"", []string{"check", "-writer", "gateway", "/no/such/file.json"}},
		"sql with args":  {"", []string{"sql", "extra"}},
	} {
		if code, _, _ := runIt(t, tc.stdin, tc.args...); code != 2 {
			t.Errorf("%s: exit %d, want 2", name, code)
		}
	}
}

// A decode error names a position, a field or an attribute key and a reason,
// never a value from the input: audit values carry identity, and the error goes
// to stderr and CI logs. encoding/json and strconv quote their input, so each
// path that wraps one of them is driven with a marker value here.
func TestCheck_DecodeErrorsNeverPrintAValue(t *testing.T) {
	const secret = "alice.secret.identity"
	for name, in := range map[string]string{
		"intValue not a number": `{"attributes":[{"key":"k8s.object.generation","value":{"intValue":"` + secret + `"}}]}`,
		"bytesValue not base64": `{"attributes":[{"key":"b","value":{"bytesValue":"` + secret + `!"}}]}`,
		"JSON syntax error":     `{"attributes":[{"key":"user.name","value":{"stringValue":"x"}}]} ` + secret,
		"syntax error inside":   `{"attributes":[{"key":"user.name","value":{"stringValue":` + secret + `}}]}`,
		"number where a string": `{"eventName":4815162342,"attributes":[]}`,
	} {
		code, out, errs := runIt(t, in, "check", "-writer", "controller")
		if code != 2 {
			t.Errorf("%s: exit %d, want 2", name, code)
		}
		for _, leaked := range []string{secret, "4815162342"} {
			if strings.Contains(errs, leaked) || strings.Contains(out, leaked) {
				t.Errorf("%s: the output carries an input value:\n%s%s", name, out, errs)
			}
		}
		if !strings.Contains(errs, "auditschema: stdin: ") {
			t.Errorf("%s: no decode error reported: %q", name, errs)
		}
	}
}

func TestConditionSQLIsTotal(t *testing.T) {
	for _, c := range audit.Conditions() {
		if conditionSQL[c] == "" {
			t.Errorf("condition %s has no SQL predicate", c)
		}
	}
	if len(conditionSQL) != len(audit.Conditions()) {
		t.Errorf("conditionSQL names %d conditions, the schema %d", len(conditionSQL), len(audit.Conditions()))
	}
}

func TestSQL_IsGeneratedFromTheSchema(t *testing.T) {
	code, sql, _ := runIt(t, "", "sql")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	// One required-keys and one rules query per writer with a population.
	for _, w := range []audit.Writer{audit.WriterRequest, audit.WriterGateway, audit.WriterController} {
		for _, h := range []string{"-- Required keys, writer " + string(w) + ".", "-- Conditional keys, enums, closed set, target rule and W1 pairs, writer " + string(w) + "."} {
			if !strings.Contains(sql, h) {
				t.Errorf("no query %q", h)
			}
		}
	}
	// The controls.
	for _, want := range []string{"'claude.no.such.key'] AS required_keys", "'github.com/krateo-platformops/observability/gateway-audit', 'request')", "-- Its control, with only claude.no.such.key"} {
		if !strings.Contains(sql, want) {
			t.Errorf("the SQL lacks %q", want)
		}
	}
	// ARRAY JOIN needs the key and marker arrays to be the same length.
	keys := regexp.MustCompile(`WITH (\[[^\]]*\]) AS required_keys,\n\s+(\[[^\]]*\]) AS required_markers`).FindAllStringSubmatch(sql, -1)
	if len(keys) != 3 {
		t.Fatalf("%d required-keys queries, want 3", len(keys))
	}
	for _, m := range keys {
		if strings.Count(m[1], "', '") != strings.Count(m[2], "', '") {
			t.Errorf("key and marker arrays differ in length:\n%s\n%s", m[1], m[2])
		}
	}
	// Every enum and every key of the closed set appears.
	for _, k := range audit.Keys() {
		if !strings.Contains(sql, "'"+k.Name+"'") {
			t.Errorf("key %s is not in the SQL", k.Name)
		}
		if len(k.Values) > 0 && !strings.Contains(sql, alias("bad", k.Name)) {
			t.Errorf("enum %s has no bad_ column", k.Name)
		}
	}
	// Every only_when key has its unexpected_ column in the rules query of
	// each writer that has a population and may write the key.
	onlyWhen := 0
	for _, k := range audit.Keys() {
		if k.OnlyWhen == "" {
			continue
		}
		onlyWhen++
		want := 0
		for _, w := range audit.Writers() {
			if len(scopesOf(w, false)) > 0 && k.Writers[w].Level > audit.LevelNotEstablished {
				want++
			}
		}
		if want == 0 {
			t.Errorf("%s: no rules query can carry its column, so this arm tests nothing for it", k.Name)
		}
		// Whole aliases only: one key's alias may prefix another's
		// (endpoint_ref.name, endpoint_ref.namespace).
		if n := len(regexp.MustCompile(`AS ` + regexp.QuoteMeta(alias("unexpected", k.Name)) + `\b`).FindAllString(sql, -1)); n != want {
			t.Errorf("%s: %d unexpected_ columns, want %d (one per rules query of a writer that may write it)", k.Name, n, want)
		}
	}
	if onlyWhen == 0 {
		t.Errorf("no only_when key in the schema: the unexpected_ arm tests nothing (http.request.method_original has one)")
	}
	// The leak detector covers every identity key.
	leak := sql[strings.Index(sql, "-- Leak detector"):]
	for _, k := range audit.Keys() {
		if k.Identity && !strings.Contains(leak, "'"+k.Name+"'") {
			t.Errorf("identity key %s is not in the leak detector", k.Name)
		}
	}
}
