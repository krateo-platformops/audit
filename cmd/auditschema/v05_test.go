package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/krateo-platformops/audit"
)

// A v0.4.0 record stays valid: the records audit v0.4.0's own Emit wrote, per
// writer (testdata/v0.4.0/<writer>.json), get exactly the report v0.4.0's
// auditschema gave them (<writer>.check-v0.4.0.txt, captured with the v0.4.0
// binary), and the same exit code.
func TestCheck_V040RecordsStayValid(t *testing.T) { recordsStayValid(t, "v0.4.0") }

// recordsStayValid replays testdata/<version>/<writer>.json, the records that
// release's own Emit wrote, and expects the report and exit code that
// release's own auditschema gave (<writer>.check-<version>.txt).
func recordsStayValid(t *testing.T, version string) {
	files, err := filepath.Glob("../../testdata/" + version + "/*.json")
	if err != nil || len(files) < 3 {
		t.Fatalf("%s fixtures: %v, %v", version, files, err)
	}
	for _, f := range files {
		w := strings.TrimSuffix(filepath.Base(f), ".json")
		want, err := os.ReadFile(strings.TrimSuffix(f, ".json") + ".check-" + version + ".txt")
		if err != nil {
			t.Fatal(err)
		}
		code, out, errs := runIt(t, "", "check", "-writer", w, f)
		// The report names the file as the caller spelled it; the release
		// was run from the module root.
		out = strings.ReplaceAll(out, "../../", "")
		if out != string(want) {
			t.Errorf("%s: this release reports\n%s\n%s reported\n%s%s", w, out, version, want, errs)
		}
		if wantCode := map[bool]int{true: 0, false: 1}[strings.HasPrefix(string(want), "0 of ")]; code != wantCode {
			t.Errorf("%s: exit %d, %s exited %d", w, code, version, wantCode)
		}
	}
}

// A controller row as OTLP/JSON: a pruned helm child, the object written in
// object_ref and the reconciled resource in cause_ref.
const controllerRecord = `{"eventName":"audit","attributes":[
  {"key":"event.name","value":{"stringValue":"audit"}},
  {"key":"krateo.audit.schema_version","value":{"stringValue":"1"}},
  {"key":"user.name","value":{"stringValue":"system:serviceaccount:example-system:example-controller"}},
  {"key":"krateo.audit.actor_class","value":{"stringValue":"controller"}},
  {"key":"krateo.action","value":{"stringValue":"helm.upgrade"}},
  {"key":"krateo.audit.verb","value":{"stringValue":"delete"}},
  {"key":"http.request.method","value":{"stringValue":"DELETE"}},
  {"key":"krateo.audit.outcome","value":{"stringValue":"success"}},
  {"key":"krateo.audit.preview","value":{"boolValue":false}},
  {"key":"k8s.namespace.name","value":{"stringValue":"example-ns"}},
  {"key":"krateo.audit.object_ref.api_group","value":{"stringValue":"apps"}},
  {"key":"krateo.audit.object_ref.api_version","value":{"stringValue":"v1"}},
  {"key":"krateo.audit.object_ref.resource","value":{"stringValue":"deployments"}},
  {"key":"krateo.audit.object_ref.name","value":{"stringValue":"example-worker"}},
  {"key":"krateo.audit.cause_ref.api_group","value":{"stringValue":"composition.krateo.io"}},
  {"key":"krateo.audit.cause_ref.api_version","value":{"stringValue":"v1-2-0"}},
  {"key":"krateo.audit.cause_ref.resource","value":{"stringValue":"exampleapps"}},
  {"key":"krateo.audit.cause_ref.namespace","value":{"stringValue":"example-ns"}},
  {"key":"krateo.audit.cause_ref.name","value":{"stringValue":"example-composition"}},
  {"key":"krateo.audit.cause_ref.uid","value":{"stringValue":"00000000-0000-4000-8000-0000000000c1"}},
  {"key":"krateo.audit.cause_ref.generation","value":{"intValue":"4"}}
]}`

// An authn login refusal as OTLP/JSON: a request writer's denied record.
const authnDenied = `{"eventName":"audit","attributes":[
  {"key":"event.name","value":{"stringValue":"audit"}},
  {"key":"krateo.audit.schema_version","value":{"stringValue":"1"}},
  {"key":"user.name","value":{"stringValue":"example-user"}},
  {"key":"krateo.audit.actor_class","value":{"stringValue":"human"}},
  {"key":"krateo.action","value":{"stringValue":"authn.login.oidc"}},
  {"key":"krateo.audit.verb","value":{"stringValue":"update"}},
  {"key":"http.request.method","value":{"stringValue":"PUT"}},
  {"key":"krateo.audit.outcome","value":{"stringValue":"denied"}},
  {"key":"krateo.audit.denial_reason","value":{"stringValue":"name_held_legacy"}},
  {"key":"krateo.audit.dry_run","value":{"boolValue":false}},
  {"key":"krateo.audit.preview","value":{"boolValue":false}},
  {"key":"k8s.namespace.name","value":{"stringValue":"example-system"}},
  {"key":"krateo.audit.object_ref.api_version","value":{"stringValue":"v1"}},
  {"key":"krateo.audit.object_ref.resource","value":{"stringValue":"secrets"}},
  {"key":"krateo.audit.object_ref.name","value":{"stringValue":"example-user-clientconfig"}},
  {"key":"krateo.request.uri","value":{"stringValue":"/oidc/callback"}},
  {"key":"krateo.request.source_ips","value":{"arrayValue":{"values":[{"stringValue":"192.0.2.10"}]}}},
  {"key":"session.id","value":{"stringValue":"example-session"}}
]}`

const (
	pruned       = `{"key":"krateo.audit.outcome","value":{"stringValue":"success"}},`
	keptOutcome  = `{"key":"krateo.audit.outcome","value":{"stringValue":"denied"}},{"key":"krateo.audit.denial_reason","value":{"stringValue":"kept_resource_policy"}},`
	causeUID     = `{"key":"krateo.audit.cause_ref.uid","value":{"stringValue":"00000000-0000-4000-8000-0000000000c1"}},`
	causeVersion = `{"key":"krateo.audit.cause_ref.api_version","value":{"stringValue":"v1-2-0"}},`
	authnReason  = `{"key":"krateo.audit.denial_reason","value":{"stringValue":"name_held_legacy"}},`
	authnOutcome = `{"key":"krateo.audit.outcome","value":{"stringValue":"denied"}},`
	httpMethod   = `{"key":"http.request.method","value":{"stringValue":"DELETE"}},`
)

// `auditschema check` accepts and rejects what Check does for every v0.5.0
// rule: cause_ref (controller only, all of a piece once named) and
// denial_reason (denied only, the writer's own closed set). It names keys and
// reasons, never a value.
func TestCheck_CauseRefAndDenialReasonRules(t *testing.T) {
	sub := func(base, old, new string) string {
		t.Helper()
		out := strings.Replace(base, old, new, 1)
		if out == base {
			t.Fatalf("precondition: %q does not occur", old)
		}
		return out
	}
	kept := sub(sub(controllerRecord, pruned, keptOutcome), httpMethod, "")
	for _, tc := range []struct {
		name, writer, record string
		want                 []string // the violation lines; none: accepted
	}{
		{"pruned child", "controller", controllerRecord, nil},
		{"kept deletion", "controller", kept, nil},
		{"authn refusal", "request", authnDenied, nil},
		{"authn group gate", "request", sub(authnDenied, "name_held_legacy", "group_not_allowed"), nil},
		{"authn group gate on a controller", "controller", sub(kept, "kept_resource_policy", "group_not_allowed"), []string{"krateo.audit.denial_reason: bad-enum"}},
		{"a partial cause_ref", "controller", sub(sub(controllerRecord, causeUID, ""), causeVersion, ""),
			[]string{"krateo.audit.cause_ref.api_version: missing", "krateo.audit.cause_ref.uid: missing"}},
		{"a cause without its uid", "controller", sub(controllerRecord, causeUID, ""), []string{"krateo.audit.cause_ref.uid: missing"}},
		{"cause_ref on a request writer", "request", sub(authnDenied, authnReason, authnReason+causeUID), []string{"krateo.audit.cause_ref.uid: not-for-writer"}},
		{"a reason on a success", "controller", sub(controllerRecord, pruned, pruned+`{"key":"krateo.audit.denial_reason","value":{"stringValue":"kept_resource_policy"}},`),
			[]string{"krateo.audit.denial_reason: unexpected"}},
		{"another writer's reason", "controller", sub(kept, "kept_resource_policy", "name_claimed"), []string{"krateo.audit.denial_reason: bad-enum"}},
		{"the body text as a reason", "controller", sub(kept, `"kept_resource_policy"`, `"kept: resource-policy"`), []string{"krateo.audit.denial_reason: bad-enum"}},
		{"the controller's reason on authn", "request", sub(authnDenied, "name_held_legacy", "kept_resource_policy"), []string{"krateo.audit.denial_reason: bad-enum"}},
		{"authn's reason on a failure", "request", sub(authnDenied, authnOutcome, `{"key":"krateo.audit.outcome","value":{"stringValue":"failure"}},`),
			[]string{"krateo.audit.denial_reason: unexpected"}},
		// A denied record carries no status code (v0.6.0, audit#13): the
		// gateway record's 200 goes with its success.
		{"a reason on the gateway", "gateway", sub(sub(sub(gatewayRecord, `"krateo.audit.outcome","value":{"stringValue":"success"}`, `"krateo.audit.outcome","value":{"stringValue":"denied"}`),
			`{"key":"outcome","value":{"stringValue":"success"}},`, `{"key":"outcome","value":{"stringValue":"denied"}},`+authnReason),
			`{"key":"http.response.status_code","value":{"intValue":"200"}},`, ""),
			[]string{"krateo.audit.denial_reason: not-for-writer"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errs := runIt(t, tc.record, "check", "-writer", tc.writer)
			if errs != "" {
				t.Fatalf("stderr: %s", errs)
			}
			lines := regexp.MustCompile(`(?m)^stdin: record 0: (.*)$`).FindAllStringSubmatch(out, -1)
			var got []string
			for _, l := range lines {
				got = append(got, l[1])
			}
			if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
				t.Errorf("violations:\n got %q\nwant %q", got, tc.want)
			}
			if wantCode := map[bool]int{true: 0, false: 1}[len(tc.want) == 0]; code != wantCode {
				t.Errorf("exit %d, want %d", code, wantCode)
			}
			for _, value := range []string{"example-user", "example-composition", "name_claimed", "kept: resource-policy"} {
				if strings.Contains(out, value) {
					t.Errorf("the output carries the value %q:\n%s", value, out)
				}
			}
		})
	}
}

// The live queries carry the v0.5.0 rules: the denial reason's closed set per
// writer and its only_when, cause_ref's conditional keys, authn's own
// populations, and denial_reason/cause_ref in not_for_writer elsewhere.
func TestSQL_CauseRefAndDenialReason(t *testing.T) {
	_, sql, _ := runIt(t, "", "sql")
	rules := map[audit.Writer]string{}
	for _, q := range strings.Split(sql, "-- Conditional keys, enums, closed set, target rule and W1 pairs, writer ")[1:] {
		w, _, _ := strings.Cut(q, ".")
		rules[audit.Writer(w)] = q[:strings.Index(q, ";")]
	}
	bad := alias("bad", audit.KeyDenialReason)
	if q := rules[audit.WriterRequest]; !strings.Contains(q, "'name_held_legacy'") || strings.Contains(q, "'kept_resource_policy'") || !strings.Contains(q, bad) {
		t.Errorf("the request writer's bad_ column is not authn's set:\n%s", q)
	}
	if q := rules[audit.WriterController]; !strings.Contains(q, "NOT IN ('', 'kept_resource_policy')) AS "+bad) {
		t.Errorf("the controller's bad_ column is not its set:\n%s", q)
	}
	for _, w := range []audit.Writer{audit.WriterRequest, audit.WriterController} {
		if !strings.Contains(rules[w], "AS "+alias("unexpected", audit.KeyDenialReason)) {
			t.Errorf("%s: no unexpected_ column for the denial reason", w)
		}
	}
	if q := rules[audit.WriterController]; !strings.Contains(q, "AS "+alias("unmet", audit.KeyCauseUID)) || !strings.Contains(q, "startsWith(k, 'krateo.audit.cause_ref.')") {
		t.Errorf("the controller's rules lack the cause_ref.uid condition:\n%s", q)
	}
	for _, w := range []audit.Writer{audit.WriterRequest, audit.WriterGateway} {
		nfw := regexp.MustCompile(`countIf\(arrayExists\(k -> has\((\[[^\]]*\]), k\), mapKeys\(LogAttributes\)\)\) AS not_for_writer`).FindStringSubmatch(rules[w])
		if nfw == nil || !strings.Contains(nfw[1], "'"+audit.KeyCauseUID+"'") {
			t.Errorf("%s: cause_ref is not in not_for_writer", w)
		}
	}
}

// authn emits as two writers, each on its own scope, and the live queries
// judge each scope by its own writer's rules only: logins and /delegate as
// request rows, the background credential writes as controller rows.
func TestSQL_AuthnScopesAreTwoWriters(t *testing.T) {
	const (
		authnRequest    = "github.com/krateo-platformops/authn/audit"
		authnController = "github.com/krateo-platformops/authn/audit/controller"
	)
	_, sql, _ := runIt(t, "", "sql")
	// The scope list of every query, by writer: required keys and rules.
	scopes := map[audit.Writer][]string{}
	for _, head := range []string{"-- Required keys, writer ", "-- Conditional keys, enums, closed set, target rule and W1 pairs, writer "} {
		for _, q := range strings.Split(sql, head)[1:] {
			w, _, _ := strings.Cut(q, ".")
			m := regexp.MustCompile(`AND ScopeName IN \(([^)]*)\)`).FindStringSubmatch(q[:strings.Index(q, ";")])
			if m == nil {
				t.Fatalf("writer %s: a query with no scope list", w)
			}
			scopes[audit.Writer(w)] = append(scopes[audit.Writer(w)], m[1])
		}
	}
	for w, want := range map[audit.Writer]string{audit.WriterRequest: authnRequest, audit.WriterController: authnController} {
		if len(scopes[w]) != 2 {
			t.Fatalf("writer %s: %d queries, want 2 (required keys, rules)", w, len(scopes[w]))
		}
		for _, list := range scopes[w] {
			if !strings.Contains(list, "'"+want+"'") {
				t.Errorf("writer %s: a query does not read authn's scope %s: %s", w, want, list)
			}
		}
	}
	for w, lists := range scopes {
		for _, list := range lists {
			for scope, owner := range map[string]audit.Writer{authnRequest: audit.WriterRequest, authnController: audit.WriterController} {
				if w != owner && strings.Contains(list, "'"+scope+"'") {
					t.Errorf("writer %s's query reads %s, which belongs to %s", w, scope, owner)
				}
			}
		}
	}
}
