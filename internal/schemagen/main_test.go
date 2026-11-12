package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// The committed schema_gen.go and docs/schema.md are exactly what `go
// generate` produces from the committed schema/v1.yaml. Fails when either
// changed without the other: run `go generate ./...` in the module root.
func TestGeneratedFilesAreCurrent(t *testing.T) {
	src, md, err := generate("../../schema/v1.yaml", "../../contract_records_test.go")
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string][]byte{"../../schema_gen.go": src, "../../docs/schema.md": md} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s is stale: run `go generate ./...` in the module root", path)
		}
	}
}

// The staleness check can fail: a one-word change to the schema changes the
// generated file.
func TestGeneratedFileFollowsTheSchema(t *testing.T) {
	raw, err := os.ReadFile("../../schema/v1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	s, err := parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	base, err := render(s)
	if err != nil {
		t.Fatal(err)
	}
	changed := bytes.Replace(raw, []byte("values: [success, failure, denied]"), []byte("values: [success, failure]"), 1)
	if bytes.Equal(changed, raw) {
		t.Fatal("precondition: the mutation did not apply")
	}
	s2, err := parse(changed)
	if err != nil {
		t.Fatal(err)
	}
	mutated, err := render(s2)
	if err != nil {
		t.Fatal(err)
	}
	ex := map[string]string{}
	for _, n := range exampleNames {
		ex[n] = "x\n"
	}
	if bytes.Equal(base, mutated) || bytes.Equal(renderDoc(s, ex), renderDoc(s2, ex)) {
		t.Fatal("a schema change left the generated file unchanged")
	}
}

// The generator refuses a schema that breaks its own rules.
func TestParse_RefusesABrokenSchema(t *testing.T) {
	raw, err := os.ReadFile("../../schema/v1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	// Each arm: the text replaced, its replacement, and the refusal it must
	// get, so an arm cannot pass on another rule's refusal.
	for name, m := range map[string][3]string{
		"unknown level":        {"request: required, gateway: required, action: required, controller: required}", "request: mandatory, gateway: required, action: required, controller: required}", `unknown level "mandatory"`},
		"unknown field":        {"    semconv: deprecated\n", "    semconv: deprecated\n    colour: red\n", "colour"},
		"unknown type":         {"type: bool\n", "type: boolean\n", `unknown type "boolean"`},
		"unknown condition":    {"check: k8s_target}", "check: k8s_targ}", "needs a conditional level and a declared condition"},
		"when without cond":    {"controller: optional\n\n  - name: krateo.audit.actor_class", "controller: {level: optional, when: never}\n\n  - name: krateo.audit.actor_class", "`when` goes with, and only with, conditional"},
		"markable, no marker":  {"action: {level: conditional, when: the token carries groups}", "action: {level: conditional, when: the token carries groups, markable: true}", "markable needs a marker"},
		"missing writer":       {"    writers: {request: optional, gateway: optional, action: optional, controller: not_applicable}", "    writers: {request: optional, gateway: optional, action: optional}", `no requirement for writer "controller"`},
		"asserted outside":     {"    asserted: true\n", "    asserted: false\n", "asserted keys, and only they"},
		"identity asserted":    {"    asserted: true\n", "    asserted: true\n    identity: true\n", "an asserted key is never identity"},
		"dangling replacement": {"replaced_by: krateo.audit.outcome", "replaced_by: krateo.audit.result", "is not a current key"},
		"duplicate key":        {"  - name: user.roles\n", "  - name: user.name\n", "(UserRoles): duplicate"},
		"no target mode":       {"    controller: at_least_one\n", "", `writer "controller" has no mode`},
		"unknown only_when":    {"    only_when: method_other\n", "    only_when: method_othr\n", `only_when "method_othr" is not a declared condition`},
		// A `when` with an unquoted comma splits into a second, unknown field.
		"unquoted comma in when":    {`when: "a successful, non-dry-run write"}`, `when: a successful, non-dry-run write}`, `requirement field "non-dry-run write" is not one of`},
		"unknown requirement field": {"controller: {level: optional, values: [kept_resource_policy]}", "controller: {level: optional, values: [kept_resource_policy], colour: red}", `requirement field "colour" is not one of`},
		// Per-action values (v0.9.0, audit#23): a closed set per krateo.action,
		// declared by every writer that may write the key, and by no other.
		"per-action and per-writer values":  {"request: {level: optional, actions: {authn.username.check:", "request: {level: optional, values: [x], actions: {authn.username.check:", "per-writer values and per-action values exclude each other"},
		"per-action and key-level values":   {"    go: CheckResult\n    type: string\n", "    go: CheckResult\n    type: string\n    values: [x]\n", "per-action values and key-level values exclude each other"},
		"per-action values on a non-string": {"    go: CheckResult\n    type: string\n", "    go: CheckResult\n    type: int\n", `key "krateo.audit.check_result": per-action values need a string key, not int`},
		"per-action values, a writer without": {"invalid]}}\n      gateway: not_applicable\n", "invalid]}}\n      gateway: optional\n",
			`key "krateo.audit.check_result", writer "gateway": every writer that may write a key with per-action values declares its own`},
		"per-action values on a writer that cannot write": {"invalid]}}\n      gateway: not_applicable\n", "invalid]}}\n      gateway: {level: not_applicable, actions: {gateway.mcp: [x]}}\n",
			`key "krateo.audit.check_result", writer "gateway": every writer that may write a key with per-action values declares its own`},
		"malformed action":            {"actions: {authn.username.check:", "actions: {Authn.UsernameCheck:", `action "Authn.UsernameCheck" is not a krateo.action literal`},
		"an action with an empty set": {"actions: {authn.username.check: [available, reserved, name_claimed, name_held_legacy, name_provisioned, name_bound, invalid]}", "actions: {authn.username.check: []}", `action "authn.username.check": an empty set`},
		"malformed per-action value":  {"authn.username.check: [available,", "authn.username.check: [Available,", `value "Available" is malformed`},
		"duplicate per-action value":  {"authn.username.check: [available,", "authn.username.check: [available, available,", `value "available" is malformed (lower_snake_case) or duplicate`},
		// Per-writer values: a closed set for every writer that may write the key, and for no other.
		"per-writer values, a writer without":             {"controller: {level: optional, values: [kept_resource_policy]}", "controller: optional", `key "krateo.audit.denial_reason", writer "controller": every writer that may write`},
		"per-writer values on a writer that cannot write": {"      gateway: not_applicable\n      action: not_applicable\n      # kept", "      gateway: {level: not_applicable, values: [x]}\n      action: not_applicable\n      # kept", `writer "gateway": every writer that may write`},
		"per-writer and key-level values":                 {"    only_when: denied\n", "    only_when: denied\n    values: [x]\n", "per-writer values and key-level values exclude each other"},
		// Every other writer not_applicable: only the type rule can refuse it.
		"per-writer values on a non-string": {"values: [kept_resource_policy]}", "values: [kept_resource_policy]}\n\n  - name: x.int\n    go: XInt\n    type: int\n    semconv: none\n    description: d\n    writers: {request: not_applicable, gateway: not_applicable, action: not_applicable, controller: {level: optional, values: [one]}}", `key "x.int": per-writer values need a string key, not int`},
		"malformed per-writer value":        {"values: [kept_resource_policy]}", "values: [Kept-Resource-Policy]}", `value "Kept-Resource-Policy" is malformed`},
		"duplicate per-writer value":        {"values: [kept_resource_policy]}", "values: [kept_resource_policy, kept_resource_policy]}", `value "kept_resource_policy" is malformed (lower_snake_case) or duplicate`},
		// a_b1 and a_b_1 are both well formed, and both make DenialReasonAB1.
		"two values, one constant":   {"values: [kept_resource_policy]}", "values: [kept_resource_policy, a_b1, a_b_1]}", "both make the constant DenialReasonAB1"},
		"duplicate population scope": {"  - scope: github.com/krateo-platformops/authn/audit/controller\n", "  - scope: github.com/krateo-platformops/authn/audit\n", `population "github.com/krateo-platformops/authn/audit": duplicate scope`},
		// v0.6.0: not_when, credential_free, the int bounds, the new formats and the client prefix.
		"unknown not_when":                    {"    not_when: denied\n", "    not_when: denid\n", `not_when "denid" is not a declared condition`},
		"not_when equal to only_when":         {"    only_when: write\n    not_when: client_rejected\n", "    only_when: write\n    not_when: write\n", "only_when and not_when name the same condition"},
		"credential_free, no targets":         {"credential_targets:\n  - {api_group: \"\", resource: secrets}\n  - {api_group: \"\", resource: serviceaccounts, subresource: token}\n  - {api_group: authentication.k8s.io, resource: tokenreviews}\n", "credential_targets: []\n", "credential_free with no credential_targets"},
		"content annotation without a prefix": {"  - authn.krateo.io/strategy\n", "  - strategy\n", `content annotation "strategy": a qualified annotation key`},
		"duplicate content annotation":        {"  - authn.krateo.io/groups\n", "  - authn.krateo.io/strategy\n", `content annotation "authn.krateo.io/strategy": a qualified annotation key (prefix/name), listed once`},
		"credential target, no resource":      {"  - {api_group: \"\", resource: secrets}\n", "  - {api_group: \"\"}\n", "a resource is required"},
		"duplicate credential target":         {"  - {api_group: \"\", resource: serviceaccounts, subresource: token}\n", "  - {api_group: \"\", resource: secrets}\n", "each target is listed once"},
		"unknown format":                      {"    format: sha256_hex\n", "    format: sha256\n", `unknown format "sha256"`},
		"format on an int":                    {"    minimum: 1\n", "    minimum: 1\n    format: uuid\n", "format uuid needs a string key, not int"},
		"minimum on a string":                 {"    format: opaque_id\n", "    format: opaque_id\n    minimum: 1\n", "minimum and less_than bound an int key, not string"},
		"less_than an unknown key":            {"less_than: krateo.audit.client.confirmed_set.count", "less_than: krateo.audit.client.confirmed_set.size", `less_than "krateo.audit.client.confirmed_set.size" is not another int key`},
		"less_than a string key":              {"less_than: krateo.audit.client.confirmed_set.count", "less_than: krateo.audit.client.confirmed_set.sha256", "is not another int key"},
		"less_than itself":                    {"less_than: krateo.audit.client.confirmed_set.count", "less_than: krateo.audit.client.confirmed_set.op", "is not another int key"},
		"client key not asserted":             {"    asserted: true\n    values: [portal]\n", "    values: [portal]\n", "asserted keys, and only they, live under the prefixes"},
		"asserted key outside the prefixes":   {"  - name: krateo.audit.client.requested_at\n", "  - name: krateo.audit.requested_at\n", "asserted keys, and only they, live under the prefixes"},
		"an asserted key required":            {"      request: {level: conditional, when: the record carries client provenance, check: client_provenance}\n", "      request: required\n", "an asserted key is never required"},
		"an asserted key marked":              {"    values: [portal]\n", "    values: [portal]\n    marker: source\n", "an asserted key is never marked and never a target"},
	} {
		t.Run(name, func(t *testing.T) {
			bad := strings.Replace(src, m[0], m[1], 1)
			if bad == src {
				t.Fatalf("precondition: the mutation %q did not apply", m[0])
			}
			_, err := parse([]byte(bad))
			if err == nil {
				t.Fatalf("parse accepted the schema with %s", name)
			}
			if !strings.Contains(err.Error(), m[2]) {
				t.Errorf("parse refused it for another reason:\n got %v\nwant %q", err, m[2])
			}
		})
	}
}

// Every format schema/v1.yaml declares is documented in docs/schema.md, with
// its validator's name and, when it has one, its pattern; and the generator
// refuses a format that is unnamed, undescribed, repeated, unanchored or not
// a regular expression, and a key naming an undeclared format.
func TestFormatsAreDocumented(t *testing.T) {
	raw, err := os.ReadFile("../../schema/v1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	s, err := parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Formats) == 0 {
		t.Fatal("schema/v1.yaml declares no format")
	}
	md, err := os.ReadFile("../../docs/schema.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.Join(strings.Fields(string(md)), " ")
	for _, f := range s.Formats {
		if !strings.Contains(doc, "- `"+f.ID+"` (`audit.Valid"+f.Go+"`): "+strings.Join(strings.Fields(f.Description), " ")) {
			t.Errorf("docs/schema.md does not document format %s", f.ID)
		}
		if f.Pattern != "" && !strings.Contains(doc, "Pattern `"+f.Pattern+"`") {
			t.Errorf("docs/schema.md does not show format %s's pattern", f.ID)
		}
	}
	src := string(raw)
	// The mutations are built from the declared pattern, so no copy of it
	// lives here.
	var p string
	for _, f := range s.Formats {
		if f.ID == "opaque_id" {
			p = f.Pattern
		}
	}
	if p == "" {
		t.Fatal("precondition: opaque_id declares no pattern")
	}
	for name, m := range map[string][3]string{
		"undeclared format":  {"    format: opaque_id\n", "    format: opaque_idx\n", `unknown format "opaque_idx"`},
		"unanchored pattern": {"pattern: '" + p + "'", "pattern: '" + strings.TrimSuffix(strings.TrimPrefix(p, "^"), "$") + "'", "a pattern is anchored"},
		"bad pattern":        {"pattern: '" + p + "'", "pattern: '" + strings.Replace(p, "]", "", 1) + "'", `format "opaque_id": pattern:`},
		"repeated format":    {"  - id: rfc3339\n", "  - id: uuid\n", `format "uuid": id (lower_snake_case), go and description are required, and the id once`},
		"no description":     {"    description: an RFC 3339 timestamp, with or without fractional seconds.\n", "", `format "rfc3339": id (lower_snake_case), go and description are required`},
	} {
		t.Run(name, func(t *testing.T) {
			bad := strings.Replace(src, m[0], m[1], 1)
			if bad == src {
				t.Fatalf("precondition: the mutation %q did not apply", m[0])
			}
			if _, err := parse([]byte(bad)); err == nil || !strings.Contains(err.Error(), m[2]) {
				t.Errorf("parse: %v; want %q", err, m[2])
			}
		})
	}
}

// The doc shows the example regions of the examples file, and generate
// refuses a file whose regions are missing, unclosed, unknown or repeated.
func TestExampleRegions(t *testing.T) {
	src, err := os.ReadFile("../../contract_records_test.go")
	if err != nil {
		t.Fatal(err)
	}
	got, err := exampleRegions(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range exampleNames {
		if !strings.Contains(got[n], "audit.") || strings.HasPrefix(got[n], "\t") {
			t.Errorf("region %s is not dedented Go: %q", n, got[n])
		}
	}
	good := "x\n\t// schema.md: controller-emitter\n\t\ta\n\t// schema.md: end\n\t// schema.md: kept-deletion\n\tb\n\t// schema.md: end\n// schema.md: pruned-child\nc\n// schema.md: end\n"
	r, err := exampleRegions([]byte(good))
	if err != nil || r["controller-emitter"] != "a\n" || r["kept-deletion"] != "b\n" || r["pruned-child"] != "c\n" {
		t.Fatalf("regions of a good file: %q, %v", r, err)
	}
	for name, bad := range map[string]string{
		"missing":   strings.Replace(good, "// schema.md: pruned-child\nc\n// schema.md: end\n", "", 1),
		"unclosed":  strings.TrimSuffix(good, "// schema.md: end\n"),
		"unknown":   strings.Replace(good, "pruned-child", "pruned-kid", 1),
		"repeated":  good + "// schema.md: kept-deletion\nd\n// schema.md: end\n",
		"nested":    strings.Replace(good, "\t\ta\n", "\t\ta\n// schema.md: kept-deletion\n", 1),
		"stray end": "// schema.md: end\n" + good,
	} {
		if bad == good {
			t.Fatalf("%s: precondition: the mutation did not apply", name)
		}
		if _, err := exampleRegions([]byte(bad)); err == nil {
			t.Errorf("%s: exampleRegions accepted it", name)
		}
	}
}
