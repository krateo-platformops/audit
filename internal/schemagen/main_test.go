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
	for name, m := range map[string][2]string{
		"unknown level":        {"request: required, gateway: required, action: required, controller: required}", "request: mandatory, gateway: required, action: required, controller: required}"},
		"unknown field":        {"    semconv: deprecated\n", "    semconv: deprecated\n    colour: red\n"},
		"unknown type":         {"type: bool\n", "type: boolean\n"},
		"unknown condition":    {"check: k8s_target}", "check: k8s_targ}"},
		"when without cond":    {"controller: optional\n\n  - name: krateo.audit.actor_class", "controller: {level: optional, when: never}\n\n  - name: krateo.audit.actor_class"},
		"markable, no marker":  {"action: {level: conditional, when: the token carries groups}", "action: {level: conditional, when: the token carries groups, markable: true}"},
		"missing writer":       {"    writers: {request: optional, gateway: optional, action: optional, controller: not_applicable}", "    writers: {request: optional, gateway: optional, action: optional}"},
		"asserted outside":     {"    asserted: true\n", "    asserted: false\n"},
		"identity asserted":    {"    asserted: true\n", "    asserted: true\n    identity: true\n"},
		"dangling replacement": {"replaced_by: krateo.audit.outcome", "replaced_by: krateo.audit.result"},
		"duplicate key":        {"  - name: user.roles\n", "  - name: user.name\n"},
		"no target mode":       {"    controller: at_least_one\n", ""},
		"unknown only_when":    {"    only_when: method_other\n", "    only_when: method_othr\n"},
		// A `when` with an unquoted comma splits into a second, unknown field.
		"unquoted comma in when":    {`when: "a successful, non-dry-run write"}`, `when: a successful, non-dry-run write}`},
		"unknown requirement field": {"controller: {level: optional, values: [kept_resource_policy]}", "controller: {level: optional, values: [kept_resource_policy], colour: red}"},
		// Per-writer values: a closed set for every writer that may write the key, and for no other.
		"per-writer values, a writer without":             {"controller: {level: optional, values: [kept_resource_policy]}", "controller: optional"},
		"per-writer values on a writer that cannot write": {"      gateway: not_applicable\n      action: not_applicable\n      # kept", "      gateway: {level: not_applicable, values: [x]}\n      action: not_applicable\n      # kept"},
		"per-writer and key-level values":                 {"    only_when: denied\n", "    only_when: denied\n    values: [x]\n"},
		"per-writer values on a non-string":               {"values: [kept_resource_policy]}", "values: [kept_resource_policy]}\n\n  - name: x.int\n    go: XInt\n    type: int\n    semconv: none\n    description: d\n    writers: {request: optional, gateway: not_applicable, action: not_applicable, controller: {level: optional, values: [one]}}"},
		"malformed per-writer value":                      {"values: [kept_resource_policy]}", "values: [Kept-Resource-Policy]}"},
		"duplicate per-writer value":                      {"values: [kept_resource_policy]}", "values: [kept_resource_policy, kept_resource_policy]}"},
		"duplicate population scope":                      {"  - scope: github.com/krateo-platformops/authn/audit/controller\n", "  - scope: github.com/krateo-platformops/authn/audit\n"},
	} {
		t.Run(name, func(t *testing.T) {
			bad := strings.Replace(src, m[0], m[1], 1)
			if bad == src {
				t.Fatalf("precondition: the mutation %q did not apply", m[0])
			}
			if _, err := parse([]byte(bad)); err == nil {
				t.Errorf("parse accepted the schema with %s", name)
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
