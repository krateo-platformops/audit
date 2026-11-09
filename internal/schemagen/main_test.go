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
	src, md, err := generate("../../schema/v1.yaml")
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
	if bytes.Equal(base, mutated) || bytes.Equal(renderDoc(s), renderDoc(s2)) {
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
