package main

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// unregistered is every (writer, action) a per-action closed set of s
// declares that actionLiterals does not register under that writer.
func unregistered(s *schema, registry []actionLiteral) []string {
	var out []string
	for _, k := range s.Keys {
		for w, r := range k.Writers {
			for a := range r.Actions {
				if !slices.ContainsFunc(registry, func(l actionLiteral) bool { return l.Writer == w && l.Literal == a }) {
					out = append(out, k.Name+": writer "+w+", action "+a)
				}
			}
		}
	}
	slices.Sort(out)
	return out
}

func parseSchema(t *testing.T, src string) *schema {
	t.Helper()
	s, err := parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// audit#25: every action a per-action closed set declares in schema/v1.yaml
// is in the krateo.action literal registry, under the writer that declares
// it. The check can fail: an action declared and not registered is reported,
// and one registered under another writer is too.
func TestActionLiterals_RegistryNamesEveryDeclaredAction(t *testing.T) {
	raw, err := os.ReadFile("../../schema/v1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	s := parseSchema(t, src)
	declared := 0
	for _, k := range s.Keys {
		for _, r := range k.Writers {
			declared += len(r.Actions)
		}
	}
	if declared == 0 {
		t.Fatal("schema/v1.yaml declares no per-action set: the check would test nothing")
	}
	if miss := unregistered(s, actionLiterals); len(miss) > 0 {
		t.Errorf("declared but not in the registry (internal/schemagen/doc.go, actionLiterals): %v", miss)
	}

	// An action declared and not registered.
	const set = "actions: {authn.username.check: ["
	if !strings.Contains(src, set) {
		t.Fatalf("precondition: %q does not occur", set)
	}
	added := parseSchema(t, strings.Replace(src, set, "actions: {authn.example.check: [available], authn.username.check: [", 1))
	if miss := unregistered(added, actionLiterals); !slices.Equal(miss, []string{"krateo.audit.check_result: writer request, action authn.example.check"}) {
		t.Errorf("an unregistered declared action: reported %v", miss)
	}
	// The same literal registered under another writer.
	other := slices.Clone(actionLiterals)
	for i := range other {
		if other[i].Literal == "authn.username.check" {
			other[i].Writer = "controller"
		}
	}
	if miss := unregistered(s, other); len(miss) != 1 {
		t.Errorf("a literal registered under another writer: reported %v", miss)
	}
}

// audit#25: the registry's statement of which rules read krateo.action is
// derived from the schema, never typed: it names exactly the keys with a
// per-action set and their actions, and changes when the schema does.
func TestActionLiterals_ReadersAreDerived(t *testing.T) {
	raw, err := os.ReadFile("../../schema/v1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	s := parseSchema(t, src)
	want := "The only rule that reads it is a per-action closed set (above): `krateo.audit.check_result` on `authn.username.check`."
	if got := actionReaders(s); got != want {
		t.Errorf("readers:\n got %q\nwant %q", got, want)
	}
	if doc := actionLiteralsDoc(s); !strings.Contains(doc, want) {
		t.Errorf("the registry section does not carry the derived sentence:\n%s", doc)
	}

	// A second action on the same key: named, sorted.
	const set = "actions: {authn.username.check: ["
	two := parseSchema(t, strings.Replace(src, set, "actions: {authn.example.check: [available], authn.username.check: [", 1))
	if got, w := actionReaders(two), "The only rule that reads it is a per-action closed set (above): `krateo.audit.check_result` on `authn.example.check`, `authn.username.check`."; got != w {
		t.Errorf("two actions:\n got %q\nwant %q", got, w)
	}
	// No per-action set at all: no rule reads it.
	none := parseSchema(t, strings.Replace(src,
		"request: {level: optional, actions: {authn.username.check: [available, reserved, name_claimed, name_held_legacy, name_provisioned, name_bound, invalid]}}",
		"request: optional", 1))
	if got := actionReaders(none); got != "No rule reads it." {
		t.Errorf("no per-action set: %q", got)
	}
	if strings.Contains(actionLiteralsDoc(none), "krateo.audit.check_result` on") {
		t.Error("the registry still names check_result as a reader once the schema has no per-action set")
	}
}
