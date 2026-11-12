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
		"request: {level: optional, actions: {authn.username.check: [available, reserved, name_claimed, name_held_legacy, name_provisioned, name_bound, invalid, name_claimed_by_claimant, name_claimed_by_another]}}",
		"request: optional", 1))
	if got := actionReaders(none); got != "No rule reads it." {
		t.Errorf("no per-action set: %q", got)
	}
	if strings.Contains(actionLiteralsDoc(none), "krateo.audit.check_result` on") {
		t.Error("the registry still names check_result as a reader once the schema has no per-action set")
	}
}

// core-provider's literals (v0.14.0, core-provider@b1f9b5f), by hand: each
// registered under the controller, citing that commit, and shown in the
// registry section. secret.delete is not registered: it has no emit site.
func TestActionLiterals_CoreProvider(t *testing.T) {
	raw, err := os.ReadFile("../../schema/v1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	doc := actionLiteralsDoc(parseSchema(t, string(raw)))
	byLiteral := map[string]actionLiteral{}
	for _, l := range actionLiterals {
		byLiteral[l.Literal] = l
	}
	for _, lit := range []string{"rbac.apply", "rbac.delete", "secret.apply", "authn.mapping.apply", "composition.mirror", "composition.hub.delete", "composition.migrate"} {
		l, ok := byLiteral[lit]
		if !ok || l.Writer != "controller" {
			t.Errorf("%s: %+v, want registered under the controller", lit, l)
			continue
		}
		if !strings.Contains(l.Action, "core-provider@b1f9b5f") {
			t.Errorf("%s does not cite core-provider@b1f9b5f: %q", lit, l.Action)
		}
		if !strings.Contains(doc, "| `controller` | `"+lit+"` | ") {
			t.Errorf("the registry section does not show %s", lit)
		}
	}
	if _, ok := byLiteral["secret.delete"]; ok {
		t.Error("secret.delete is registered, but no core-provider site emits it")
	}
}

// The registry is well formed: each row names a writer class of the schema
// and a literal of krateo.action's form, once per writer. cdc's helm
// literals (core-provider#423) are registered under the controller, written
// out by hand so a dropped row is caught.
func TestActionLiterals_RegistryIsWellFormed(t *testing.T) {
	raw, err := os.ReadFile("../../schema/v1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	s := parseSchema(t, string(raw))
	writers := map[string]bool{}
	for _, w := range s.Writers {
		writers[w.ID] = true
	}
	seen := map[string]bool{}
	for _, l := range actionLiterals {
		if !writers[l.Writer] || !actionName.MatchString(l.Literal) || l.Action == "" {
			t.Errorf("row %+v: an unknown writer, a malformed literal or no meaning", l)
		}
		if seen[l.Writer+" "+l.Literal] {
			t.Errorf("row %+v: registered twice", l)
		}
		seen[l.Writer+" "+l.Literal] = true
	}
	for _, lit := range []string{"helm.install", "helm.upgrade", "helm.reconcile", "helm.rollback", "helm.uninstall"} {
		if !seen["controller "+lit] {
			t.Errorf("%s is not registered under the controller", lit)
		}
	}
	doc := actionLiteralsDoc(s)
	if !strings.Contains(doc, "| `controller` | `helm.rollback` | ") {
		t.Errorf("the registry section does not show helm.rollback:\n%s", doc)
	}
}
