package audittest_test

import (
	"reflect"
	"slices"
	"testing"

	"github.com/krateo-platformops/audit"
	"github.com/krateo-platformops/audit/audittest"
)

func casesByName(t *testing.T) map[string]audittest.ContentCase {
	t.Helper()
	out := map[string]audittest.ContentCase{}
	for _, c := range audittest.AuthorizationMetadataCases() {
		if _, dup := out[c.Name]; dup {
			t.Errorf("two cases named %q", c.Name)
		}
		if reflect.DeepEqual(c.Before, c.After) {
			t.Errorf("%s: before and after are the same object: the case tests nothing", c.Name)
		}
		out[c.Name] = c
	}
	return out
}

// The rule, by hand (v0.13.0): changing either authorization label, adding it
// or removing it is a content change; changing, adding or removing an
// undeclared label is not. The same for the annotations, and a declared key
// counts only as the kind it is declared as.
func TestAuthorizationMetadataCases_TheRuleByHand(t *testing.T) {
	cases := casesByName(t)
	want := map[string]bool{}
	for _, k := range []string{"authn.krateo.io/principal", "authn.krateo.io/username-label"} {
		for _, e := range []string{"changed", "added", "removed"} {
			want["a declared label "+k+" "+e] = true
			want["a declared label's key as annotation "+k+" "+e] = false
		}
	}
	for _, k := range []string{"authn.krateo.io/strategy", "authn.krateo.io/groups", "authn.krateo.io/username"} {
		for _, e := range []string{"changed", "added", "removed"} {
			want["a declared annotation "+k+" "+e] = true
			want["a declared annotation's key as label "+k+" "+e] = false
		}
	}
	for _, kind := range []string{"label", "annotation"} {
		for _, e := range []string{"changed", "added", "removed"} {
			want["an undeclared "+kind+" example.com/unrelated "+e] = false
		}
	}
	for name, changed := range want {
		c, ok := cases[name]
		if !ok {
			t.Errorf("no case %q", name)
			continue
		}
		if c.Changed != changed {
			t.Errorf("%s: Changed = %v, want %v", name, c.Changed, changed)
		}
	}
	if len(cases) != len(want) {
		t.Errorf("%d cases, want %d: a case the rule does not name", len(cases), len(want))
	}
}

// content is the AUDIT-4 rule as the docs state it, for these objects (whose
// desired state is spec): spec, plus the declared annotations as annotations
// and the declared labels as labels, compared by key and value.
func content(obj map[string]any) map[string]any {
	meta, _ := obj["metadata"].(map[string]any)
	kept := func(field string, keys []string) map[string]any {
		all, _ := meta[field].(map[string]any)
		out := map[string]any{}
		for _, k := range keys {
			if v, ok := all[k]; ok {
				out[k] = v
			}
		}
		return out
	}
	return map[string]any{
		"spec":        obj["spec"],
		"annotations": kept("annotations", audit.AuthorizationAnnotations()),
		"labels":      kept("labels", audit.AuthorizationLabels()),
	}
}

// c1Annotations is the object's annotations kept to form c1's FROZEN key set
// (audit.ContentFormC1Annotations), not to the declared list.
func c1Annotations(obj map[string]any) map[string]any {
	meta, _ := obj["metadata"].(map[string]any)
	all, _ := meta["annotations"].(map[string]any)
	out := map[string]any{}
	for _, k := range audit.ContentFormC1Annotations() {
		if v, ok := all[k]; ok {
			out[k] = v
		}
	}
	return out
}

// Every case's verdict is the stated rule's, and the content hash, form c1,
// differs exactly when c1's frozen annotations differ, and counts no label (a
// form is fixed). A declared annotation outside the frozen set
// (authn.krateo.io/username) changes the comparator's verdict and not c1.
func TestAuthorizationMetadataCases_AgreeWithTheRuleAndTheHash(t *testing.T) {
	hash := func(obj map[string]any) string {
		t.Helper()
		h, err := audit.ContentSHA256("example.krateo.io", "examples", "", obj)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	var changed, unchanged, hashed, outsideC1 int
	for _, c := range audittest.AuthorizationMetadataCases() {
		if got := !reflect.DeepEqual(content(c.Before), content(c.After)); got != c.Changed {
			t.Errorf("%s: the rule says changed=%v, the case %v", c.Name, got, c.Changed)
		}
		hashDiffers := hash(c.Before) != hash(c.After)
		c1Differ := !reflect.DeepEqual(c1Annotations(c.Before), c1Annotations(c.After))
		if hashDiffers != c1Differ {
			t.Errorf("%s: c1 differs=%v, c1's frozen annotations differ=%v", c.Name, hashDiffers, c1Differ)
		}
		if c.Changed {
			changed++
		} else {
			unchanged++
		}
		if hashDiffers {
			hashed++
		}
		if c.Changed && !hashDiffers {
			outsideC1++
		}
	}
	if changed == 0 || unchanged == 0 {
		t.Errorf("changed %d, unchanged %d: the cases need both", changed, unchanged)
	}
	// Both arms of the c1 assertion are exercised: a case c1 sees, and a
	// content change c1 does not (a declared label, or a declared annotation
	// outside the frozen set).
	if hashed == 0 || outsideC1 == 0 {
		t.Errorf("c1 differs in %d cases, a content change c1 doesn't see in %d: the cases need both", hashed, outsideC1)
	}
	for _, e := range []string{"changed", "added", "removed"} {
		name := "a declared annotation authn.krateo.io/username " + e
		c, ok := casesByName(t)[name]
		if !ok {
			t.Fatalf("no case %q", name)
		}
		if !c.Changed || hash(c.Before) != hash(c.After) {
			t.Errorf("%s: changed=%v, c1 differs=%v; want a content change c1 does not hash", name, c.Changed, hash(c.Before) != hash(c.After))
		}
	}
}

// Each call returns fresh objects: a comparator that edits one (normalising
// it, as an unstructured wrapper may) changes no later case.
func TestAuthorizationMetadataCases_FreshCopies(t *testing.T) {
	first := audittest.AuthorizationMetadataCases()
	first[0].Before["spec"] = "mutated"
	first[0].After["metadata"].(map[string]any)["name"] = "mutated"
	if reflect.DeepEqual(first[0].Before, first[0].After) {
		t.Fatal("precondition")
	}
	again := audittest.AuthorizationMetadataCases()
	if again[0].Before["spec"] == "mutated" || again[0].After["metadata"].(map[string]any)["name"] == "mutated" {
		t.Error("AuthorizationMetadataCases shares its objects between calls")
	}
	if !slices.ContainsFunc(again, func(c audittest.ContentCase) bool { return c.Changed }) {
		t.Error("no case is a content change")
	}
}
