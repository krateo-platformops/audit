package audit

import (
	"slices"
	"testing"
)

// The declared authorization labels, by hand (v0.13.0): authn stamps both on
// every session Secret, and authorization reads them.
func TestAuthorizationLabels(t *testing.T) {
	if got, want := AuthorizationLabels(), []string{"authn.krateo.io/principal", "authn.krateo.io/username-label"}; !slices.Equal(got, want) {
		t.Errorf("AuthorizationLabels() = %v, want %v", got, want)
	}
	l := AuthorizationLabels()
	l[0] = "mutated"
	if AuthorizationLabels()[0] != "authn.krateo.io/principal" {
		t.Errorf("AuthorizationLabels shares the schema's list with its caller")
	}
	// The annotations are unchanged by the move to one list of both kinds.
	if got, want := AuthorizationAnnotations(), []string{"authn.krateo.io/strategy", "authn.krateo.io/groups"}; !slices.Equal(got, want) {
		t.Errorf("AuthorizationAnnotations() = %v, want %v", got, want)
	}
}

// Form c1 counts no label, a declared one included: a form is fixed. Two
// objects that differ only in a declared label hash the same.
func TestContentSHA256_CountsNoAuthorizationLabel(t *testing.T) {
	obj := func(labels map[string]any) map[string]any {
		return map[string]any{"spec": map[string]any{"a": "1"}, "metadata": map[string]any{"name": "x", "labels": labels}}
	}
	for _, k := range AuthorizationLabels() {
		a, err := ContentSHA256("example.krateo.io", "examples", "", obj(map[string]any{k: "example-a"}))
		if err != nil {
			t.Fatal(err)
		}
		b, err := ContentSHA256("example.krateo.io", "examples", "", obj(nil))
		if err != nil {
			t.Fatal(err)
		}
		if a != b {
			t.Errorf("c1 counts the label %s: the form changed", k)
		}
	}
}
