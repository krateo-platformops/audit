package audit

import (
	"slices"
	"testing"

	"go.opentelemetry.io/otel/attribute"
)

// principal stands in for plumbing's jwtutil.Principal (a named string type,
// v1.34.0 principal.go), so this arm proves ParseClaim takes it without a
// conversion and without importing plumbing.
type jwtPrincipal string

func TestParseClaim(t *testing.T) {
	for in, want := range map[jwtPrincipal]Class{
		"human": ClassHuman, "agent": ClassAgent, "controller": ClassController, "service": ClassService,
	} {
		got, ok := ParseClaim(in)
		if !ok || got != want {
			t.Errorf("ParseClaim(%q) = %q, %v; want %q, true", in, got, ok, want)
		}
	}
	// "" is a token from before authn set the claim, or an actor with no kind.
	// Wrong case and unknown values read "" in jwtutil too. None of them
	// becomes a class, least of all human.
	for _, in := range []jwtPrincipal{"", "Human", "HUMAN", "robot", " human"} {
		if got, ok := ParseClaim(in); ok || got != "" {
			t.Errorf("ParseClaim(%q) = %q, %v; want \"\", false", in, got, ok)
		}
	}
	if got, ok := ParseClaim("agent"); !ok || got != ClassAgent { // a plain string works too
		t.Errorf("ParseClaim(string) = %q, %v", got, ok)
	}
}

func TestWithLegacyKeys(t *testing.T) {
	in := make([]attribute.KeyValue, 0, 8) // spare capacity: the caller's array must not be written
	in = append(in,
		attribute.String(KeyOutcome, "success"),
		attribute.String(KeyObjectResource, "pods"),
		attribute.String(KeyLegacyResourceResource, "already"),
		attribute.String(KeyVerb, "get"),
	)
	out := WithLegacyKeys(in)
	got := map[string]string{}
	for _, kv := range out {
		got[string(kv.Key)] = kv.Value.AsString()
	}
	if got[KeyLegacyOutcome] != "success" {
		t.Errorf("outcome not dual-written: %v", got)
	}
	if got[KeyLegacyResourceResource] != "already" {
		t.Errorf("a v0.3 key the caller set was overwritten: %v", got)
	}
	if len(out) != 5 {
		t.Errorf("len = %d, want 5 (one twin added): %v", len(out), out)
	}
	if spare := in[:cap(in)][len(in)]; spare.Key != "" {
		t.Errorf("WithLegacyKeys wrote into the caller's array: %v", spare)
	}
	if !slices.Equal(in, out[:len(in)]) {
		t.Errorf("the caller's attributes changed")
	}
}
