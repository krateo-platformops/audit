package audit

import (
	"os"
	"slices"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
)

// The declared authorization labels, by hand (v0.13.0): authn will stamp both
// on every session Secret (planned, per authn#144), and authorization reads
// them.
func TestAuthorizationLabels(t *testing.T) {
	if got, want := AuthorizationLabels(), []string{"authn.krateo.io/principal", "authn.krateo.io/username-label"}; !slices.Equal(got, want) {
		t.Errorf("AuthorizationLabels() = %v, want %v", got, want)
	}
	l := AuthorizationLabels()
	l[0] = "mutated"
	if AuthorizationLabels()[0] != "authn.krateo.io/principal" {
		t.Errorf("AuthorizationLabels shares the schema's list with its caller")
	}
	// The annotations: v0.12.0's two, then plumbing v1.58.0's
	// endpoints.UsernameAnnotation, which decides credential ownership.
	if got, want := AuthorizationAnnotations(), []string{"authn.krateo.io/strategy", "authn.krateo.io/groups", "authn.krateo.io/username"}; !slices.Equal(got, want) {
		t.Errorf("AuthorizationAnnotations() = %v, want %v", got, want)
	}
}

// c1's annotation key set, by hand: frozen at v0.12.0's two, whatever
// AuthorizationAnnotations declares, and a copy.
func TestContentFormC1Annotations_Frozen(t *testing.T) {
	want := []string{"authn.krateo.io/strategy", "authn.krateo.io/groups"}
	if got := ContentFormC1Annotations(); !slices.Equal(got, want) {
		t.Errorf("ContentFormC1Annotations() = %v, want %v", got, want)
	}
	c := ContentFormC1Annotations()
	c[0] = "mutated"
	if ContentFormC1Annotations()[0] != "authn.krateo.io/strategy" {
		t.Error("ContentFormC1Annotations shares c1's list with its caller")
	}
	doc, err := os.ReadFile("docs/schema.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(doc), "**c1's key set is frozen** (`audit.ContentFormC1Annotations()`): the two\nannotations v0.12.0 declared, `authn.krateo.io/strategy` and `authn.krateo.io/groups`,") {
		t.Error("docs/schema.md does not state c1's frozen key set")
	}
}

// Growing authorization_metadata never changes a c1 hash: an annotation the
// schema declares after v0.12.0 (authn.krateo.io/username, or any other added
// to the list) is content to a comparator, and invisible to c1.
func TestContentSHA256_C1IgnoresTheGrowingAuthorizationList(t *testing.T) {
	obj := func(annotations map[string]any) map[string]any {
		return map[string]any{"spec": map[string]any{"a": "1"}, "metadata": map[string]any{"name": "x", "annotations": annotations}}
	}
	hash := func(annotations map[string]any) string {
		t.Helper()
		h, err := ContentSHA256("example.krateo.io", "examples", "", obj(annotations))
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	const added = "example.krateo.io/added"
	before := map[string]string{}
	for _, k := range []string{"authn.krateo.io/username", added} {
		before[k] = hash(map[string]any{"authn.krateo.io/groups": "devs", k: "example-a"})
	}
	// Add an annotation to the declared list, as a later schema would.
	saved := schemaContentAnnotations
	schemaContentAnnotations = append(slices.Clone(saved), added)
	t.Cleanup(func() { schemaContentAnnotations = saved })
	if !slices.Contains(AuthorizationAnnotations(), added) {
		t.Fatal("precondition: the annotation was not added to the declared list")
	}
	for _, k := range []string{"authn.krateo.io/username", added} {
		if !slices.Contains(AuthorizationAnnotations(), k) {
			t.Fatalf("precondition: %s is not declared", k)
		}
		base := map[string]any{"authn.krateo.io/groups": "devs"}
		with := func(v any) map[string]any { m := map[string]any{"authn.krateo.io/groups": "devs"}; m[k] = v; return m }
		if got := hash(with("example-a")); got != before[k] {
			t.Errorf("%s: declaring the annotation changed the c1 hash: %s, was %s", k, got, before[k])
		}
		if hash(with("example-a")) != hash(with("example-b")) || hash(with("example-a")) != hash(base) {
			t.Errorf("%s: a declared annotation outside c1's frozen set changes the c1 hash", k)
		}
	}
	// c1's own keys still count.
	if hash(map[string]any{"authn.krateo.io/groups": "devs"}) == hash(map[string]any{"authn.krateo.io/groups": "ops"}) {
		t.Error("a changed authn.krateo.io/groups is not detected")
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

// rbac_not_allowed (v0.13.0): the writer's own RBAC evaluation refused a
// verified caller before any dial. First user: snowplow's DebugAuthz on POST
// /debug/shadow-parity (schema/v1.yaml cites the sites). An authority's 403
// is not it: that stays a failure carrying the authority's status code.
func TestCheck_RBACNotAllowed(t *testing.T) {
	v := func(k string, r Reason) Violation { return Violation{Key: k, Reason: r} }
	refused := with(deniedRecord(pathRecord()), attribute.String(KeyDenialReason, DenialReasonRbacNotAllowed))
	// The apiserver answering 403 to the object the writer dialled.
	apiserver403 := with(baseRecord(WriterRequest), attribute.Int(KeyHTTPStatusCode, 403),
		attribute.String(KeyOutcome, OutcomeFailure), attribute.String(KeyLegacyOutcome, OutcomeFailure))
	for _, tc := range []struct {
		name  string
		w     Writer
		attrs []attribute.KeyValue
		want  []Violation
	}{
		{"DebugAuthz refusing a path", WriterRequest, refused, nil},
		{"with the writer's own 403 as a status code", WriterRequest, with(refused, attribute.Int(KeyHTTPStatusCode, 403)),
			[]Violation{v(KeyHTTPStatusCode, ReasonUnexpected)}},
		{"an authority's 403: a failure with its code", WriterRequest, apiserver403, nil},
		{"an authority's 403 given the reason", WriterRequest, with(apiserver403, attribute.String(KeyDenialReason, DenialReasonRbacNotAllowed)),
			[]Violation{v(KeyDenialReason, ReasonUnexpected)}},
		{"on a controller", WriterController, with(deniedRecord(baseRecord(WriterController)), attribute.String(KeyDenialReason, DenialReasonRbacNotAllowed)),
			[]Violation{v(KeyDenialReason, ReasonBadEnum)}},
		{"on the gateway", WriterGateway, with(deniedRecord(baseRecord(WriterGateway)), attribute.String(KeyDenialReason, DenialReasonRbacNotAllowed)),
			[]Violation{v(KeyDenialReason, ReasonNotForWriter)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Check(tc.w, tc.attrs); !slices.Equal(got, tc.want) {
				t.Errorf("Check(%s):\n got %v\nwant %v", tc.w, got, tc.want)
			}
		})
	}

	// By hand: the value, the request writer's only.
	if DenialReasonRbacNotAllowed != "rbac_not_allowed" {
		t.Errorf("DenialReasonRbacNotAllowed = %q", DenialReasonRbacNotAllowed)
	}
	d, _ := LookupKey(KeyDenialReason)
	if !slices.Contains(d.Writers[WriterRequest].Values, "rbac_not_allowed") || slices.Contains(d.Writers[WriterController].Values, "rbac_not_allowed") {
		t.Error("rbac_not_allowed: the request writer's value only")
	}
}

// Emit writes DebugAuthz's refusal of POST /debug/shadow-parity as a denied
// path record with the reason and no status code; it passes Check.
func TestEmit_RBACNotAllowed(t *testing.T) {
	e, rec := newEmitter(t, WithWriter(WriterRequest))
	e.Emit(WithSessionIDForTest(t, spanCtx(t), "s1"), Event{UserName: "example-user", ActorClass: ClassHuman,
		Action: "debug.shadowParity", Verb: "post", HTTPMethod: "POST", Outcome: OutcomeDenied, DenialReason: DenialReasonRbacNotAllowed,
		URLPath: "/debug/shadow-parity", RequestURI: "/debug/shadow-parity", SourceIPs: []string{"192.0.2.10"}})
	got := attrs(only(t, rec))
	if got[KeyDenialReason] != attribute.StringValue("rbac_not_allowed") || got[KeyOutcome] != attribute.StringValue(OutcomeDenied) {
		t.Errorf("denial_reason = %v, outcome = %v", got[KeyDenialReason].Emit(), got[KeyOutcome].Emit())
	}
	if _, here := got[KeyHTTPStatusCode]; here {
		t.Errorf("a status code on the writer's own refusal")
	}
	if vs := Check(WriterRequest, kvs(got)); len(vs) > 0 {
		t.Errorf("rbac_not_allowed record: %v", vs)
	}
}
