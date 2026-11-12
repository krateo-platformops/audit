package audit

import (
	"os"
	"slices"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
)

// v0.14.0: a username check's claimant results, the controller's
// kept_existing_value, and krateo.audit.authorization_key.

// The claimant's results (authn#146): on authn.username.check, a success,
// accepted like every other result; nowhere else.
func TestCheck_ClaimantResults(t *testing.T) {
	v := func(k string, r Reason) Violation { return Violation{Key: k, Reason: r} }
	if CheckResultNameClaimedByClaimant != "name_claimed_by_claimant" || CheckResultNameClaimedByAnother != "name_claimed_by_another" {
		t.Errorf("constants %q, %q", CheckResultNameClaimedByClaimant, CheckResultNameClaimedByAnother)
	}
	for _, r := range []string{CheckResultNameClaimedByClaimant, CheckResultNameClaimedByAnother} {
		rec := usernameCheckRecord(r)
		for _, tc := range []struct {
			name  string
			w     Writer
			attrs []attribute.KeyValue
			want  []Violation
		}{
			{"a completed check", WriterRequest, rec, nil},
			{"on a failure", WriterRequest, with(rec, attribute.String(KeyOutcome, OutcomeFailure), attribute.String(KeyLegacyOutcome, OutcomeFailure)),
				[]Violation{v(KeyCheckResult, ReasonUnexpected)}},
			{"on another action", WriterRequest, with(rec, attribute.String(KeyAction, "call")), []Violation{v(KeyCheckResult, ReasonNotForAction)}},
			{"as a denial reason", WriterRequest, with(deniedRecord(without(rec, KeyCheckResult)), attribute.String(KeyDenialReason, r)),
				[]Violation{v(KeyDenialReason, ReasonBadEnum)}},
			{"on a controller", WriterController, with(baseRecord(WriterController), attribute.String(KeyCheckResult, r)), []Violation{v(KeyCheckResult, ReasonNotForWriter)}},
		} {
			t.Run(r+": "+tc.name, func(t *testing.T) {
				if got := Check(tc.w, tc.attrs); !slices.Equal(got, tc.want) {
					t.Errorf("Check(%s):\n got %v\nwant %v", tc.w, got, tc.want)
				}
			})
		}
	}
	// The set, by hand, on authn.username.check only.
	k, _ := LookupKey(KeyCheckResult)
	set := k.Writers[WriterRequest].ActionValues[usernameCheck]
	for _, r := range []string{"name_claimed", "name_claimed_by_claimant", "name_claimed_by_another"} {
		if !slices.Contains(set, r) {
			t.Errorf("%s is not in %s's set %v", r, usernameCheck, set)
		}
	}
}

// keptRecord is a controller's record of an update it declined: a credential
// Secret already holds the authorization key with another value (authn#147's
// backfill), so nothing was sent.
func keptRecord(key string) []attribute.KeyValue {
	return with(deniedRecord(without(baseRecord(WriterController), KeyServerAddress)),
		attribute.String(KeyAction, "authn.identity.inconsistent"), attribute.String(KeyVerb, "update"),
		attribute.String(KeyNamespace, "krateo-system"),
		attribute.String(KeyObjectAPIVersion, "v1"), attribute.String(KeyLegacyResourceVersion, "v1"),
		attribute.String(KeyObjectResource, "secrets"), attribute.String(KeyLegacyResourceResource, "secrets"),
		attribute.String(KeyObjectName, "example-user-clientconfig"), attribute.String(KeyLegacyResourceName, "example-user-clientconfig"),
		attribute.Bool(KeyPreview, false),
		attribute.String(KeyDenialReason, DenialReasonKeptExistingValue),
		attribute.String(KeyAuthorizationKey, key))
}

// kept_existing_value and authorization_key, both ways: the key exactly when
// the reason, its value one of the declared <kind>:<key>, the controller's
// only, and never beside a status code.
func TestCheck_KeptExistingValue(t *testing.T) {
	v := func(k string, r Reason) Violation { return Violation{Key: k, Reason: r} }
	if DenialReasonKeptExistingValue != "kept_existing_value" {
		t.Errorf("DenialReasonKeptExistingValue = %q", DenialReasonKeptExistingValue)
	}
	rec := keptRecord("annotation:authn.krateo.io/username")
	for _, tc := range []struct {
		name  string
		w     Writer
		attrs []attribute.KeyValue
		want  []Violation
	}{
		{"a kept annotation", WriterController, rec, nil},
		{"a kept label", WriterController, keptRecord("label:authn.krateo.io/principal"), nil},
		{"the reason without the key", WriterController, without(rec, KeyAuthorizationKey), []Violation{v(KeyAuthorizationKey, ReasonMissing)}},
		{"the key without the reason", WriterController, without(rec, KeyDenialReason), []Violation{v(KeyAuthorizationKey, ReasonUnexpected)}},
		{"the key beside another reason", WriterController, with(rec, attribute.String(KeyDenialReason, DenialReasonKeptResourcePolicy)),
			[]Violation{v(KeyAuthorizationKey, ReasonUnexpected)}},
		{"a success naming a key", WriterController,
			with(without(rec, KeyDenialReason), attribute.String(KeyOutcome, OutcomeSuccess), attribute.String(KeyLegacyOutcome, OutcomeSuccess)),
			[]Violation{v(KeyAuthorizationKey, ReasonUnexpected)}},
		{"an undeclared key", WriterController, keptRecord("annotation:example.com/note"), []Violation{v(KeyAuthorizationKey, ReasonBadEnum)}},
		{"a declared annotation as a label", WriterController, keptRecord("label:authn.krateo.io/username"), []Violation{v(KeyAuthorizationKey, ReasonBadEnum)}},
		{"the bare key, no kind", WriterController, keptRecord("authn.krateo.io/username"), []Violation{v(KeyAuthorizationKey, ReasonBadEnum)}},
		{"a value, not a key", WriterController, keptRecord("example-user"), []Violation{v(KeyAuthorizationKey, ReasonBadEnum)}},
		{"with a status code", WriterController, with(rec, attribute.Int(KeyHTTPStatusCode, 409)), []Violation{v(KeyHTTPStatusCode, ReasonUnexpected)}},
		{"on a request record", WriterRequest, with(deniedRecord(baseRecord(WriterRequest)), attribute.String(KeyDenialReason, DenialReasonKeptExistingValue)),
			[]Violation{v(KeyDenialReason, ReasonBadEnum)}},
		{"the key on a request record", WriterRequest, with(baseRecord(WriterRequest), attribute.String(KeyAuthorizationKey, "annotation:authn.krateo.io/username")),
			[]Violation{v(KeyAuthorizationKey, ReasonNotForWriter), v(KeyAuthorizationKey, ReasonUnexpected)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Check(tc.w, tc.attrs); !slices.Equal(got, tc.want) {
				t.Errorf("Check(%s):\n got %v\nwant %v", tc.w, got, tc.want)
			}
		})
	}
	if !Holds(CondKeptExistingValue, rec) || Holds(CondKeptExistingValue, without(rec, KeyDenialReason)) ||
		Holds(CondKeptExistingValue, with(rec, attribute.String(KeyDenialReason, DenialReasonKeptResourcePolicy))) {
		t.Error("condition kept_existing_value does not hold exactly on the reason")
	}
}

// The authorization key's closed set is generated from
// authorization_metadata, <kind>:<key> in schema order: by hand, and as the
// two declared lists derive it.
func TestAuthorizationKey_SetIsTheDeclaredMetadata(t *testing.T) {
	want := []string{"annotation:authn.krateo.io/strategy", "annotation:authn.krateo.io/groups", "annotation:authn.krateo.io/username",
		"label:authn.krateo.io/principal", "label:authn.krateo.io/username-label"}
	k, ok := LookupKey(KeyAuthorizationKey)
	if !ok {
		t.Fatal("no krateo.audit.authorization_key")
	}
	if !slices.Equal(k.Values, want) {
		t.Errorf("values %v, want %v", k.Values, want)
	}
	var derived []string
	for _, a := range AuthorizationAnnotations() {
		derived = append(derived, "annotation:"+a)
	}
	for _, l := range AuthorizationLabels() {
		derived = append(derived, "label:"+l)
	}
	if !slices.Equal(k.Values, derived) {
		t.Errorf("values %v, the declared lists say %v", k.Values, derived)
	}
	if k.OnlyWhen != CondKeptExistingValue || k.Type != TypeString || k.Identity {
		t.Errorf("authorization_key: %+v", k)
	}
	for _, w := range Writers() {
		r := k.Writers[w]
		if w == WriterController {
			if r.Level != LevelConditional || r.Check != CondKeptExistingValue {
				t.Errorf("controller: %+v, want conditional, checked on kept_existing_value", r)
			}
		} else if r.Level != LevelNotApplicable {
			t.Errorf("%s: %v, want not applicable", w, r.Level)
		}
	}
	d, _ := LookupKey(KeyDenialReason)
	if !slices.Contains(d.Writers[WriterController].Values, "kept_existing_value") || slices.Contains(d.Writers[WriterRequest].Values, "kept_existing_value") {
		t.Error("kept_existing_value: the controller's value only")
	}
}

// AuthorizationKeyValue spells a declared key as the record writes it, and
// refuses an undeclared one or one of the other kind.
func TestAuthorizationKeyValue(t *testing.T) {
	for _, tc := range []struct {
		kind, key, want string
		ok              bool
	}{
		{MetadataKindAnnotation, "authn.krateo.io/username", "annotation:authn.krateo.io/username", true},
		{MetadataKindLabel, "authn.krateo.io/username-label", "label:authn.krateo.io/username-label", true},
		{MetadataKindLabel, "authn.krateo.io/username", "", false},
		{MetadataKindAnnotation, "authn.krateo.io/principal", "", false},
		{MetadataKindAnnotation, "example.com/note", "", false},
		{"tag", "authn.krateo.io/username", "", false},
	} {
		if got, ok := AuthorizationKeyValue(tc.kind, tc.key); got != tc.want || ok != tc.ok {
			t.Errorf("AuthorizationKeyValue(%q, %q) = %q, %v; want %q, %v", tc.kind, tc.key, got, ok, tc.want, tc.ok)
		}
	}
	k, _ := LookupKey(KeyAuthorizationKey)
	for _, want := range k.Values {
		kind, key, _ := strings.Cut(want, ":")
		if got, ok := AuthorizationKeyValue(kind, key); !ok || got != want {
			t.Errorf("AuthorizationKeyValue(%q, %q) = %q, %v; want %q", kind, key, got, ok, want)
		}
	}
}

// oasgen-provider's population (v0.14.0, oasgen-provider#543) is the
// controller's, and every scope is a module path plus /audit, bar
// rest-dynamic-controller's bare one, the documented historical exception.
func TestPopulations_OasgenProviderAndModulePathScopes(t *testing.T) {
	scopes := map[string]Population{}
	for _, p := range Populations() {
		scopes[p.Scope] = p
	}
	p, ok := scopes["github.com/krateo-platformops/oasgen-provider/audit"]
	if !ok || p.Writer != WriterController {
		t.Errorf("oasgen-provider: %+v, %v; want a controller population", p, ok)
	}
	for _, action := range []string{"rbac.apply", "rbac.delete", "admissionpolicy.apply"} {
		if !strings.Contains(p.Who, action) {
			t.Errorf("oasgen-provider's who does not name %s: %q", action, p.Who)
		}
	}
	const bare = "rest-dynamic-controller/audit"
	if _, ok := scopes[bare]; !ok {
		t.Errorf("no population %s", bare)
	}
	doc, err := os.ReadFile("docs/schema.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(doc), "rest-dynamic-controller's bare scope, with no module path, is a historical exception") {
		t.Errorf("docs/schema.md does not call %s a historical exception", bare)
	}
	for scope := range scopes {
		if scope != bare && !strings.HasPrefix(scope, "github.com/krateo-platformops/") {
			t.Errorf("%s: a new scope is a module path (github.com/krateo-platformops/<module>/audit)", scope)
		}
	}
}

// coverage.md's derived-name rule is scoped to refusals and username checks
// (v0.14.0): the section says a successful write names its real target, and
// cites the ownership proof authn makes before writing a legacy-named Secret.
func TestCoverage_DerivedNameRuleIsScopedToRefusalsAndChecks(t *testing.T) {
	raw, err := os.ReadFile("docs/coverage.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	start := strings.Index(doc, "## Naming a derived credential Secret\n")
	if start < 0 {
		t.Fatal("no section \"Naming a derived credential Secret\"")
	}
	section := doc[start:]
	if end := strings.Index(section[3:], "\n## "); end >= 0 {
		section = section[:end+3]
	}
	flat := strings.Join(strings.Fields(section), " ")
	for _, want := range []string{
		"a **refusal**",
		"a **username check**",
		"It is not for a successful write: a write names its real target",
		"`endpoints.OwnsSecret`",
		"On a refusal or a username check:",
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("the section does not say %q", want)
		}
	}
	if strings.Contains(flat, "Every writer that names a credential Secret derived from a username") {
		t.Error("the section still states the rule for every writer, writes included")
	}
}

// Emit writes the kept key, one record per conflicting key, and each record
// passes Check; no value is written.
func TestEmit_KeptExistingValue(t *testing.T) {
	for _, conflict := range [][2]string{{MetadataKindAnnotation, "authn.krateo.io/username"}, {MetadataKindLabel, "authn.krateo.io/principal"}, {MetadataKindLabel, "authn.krateo.io/username-label"}} {
		key, ok := AuthorizationKeyValue(conflict[0], conflict[1])
		if !ok {
			t.Fatalf("%v is not declared", conflict)
		}
		e, rec := newEmitter(t, WithWriter(WriterController), WithActor("system:serviceaccount:krateo-system:authn", ClassController))
		e.Emit(spanCtx(t), Event{Action: "authn.identity.inconsistent", Verb: "update", HTTPMethod: "PUT",
			Outcome: OutcomeDenied, DenialReason: DenialReasonKeptExistingValue, AuthorizationKey: key, Preview: PreviewFalse,
			Namespace: "krateo-system", Version: "v1", Resource: "secrets", Kind: "Secret", ObjectName: "example-user-clientconfig"})
		got := attrs(only(t, rec))
		if got[KeyAuthorizationKey] != attribute.StringValue(key) {
			t.Errorf("authorization_key = %v, want %s", got[KeyAuthorizationKey].Emit(), key)
		}
		if _, here := got[KeyHTTPStatusCode]; here {
			t.Error("a status code on a declined write")
		}
		if vs := Check(WriterController, kvs(got)); len(vs) > 0 {
			t.Errorf("%s: %v", key, vs)
		}
	}
}
