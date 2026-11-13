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
		// The ownership proof is authn's default path (authn#148, 0.45.0),
		// at its two sites.
		"[authn#148]",
		"`dc732f89`",
		"`guard.go:158-166`",
		"`storage/storage.go:194-216`",
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("the section does not say %q", want)
		}
	}
	if strings.Contains(flat, "Every writer that names a credential Secret derived from a username") {
		t.Error("the section still states the rule for every writer, writes included")
	}
	if strings.Contains(flat, "exact naming on") || strings.Contains(flat, "exactUsernames") {
		t.Error("the section still limits the ownership proof to exact naming")
	}
}

// core-provider's rows (v0.14.0, core-provider@b1f9b5f): every row that emits
// names the core-provider scope, cites b1f9b5f and says it is unreleased; the
// seven literals are covered; and "audited" is claimed only by the row whose
// conformance a core-provider test proves (audit_envtest_test.go:137). Every
// other emitting row is "audited, conformance not yet proven".
func TestCoverage_CoreProviderRows(t *testing.T) {
	raw, err := os.ReadFile("docs/coverage.md")
	if err != nil {
		t.Fatal(err)
	}
	const scope = "github.com/krateo-platformops/core-provider/audit"
	actions := map[string]bool{}
	audited := 0
	for _, r := range coverageRows(t, string(raw)) {
		if r.component != "core-provider" || r.scope == "" {
			continue
		}
		if r.scope != scope {
			t.Errorf("docs/coverage.md:%d: scope %s, want %s", r.line, r.scope, scope)
		}
		if !strings.Contains(r.path, "b1f9b5f") || !strings.Contains(r.owner, "unreleased") {
			t.Errorf("docs/coverage.md:%d: the row does not cite b1f9b5f or say it is unreleased", r.line)
		}
		switch r.status {
		case "audited":
			audited++
			if !strings.Contains(r.path, "audit_envtest_test.go:137") {
				t.Errorf("docs/coverage.md:%d: audited without the test that proves it", r.line)
			}
		case coverageUnproven:
		default:
			t.Errorf("docs/coverage.md:%d: status %q", r.line, r.status)
		}
		for _, a := range strings.Split(r.action, ", ") {
			actions[strings.Trim(a, "`")] = true
		}
	}
	for _, a := range []string{"rbac.apply", "rbac.delete", "secret.apply", "authn.mapping.apply", "composition.mirror", "composition.hub.delete", "composition.migrate"} {
		if !actions[a] {
			t.Errorf("no core-provider row carries %s", a)
		}
	}
	if actions["secret.delete"] {
		t.Error("a core-provider row carries secret.delete, which has no emit site")
	}
	if audited != 1 {
		t.Errorf("%d core-provider rows are audited, want 1 (the composition RBAC set)", audited)
	}
	// The status is a closed value: an unproven path names its scope like any
	// audited one, and a status that assumes conformance is refused.
	row := coverageRow{line: 1, table: WriterController, component: "core-provider", path: "a write", writer: string(WriterController),
		identity: "its own ServiceAccount", status: coverageUnproven, owner: "[core-provider#1]", action: "`rbac.apply`"}
	defined := map[string]bool{"core-provider#1": true}
	if p := coverageProblems([]coverageRow{row}, defined); len(p) != 1 || !strings.Contains(p[0], "an audited path names no scope") {
		t.Errorf("an unproven row with no scope: %v, want refused for its scope", p)
	}
	row.scope = "github.com/krateo-platformops/core-provider/audit"
	if p := coverageProblems([]coverageRow{row}, defined); len(p) != 0 {
		t.Errorf("an unproven row with its scope: %v", p)
	}
	row.status = "audited, conformance assumed"
	if p := coverageProblems([]coverageRow{row}, defined); len(p) != 1 || !strings.Contains(p[0], "is not audited") {
		t.Errorf("a status that assumes conformance: %v, want refused", p)
	}
}

// The cdc's helm child-write row (core-provider#459, 2.13.86) is audited but
// non-conformant for authorization-metadata-only changes, which it counts as
// metadata_only and does not record (core-provider#465). It is fixed in
// core-provider#467 (a644558), unreleased, so the row stays non-conformant
// until a released cdc carries the fix.
func TestCoverage_CdcHelmWriteRow(t *testing.T) {
	raw, err := os.ReadFile("docs/coverage.md")
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, r := range coverageRows(t, string(raw)) {
		if r.component != "cdc" || !strings.HasPrefix(r.path, "helm install or upgrade") {
			continue
		}
		found++
		if !strings.HasPrefix(r.status, "audited, non-conformant for authorization-metadata-only changes: ") ||
			!strings.Contains(r.status, "metadata_only") || !strings.Contains(r.status, "[core-provider#465]") ||
			!strings.Contains(r.status, "is fixed in [core-provider#467] (`a644558`), unreleased; ships in 2.13.87") ||
			!strings.Contains(r.status, "Non-conformant until a released cdc carries it") {
			t.Errorf("docs/coverage.md:%d: status %q", r.line, r.status)
		}
		if strings.Contains(r.status, "not yet merged") || strings.Contains(r.owner, "not yet merged") {
			t.Errorf("docs/coverage.md:%d: still says core-provider#467 is not yet merged", r.line)
		}
		if r.scope != "github.com/krateo-platformops/composition-dynamic-controller/audit" {
			t.Errorf("docs/coverage.md:%d: scope %q", r.line, r.scope)
		}
	}
	if found != 1 {
		t.Errorf("%d cdc helm-write rows, want 1", found)
	}
}

// The cdc's other rows, re-derived at core-provider@b1f9b5f: each names the
// cdc scope and cites b1f9b5f; only the uninstall, whose real records the
// integration suite checks (composition_test.go:1811), is "audited"; the
// prune and the kept deletion are "audited, conformance not yet proven". No
// row is left "not yet re-derived".
func TestCoverage_CdcRowsRederived(t *testing.T) {
	raw, err := os.ReadFile("docs/coverage.md")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(strings.Fields(string(raw)), " "), "not yet re-derived") {
		t.Error("docs/coverage.md still says a row is not yet re-derived")
	}
	want := map[string]string{
		"helm prune of a child":           coverageUnproven,
		"helm uninstall of a Composition": "audited",
		"a kept deletion":                 coverageUnproven,
	}
	seen := map[string]bool{}
	for _, r := range coverageRows(t, string(raw)) {
		if r.component != "cdc" {
			continue
		}
		if r.scope != "github.com/krateo-platformops/composition-dynamic-controller/audit" || !strings.Contains(r.path, "b1f9b5f") {
			t.Errorf("docs/coverage.md:%d: scope %q, or no b1f9b5f citation", r.line, r.scope)
		}
		for prefix, status := range want {
			if !strings.HasPrefix(r.path, prefix) {
				continue
			}
			seen[prefix] = true
			if r.status != status {
				t.Errorf("docs/coverage.md:%d: %s: status %q, want %q", r.line, prefix, r.status, status)
			}
			if status == "audited" && !strings.Contains(r.path, "composition_test.go:1811") {
				t.Errorf("docs/coverage.md:%d: audited without the test that proves it", r.line)
			}
		}
	}
	for prefix := range want {
		if !seen[prefix] {
			t.Errorf("no cdc row %q", prefix)
		}
	}
}

// The kept_existing_value text after authn's review (v0.14.0): authn#147 is
// cited pending merge with no commit or line pin, the backfill is said to
// compare those keys only with exact naming on, the usage example sends no
// method, and the authn controller population names the backfill.
func TestKeptExistingValue_TextMatchesTheEmitter(t *testing.T) {
	read := func(p string) string {
		t.Helper()
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(strings.Fields(string(b)), " ")
	}
	yaml := read("schema/v1.yaml")
	start := strings.Index(yaml, "# kept_existing_value (v0.14.0)")
	end := strings.Index(yaml, "controller: {level: optional, values: [kept_resource_policy, kept_existing_value]}")
	if start < 0 || end < start {
		t.Fatal("no kept_existing_value comment in schema/v1.yaml")
	}
	comment := yaml[start:end]
	usage := read("docs/usage.md")
	ustart := strings.Index(usage, "**A kept value.**")
	uend := strings.Index(usage, "**Naming a derived credential Secret**")
	if ustart < 0 || uend < ustart {
		t.Fatal("no \"A kept value\" bullet in docs/usage.md")
	}
	bullet := usage[ustart:uend]
	for name, text := range map[string]string{"schema/v1.yaml": comment, "docs/usage.md": bullet} {
		if !strings.Contains(text, "authn#147, pending merge") || strings.Contains(text, "fdd4b61f") || strings.Contains(text, "backfill.go:") {
			t.Errorf("%s: authn#147 is not cited pending merge without pins", name)
		}
		if !strings.Contains(text, "exactUsernames.enabled") || !strings.Contains(text, "off by default") {
			t.Errorf("%s: does not say the backfill compares the keys only with exact naming on", name)
		}
	}
	// coverage.md's backfill row: authn#147 (since 98e4c9e) logs each
	// differing key and records nothing; the record it once wrote on audit
	// v0.11.0 is gone, and no doc may say otherwise.
	cov := read("docs/coverage.md")
	for _, stale := range []string{"records it today as", "one denied record per Secret"} {
		for _, p := range []string{"docs/coverage.md", "docs/usage.md", "docs/log.md", "schema/v1.yaml", "docs/schema.md"} {
			if strings.Contains(read(p), stale) {
				t.Errorf("%s still says %q: authn#147 no longer writes that record", p, stale)
			}
		}
	}
	if !strings.Contains(cov, "logs each differing key (key and uid, never a value) and records nothing until it adopts v0.14.0's kept_existing_value") {
		t.Error("docs/coverage.md: the backfill row does not say what authn#147 does today")
	}
	if strings.Contains(bullet, "HTTPMethod:") {
		t.Error("docs/usage.md: the kept-value example sends a method, but nothing was sent")
	}
	for _, p := range Populations() {
		if p.Scope == "github.com/krateo-platformops/authn/audit/controller" && !strings.Contains(p.Who, "the startup identity backfill") {
			t.Errorf("authn's controller population does not name the startup identity backfill: %q", p.Who)
		}
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
		e.Emit(spanCtx(t), Event{Action: "authn.identity.inconsistent", Verb: "update",
			Outcome: OutcomeDenied, DenialReason: DenialReasonKeptExistingValue, AuthorizationKey: key, Preview: PreviewFalse,
			Namespace: "krateo-system", Version: "v1", Resource: "secrets", Kind: "Secret", ObjectName: "example-user-clientconfig"})
		got := attrs(only(t, rec))
		if got[KeyAuthorizationKey] != attribute.StringValue(key) {
			t.Errorf("authorization_key = %v, want %s", got[KeyAuthorizationKey].Emit(), key)
		}
		if _, here := got[KeyHTTPStatusCode]; here {
			t.Error("a status code on a declined write")
		}
		if _, here := got[KeyHTTPMethod]; here {
			t.Error("a method on a declined write: nothing was sent")
		}
		if vs := Check(WriterController, kvs(got)); len(vs) > 0 {
			t.Errorf("%s: %v", key, vs)
		}
	}
}
