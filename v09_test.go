package audit

import (
	"slices"
	"testing"

	"go.opentelemetry.io/otel/attribute"
)

// v0.9.0 (audit#23): krateo.audit.check_result, a closed set per action. Its
// first action is authn.username.check, authn's POST /usernames/check.
var usernameCheckResults = []string{
	CheckResultAvailable, CheckResultReserved, CheckResultNameClaimed, CheckResultNameHeldLegacy,
	CheckResultNameProvisioned, CheckResultNameBound, CheckResultInvalid,
	CheckResultNameClaimedByClaimant, CheckResultNameClaimedByAnother, // v0.14.0 (authn#146)
}

const usernameCheck = "authn.username.check"

// usernameCheckRecord is authn's record of a completed username check with
// result r: a request row, verb get, targeting the clientconfig Secret the
// name guard protects, outcome success. A read, so no dry_run. Its method is
// GET by the schema's rule for http.request.method, derived from the verb of
// the authority request the writer sent (get is GET), never the inbound
// POST /usernames/check (authn's methodOf, auditlog.go at authn 0fa999e0).
func usernameCheckRecord(r string) []attribute.KeyValue {
	base := with(without(onObject(baseRecord(WriterRequest), "", "secrets", ""), KeyDryRun, KeyHTTPStatusCode),
		attribute.String(KeyAction, usernameCheck), attribute.String(KeyVerb, "get"), attribute.String(KeyHTTPMethod, "GET"),
		attribute.String(KeyActorClass, string(ClassService)),
		attribute.String(KeyObjectName, "example-user-clientconfig"), attribute.String(KeyLegacyResourceName, "example-user-clientconfig"),
		attribute.String(KeyRequestURI, "/usernames/check"))
	return with(base, attribute.String(KeyCheckResult, r))
}

func TestCheck_CheckResult(t *testing.T) {
	v := func(k string, r Reason) Violation { return Violation{Key: k, Reason: r} }
	for _, r := range usernameCheckResults {
		if got := Check(WriterRequest, usernameCheckRecord(r)); len(got) != 0 {
			t.Errorf("%s on %s: %v", r, usernameCheck, got)
		}
	}
	rec := usernameCheckRecord(CheckResultAvailable)
	for _, tc := range []struct {
		name  string
		w     Writer
		attrs []attribute.KeyValue
		want  []Violation
	}{
		{"no result: optional", WriterRequest, without(rec, KeyCheckResult), nil},
		{"a failed lookup, the apiserver answered 503, no result", WriterRequest,
			with(without(rec, KeyCheckResult), attribute.String(KeyOutcome, OutcomeFailure), attribute.String(KeyLegacyOutcome, OutcomeFailure), attribute.Int(KeyHTTPStatusCode, 503)), nil},
		{"a value outside the action's set", WriterRequest, with(rec, attribute.String(KeyCheckResult, "taken")), []Violation{v(KeyCheckResult, ReasonBadEnum)}},
		{"a denial reason is not a check result", WriterRequest, with(rec, attribute.String(KeyCheckResult, DenialReasonNameReserved)), []Violation{v(KeyCheckResult, ReasonBadEnum)}},
		{"on an action that declares no set", WriterRequest, with(rec, attribute.String(KeyAction, "call")), []Violation{v(KeyCheckResult, ReasonNotForAction)}},
		{"on a login", WriterRequest, with(rec, attribute.String(KeyAction, "authn.login.basic")), []Violation{v(KeyCheckResult, ReasonNotForAction)}},
		{"with no action", WriterRequest, without(rec, KeyAction), []Violation{v(KeyCheckResult, ReasonNotForAction), v(KeyAction, ReasonMissing)}},
		{"the action after the result", WriterRequest, append(without(rec, KeyAction), attribute.String(KeyAction, usernameCheck)), nil},
		{"empty", WriterRequest, with(rec, attribute.String(KeyCheckResult, "")), []Violation{v(KeyCheckResult, ReasonEmpty)}},
		{"not a string", WriterRequest, with(rec, attribute.Int(KeyCheckResult, 1)), []Violation{v(KeyCheckResult, ReasonBadType)}},
		{"on a controller", WriterController, with(baseRecord(WriterController), attribute.String(KeyCheckResult, CheckResultAvailable)), []Violation{v(KeyCheckResult, ReasonNotForWriter)}},
		{"on the gateway", WriterGateway, with(baseRecord(WriterGateway), attribute.String(KeyCheckResult, CheckResultAvailable)), []Violation{v(KeyCheckResult, ReasonNotForWriter)}},
		{"on an action record", WriterAction, with(baseRecord(WriterAction), attribute.String(KeyCheckResult, CheckResultAvailable)), []Violation{v(KeyCheckResult, ReasonNotForWriter)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Check(tc.w, tc.attrs); !slices.Equal(got, tc.want) {
				t.Errorf("Check(%s):\n got %v\nwant %v", tc.w, got, tc.want)
			}
		})
	}

	// The set, by hand: the request writer's, on authn.username.check only,
	// in audit#23's order; no key-level enum and no per-writer set.
	want := []string{"available", "reserved", "name_claimed", "name_held_legacy", "name_provisioned", "name_bound", "invalid",
		"name_claimed_by_claimant", "name_claimed_by_another"} // v0.14.0 (authn#146): a claimant's results
	if !slices.Equal(usernameCheckResults, want) {
		t.Errorf("constants %v, want %v", usernameCheckResults, want)
	}
	k, _ := LookupKey(KeyCheckResult)
	if got := k.Writers[WriterRequest].ActionValues; len(got) != 1 || !slices.Equal(got[usernameCheck], want) {
		t.Errorf("request writer's sets = %v, want only %s: %v", got, usernameCheck, want)
	}
	if len(k.Values) != 0 || len(k.Writers[WriterRequest].Values) != 0 || k.Writers[WriterRequest].Level != LevelOptional {
		t.Errorf("check_result: key values %v, writer values %v, level %s; want a per-action set only, optional",
			k.Values, k.Writers[WriterRequest].Values, k.Writers[WriterRequest].Level)
	}
	for _, w := range []Writer{WriterGateway, WriterAction, WriterController} {
		if r := k.Writers[w]; r.Level != LevelNotApplicable || r.ActionValues != nil {
			t.Errorf("%s: %+v, want not_applicable with no set", w, r)
		}
	}

	// LookupKey hands out a copy: changing it changes no rule.
	k.Writers[WriterRequest].ActionValues[usernameCheck][0] = "changed"
	if got := Check(WriterRequest, usernameCheckRecord(CheckResultAvailable)); len(got) != 0 {
		t.Errorf("a changed copy changed the rule: %v", got)
	}
}

// Emit writes the result on authn's check record, and Check accepts it.
func TestEmit_UsernameCheck(t *testing.T) {
	for _, r := range usernameCheckResults {
		e, rec := newEmitter(t, WithWriter(WriterRequest))
		e.Emit(WithSessionIDForTest(t, spanCtx(t), "s1"), Event{UserName: "system:serviceaccount:example-system:example-controller", ActorClass: ClassService,
			Action: usernameCheck, Verb: "get", HTTPMethod: "GET", Outcome: OutcomeSuccess, CheckResult: r,
			Namespace: "example-system", Version: "v1", Resource: "secrets", ObjectName: "example-user-clientconfig",
			Preview: PreviewFalse, RequestURI: "/usernames/check", SourceIPs: []string{"192.0.2.10"}})
		got := attrs(only(t, rec))
		if got[KeyCheckResult] != attribute.StringValue(r) {
			t.Errorf("%s: check_result = %v", r, got[KeyCheckResult].Emit())
		}
		if vs := Check(WriterRequest, kvs(got)); len(vs) > 0 {
			t.Errorf("%s: %v", r, vs)
		}
	}
	// An Event with no result writes no key.
	e, rec := newEmitter(t, WithWriter(WriterRequest))
	e.Emit(spanCtx(t), Event{UserName: "example-user", Action: "call", Verb: "get", Outcome: OutcomeSuccess, Resource: "configmaps", Version: "v1"})
	if _, ok := attrs(only(t, rec))[KeyCheckResult]; ok {
		t.Error("check_result written for an Event without one")
	}
}

// authn's refusals on authn.username.check (audit#23): the mapping has not
// opted in (username_check_not_allowed, naming the checked name's Secret),
// or v0.8.0's ServiceAccount refusals (naming the mapping resource without a
// name, as on /delegate). Each is denied, with no status code and no check
// result: the check never ran. A check result appears only on a success.
func TestCheck_UsernameCheckRefusalsAndTheResultOnlyOnSuccess(t *testing.T) {
	v := func(k string, r Reason) Violation { return Violation{Key: k, Reason: r} }
	refused := func(reason string) []attribute.KeyValue {
		base := deniedRecord(without(usernameCheckRecord(CheckResultAvailable), KeyCheckResult))
		if reason != DenialReasonUsernameCheckNotAllowed {
			base = without(onObject(base, "serviceaccount.authn.krateo.io", "serviceaccounts", ""), KeyObjectName, KeyLegacyResourceName)
		}
		return with(base, attribute.String(KeyDenialReason, reason))
	}
	result := attribute.String(KeyCheckResult, CheckResultAvailable)
	failed := func(attrs []attribute.KeyValue) []attribute.KeyValue {
		return with(attrs, attribute.String(KeyOutcome, OutcomeFailure), attribute.String(KeyLegacyOutcome, OutcomeFailure))
	}
	type tcase struct {
		name  string
		w     Writer
		attrs []attribute.KeyValue
		want  []Violation
	}
	cases := []tcase{
		{"the mapping has not opted in", WriterRequest, refused(DenialReasonUsernameCheckNotAllowed), nil},
		{"not opted in, with a status code", WriterRequest, with(refused(DenialReasonUsernameCheckNotAllowed), attribute.Int(KeyHTTPStatusCode, 403)),
			[]Violation{v(KeyHTTPStatusCode, ReasonUnexpected)}},
		{"not opted in, with a check result", WriterRequest, with(refused(DenialReasonUsernameCheckNotAllowed), result),
			[]Violation{v(KeyCheckResult, ReasonUnexpected)}},
		{"not opted in, on a controller", WriterController,
			with(deniedRecord(baseRecord(WriterController)), attribute.String(KeyDenialReason, DenialReasonUsernameCheckNotAllowed)),
			[]Violation{v(KeyDenialReason, ReasonBadEnum)}},
		{"not opted in, on the gateway", WriterGateway,
			with(deniedRecord(baseRecord(WriterGateway)), attribute.String(KeyDenialReason, DenialReasonUsernameCheckNotAllowed)),
			[]Violation{v(KeyDenialReason, ReasonNotForWriter)}},
		{"a failed lookup with a check result", WriterRequest, failed(usernameCheckRecord(CheckResultAvailable)),
			[]Violation{v(KeyCheckResult, ReasonUnexpected)}},
		{"a failed lookup without one", WriterRequest, failed(without(usernameCheckRecord(CheckResultAvailable), KeyCheckResult)), nil},
		{"a result with no outcome", WriterRequest, without(usernameCheckRecord(CheckResultAvailable), KeyOutcome, KeyLegacyOutcome),
			[]Violation{v(KeyCheckResult, ReasonUnexpected), v(KeyOutcome, ReasonMissing)}},
	}
	for _, reason := range []string{DenialReasonNoMapping, DenialReasonAmbiguousMapping, DenialReasonNotAServiceAccount} {
		cases = append(cases,
			tcase{reason + " on the check", WriterRequest, refused(reason), nil},
			tcase{reason + " on the check, with a check result", WriterRequest, with(refused(reason), result), []Violation{v(KeyCheckResult, ReasonUnexpected)}})
	}
	for _, r := range usernameCheckResults {
		cases = append(cases, tcase{r + " on a denied check", WriterRequest,
			with(refused(DenialReasonUsernameCheckNotAllowed), attribute.String(KeyCheckResult, r)), []Violation{v(KeyCheckResult, ReasonUnexpected)}})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Check(tc.w, tc.attrs); !slices.Equal(got, tc.want) {
				t.Errorf("Check(%s):\n got %v\nwant %v", tc.w, got, tc.want)
			}
		})
	}
	if DenialReasonUsernameCheckNotAllowed != "username_check_not_allowed" {
		t.Errorf("the constant is %q", DenialReasonUsernameCheckNotAllowed)
	}
	k, _ := LookupKey(KeyCheckResult)
	if k.OnlyWhen != CondSucceeded {
		t.Errorf("check_result only_when = %q, want %s", k.OnlyWhen, CondSucceeded)
	}
	for outcome, want := range map[string]bool{OutcomeSuccess: true, OutcomeFailure: false, OutcomeDenied: false, "": false} {
		var a []attribute.KeyValue
		if outcome != "" {
			a = append(a, attribute.String(KeyOutcome, outcome))
		}
		if got := Holds(CondSucceeded, a); got != want {
			t.Errorf("succeeded on outcome %q = %v, want %v", outcome, got, want)
		}
	}
}

// docs/schema.md's registry of krateo.action literals documents them, and
// says schema v1 enforces none: a controller record conforms with each of
// core-provider's helm literals (core-provider#423) and with an unregistered
// one alike, and only an empty literal is reported. If a release starts
// enforcing literals, this test and the registry's text change together.
func TestCheck_ActionLiteralsAreNotEnforced(t *testing.T) {
	ctrl := baseRecord(WriterController)
	for _, a := range []string{"helm.install", "helm.upgrade", "helm.reconcile", "helm.rollback", "helm.uninstall", "example.unregistered"} {
		if got := Check(WriterController, with(ctrl, attribute.String(KeyAction, a))); len(got) != 0 {
			t.Errorf("krateo.action %q: %v", a, got)
		}
	}
	if got := Check(WriterController, with(ctrl, attribute.String(KeyAction, ""))); !slices.Equal(got, []Violation{{Key: KeyAction, Reason: ReasonEmpty}}) {
		t.Errorf("an empty literal: %v", got)
	}
	k, _ := LookupKey(KeyAction)
	if len(k.Values) != 0 {
		t.Errorf("krateo.action has values %v: the registry says no literal is enforced", k.Values)
	}
	for _, w := range Writers() {
		if r := k.Writers[w]; len(r.Values) != 0 || len(r.ActionValues) != 0 {
			t.Errorf("krateo.action has a closed set for %s: the registry says no literal is enforced", w)
		}
	}
}

// Emit writes the not-opted-in refusal as a conforming denied record.
func TestEmit_UsernameCheckNotAllowed(t *testing.T) {
	e, rec := newEmitter(t, WithWriter(WriterRequest))
	e.Emit(WithSessionIDForTest(t, spanCtx(t), "s1"), Event{UserName: "system:serviceaccount:example-system:example-controller", ActorClass: ClassService,
		// Verb get, so method GET: the schema derives http.request.method
		// from the verb of the authority request, never from the inbound
		// POST /usernames/check. No status code: no authority answered.
		Action: usernameCheck, Verb: "get", HTTPMethod: "GET", Outcome: OutcomeDenied, DenialReason: DenialReasonUsernameCheckNotAllowed,
		Namespace: "example-system", Version: "v1", Resource: "secrets", ObjectName: "example-user-clientconfig",
		Preview: PreviewFalse, RequestURI: "/usernames/check", SourceIPs: []string{"192.0.2.10"}})
	got := attrs(only(t, rec))
	if vs := Check(WriterRequest, kvs(got)); len(vs) > 0 {
		t.Errorf("%v", vs)
	}
	for _, k := range []string{KeyCheckResult, KeyHTTPStatusCode} {
		if _, ok := got[k]; ok {
			t.Errorf("%s on the refusal", k)
		}
	}
}
