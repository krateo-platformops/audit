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
}

const usernameCheck = "authn.username.check"

// usernameCheckRecord is authn's record of a completed username check with
// result r: a request row, verb get, targeting the clientconfig Secret the
// name guard protects, outcome success. A read, so no dry_run.
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
	want := []string{"available", "reserved", "name_claimed", "name_held_legacy", "name_provisioned", "name_bound", "invalid"}
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
