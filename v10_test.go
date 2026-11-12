package audit

import (
	"slices"
	"testing"

	"go.opentelemetry.io/otel/attribute"
)

// v0.10.0 (audit#29, authn#136): invalid_request, authn's refusal of a
// verified, mapped and opted-in caller whose /usernames/check body has no
// username or isn't JSON. Denied, no status code, no check_result; with no
// username, the Secret resource with no name.

// invalidRequest is authn's record of that refusal, as authn writes it: the
// Secret resource, no name, and no verb or method (there is no name to read),
// so both are marked.
func invalidRequest() []attribute.KeyValue {
	base := deniedRecord(without(usernameCheckRecord(CheckResultAvailable), KeyCheckResult, KeyObjectName, KeyLegacyResourceName, KeyVerb, KeyHTTPMethod))
	return with(base, attribute.String(KeyDenialReason, DenialReasonInvalidRequest), attribute.String(KeyIncomplete, "verb,method"))
}

func TestCheck_InvalidRequest(t *testing.T) {
	v := func(k string, r Reason) Violation { return Violation{Key: k, Reason: r} }
	marked := []Violation{v(KeyVerb, ReasonIncomplete), v(KeyHTTPMethod, ReasonIncomplete)}
	rec := invalidRequest()
	// With the verb the lookup would have had, the record conforms outright:
	// the reason itself is accepted.
	withVerb := with(without(rec, KeyIncomplete), attribute.String(KeyVerb, "get"), attribute.String(KeyHTTPMethod, "GET"))
	failed := func(attrs []attribute.KeyValue, o string) []attribute.KeyValue {
		return with(attrs, attribute.String(KeyOutcome, o), attribute.String(KeyLegacyOutcome, o))
	}
	for _, tc := range []struct {
		name  string
		w     Writer
		attrs []attribute.KeyValue
		want  []Violation
	}{
		{"the refusal, with the lookup's verb", WriterRequest, withVerb, nil},
		{"the refusal as authn writes it: verb and method marked, nothing else", WriterRequest, rec, marked},
		{"with a status code", WriterRequest, with(withVerb, attribute.Int(KeyHTTPStatusCode, 400)), []Violation{v(KeyHTTPStatusCode, ReasonUnexpected)}},
		{"with a check result", WriterRequest, with(withVerb, attribute.String(KeyCheckResult, CheckResultInvalid)), []Violation{v(KeyCheckResult, ReasonUnexpected)}},
		{"on a success", WriterRequest, failed(withVerb, OutcomeSuccess), []Violation{v(KeyDenialReason, ReasonUnexpected)}},
		{"on a failure", WriterRequest, failed(withVerb, OutcomeFailure), []Violation{v(KeyDenialReason, ReasonUnexpected)}},
		{"on a controller", WriterController, with(deniedRecord(baseRecord(WriterController)), attribute.String(KeyDenialReason, DenialReasonInvalidRequest)),
			[]Violation{v(KeyDenialReason, ReasonBadEnum)}},
		{"on the gateway", WriterGateway, with(deniedRecord(baseRecord(WriterGateway)), attribute.String(KeyDenialReason, DenialReasonInvalidRequest)),
			[]Violation{v(KeyDenialReason, ReasonNotForWriter)}},
		{"on an action record", WriterAction, with(deniedRecord(baseRecord(WriterAction)), attribute.String(KeyDenialReason, DenialReasonInvalidRequest)),
			[]Violation{v(KeyDenialReason, ReasonNotForWriter)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Check(tc.w, tc.attrs); !slices.Equal(got, tc.want) {
				t.Errorf("Check(%s):\n got %v\nwant %v", tc.w, got, tc.want)
			}
		})
	}

	// By hand: the constant, the request writer's value only.
	if DenialReasonInvalidRequest != "invalid_request" {
		t.Errorf("the constant is %q", DenialReasonInvalidRequest)
	}
	d, _ := LookupKey(KeyDenialReason)
	if !slices.Contains(d.Writers[WriterRequest].Values, "invalid_request") || slices.Contains(d.Writers[WriterController].Values, "invalid_request") {
		t.Error("invalid_request: the request writer's value only")
	}
}

// Emit writes the refusal as authn does: denied, the reason, no status code,
// no check result, and the verb and method marked, not guessed.
func TestEmit_InvalidRequest(t *testing.T) {
	e, rec := newEmitter(t, WithWriter(WriterRequest))
	e.Emit(WithSessionIDForTest(t, spanCtx(t), "s1"), Event{UserName: "system:serviceaccount:example-system:example-controller", ActorClass: ClassService,
		Action: usernameCheck, Outcome: OutcomeDenied, DenialReason: DenialReasonInvalidRequest,
		Namespace: "example-system", Version: "v1", Resource: "secrets",
		Preview: PreviewFalse, RequestURI: "/usernames/check", SourceIPs: []string{"192.0.2.10"}})
	got := attrs(only(t, rec))
	if got[KeyDenialReason] != attribute.StringValue(DenialReasonInvalidRequest) {
		t.Errorf("denial_reason = %v", got[KeyDenialReason].Emit())
	}
	for _, k := range []string{KeyCheckResult, KeyHTTPStatusCode, KeyObjectName} {
		if _, ok := got[k]; ok {
			t.Errorf("%s on the refusal", k)
		}
	}
	if vs := Check(WriterRequest, kvs(got)); !slices.Equal(vs, []Violation{{Key: KeyVerb, Reason: ReasonIncomplete}, {Key: KeyHTTPMethod, Reason: ReasonIncomplete}}) {
		t.Errorf("Check: %v; want only the verb and method marked", vs)
	}
}

// name_not_issued (audit#29; plumbing usernames.ErrNotIssued): a sign-in for
// a username authn would issue in another form. Denied, no status code, no
// check result; the Secret resource with no name, under the aliasing rule.
func nameNotIssued() []attribute.KeyValue {
	base := deniedRecord(without(onObject(baseRecord(WriterRequest), "", "secrets", ""), KeyObjectName, KeyLegacyResourceName))
	return with(base, attribute.String(KeyAction, "authn.login.basic"), attribute.String(KeyVerb, "update"), attribute.String(KeyHTTPMethod, "PUT"),
		attribute.String(KeyRequestURI, "/basic"), attribute.String(KeyDenialReason, DenialReasonNameNotIssued))
}

func TestCheck_NameNotIssued(t *testing.T) {
	v := func(k string, r Reason) Violation { return Violation{Key: k, Reason: r} }
	rec := nameNotIssued()
	outcome := func(attrs []attribute.KeyValue, o string) []attribute.KeyValue {
		return with(attrs, attribute.String(KeyOutcome, o), attribute.String(KeyLegacyOutcome, o))
	}
	for _, tc := range []struct {
		name  string
		w     Writer
		attrs []attribute.KeyValue
		want  []Violation
	}{
		{"the refusal, the Secret resource with no name", WriterRequest, rec, nil},
		{"with its verb unknown, marked", WriterRequest, with(without(rec, KeyVerb, KeyHTTPMethod, KeyDryRun), attribute.String(KeyIncomplete, "verb,method")),
			[]Violation{v(KeyVerb, ReasonIncomplete), v(KeyHTTPMethod, ReasonIncomplete)}},
		{"with a status code", WriterRequest, with(rec, attribute.Int(KeyHTTPStatusCode, 403)), []Violation{v(KeyHTTPStatusCode, ReasonUnexpected)}},
		// A check result is the username check's only; on a login it is
		// reported twice over: not this action's key, and not on a denial.
		{"with a check result", WriterRequest, with(rec, attribute.String(KeyCheckResult, CheckResultAvailable)),
			[]Violation{v(KeyCheckResult, ReasonNotForAction), v(KeyCheckResult, ReasonUnexpected)}},
		{"on a success", WriterRequest, outcome(rec, OutcomeSuccess), []Violation{v(KeyDenialReason, ReasonUnexpected)}},
		{"on a failure", WriterRequest, outcome(rec, OutcomeFailure), []Violation{v(KeyDenialReason, ReasonUnexpected)}},
		{"on a controller", WriterController, with(deniedRecord(baseRecord(WriterController)), attribute.String(KeyDenialReason, DenialReasonNameNotIssued)),
			[]Violation{v(KeyDenialReason, ReasonBadEnum)}},
		{"on the gateway", WriterGateway, with(deniedRecord(baseRecord(WriterGateway)), attribute.String(KeyDenialReason, DenialReasonNameNotIssued)),
			[]Violation{v(KeyDenialReason, ReasonNotForWriter)}},
		{"on an action record", WriterAction, with(deniedRecord(baseRecord(WriterAction)), attribute.String(KeyDenialReason, DenialReasonNameNotIssued)),
			[]Violation{v(KeyDenialReason, ReasonNotForWriter)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Check(tc.w, tc.attrs); !slices.Equal(got, tc.want) {
				t.Errorf("Check(%s):\n got %v\nwant %v", tc.w, got, tc.want)
			}
		})
	}
	if DenialReasonNameNotIssued != "name_not_issued" {
		t.Errorf("the constant is %q", DenialReasonNameNotIssued)
	}
	d, _ := LookupKey(KeyDenialReason)
	if !slices.Contains(d.Writers[WriterRequest].Values, "name_not_issued") || slices.Contains(d.Writers[WriterController].Values, "name_not_issued") {
		t.Error("name_not_issued: the request writer's value only")
	}
}

// Emit writes the refusal: denied, the reason, no status code, no check
// result and no name, and Check accepts it.
func TestEmit_NameNotIssued(t *testing.T) {
	e, rec := newEmitter(t, WithWriter(WriterRequest))
	e.Emit(WithSessionIDForTest(t, spanCtx(t), "s1"), Event{UserName: "example-user", ActorClass: ClassHuman,
		Action: "authn.login.basic", Verb: "update", HTTPMethod: "PUT", Outcome: OutcomeDenied, DenialReason: DenialReasonNameNotIssued,
		Namespace: "example-system", Version: "v1", Resource: "secrets",
		Preview: PreviewFalse, RequestURI: "/basic", SourceIPs: []string{"192.0.2.10"}})
	got := attrs(only(t, rec))
	if got[KeyDenialReason] != attribute.StringValue(DenialReasonNameNotIssued) {
		t.Errorf("denial_reason = %v", got[KeyDenialReason].Emit())
	}
	for _, k := range []string{KeyCheckResult, KeyHTTPStatusCode, KeyObjectName} {
		if _, ok := got[k]; ok {
			t.Errorf("%s on the refusal", k)
		}
	}
	if vs := Check(WriterRequest, kvs(got)); len(vs) > 0 {
		t.Errorf("Check: %v", vs)
	}
}
