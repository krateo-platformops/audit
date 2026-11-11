package audit

import (
	"slices"
	"testing"

	"go.opentelemetry.io/otel/attribute"
)

// v0.6.1 (audit#18): authn's /delegate refusals of a subject token, after the
// actor verified. Denied, no status code, the request writer's alone.
func TestCheck_SubjectTokenReasons(t *testing.T) {
	v := func(k string, r Reason) Violation { return Violation{Key: k, Reason: r} }
	// A /delegate refusal: the actor's ServiceAccount mapping is the target.
	delegate := with(deniedRecord(onObject(baseRecord(WriterRequest), "serviceaccount.authn.krateo.io", "serviceaccounts", "")),
		attribute.String(KeyAction, "authn.delegate"), attribute.String(KeyRequestURI, "/delegate"))
	for _, reason := range []string{DenialReasonSubjectTokenExpired, DenialReasonSubjectTokenInvalid} {
		refused := with(delegate, attribute.String(KeyDenialReason, reason))
		for _, tc := range []struct {
			name  string
			w     Writer
			attrs []attribute.KeyValue
			want  []Violation
		}{
			{"a /delegate refusal", WriterRequest, refused, nil},
			{"with a status code", WriterRequest, with(refused, attribute.Int(KeyHTTPStatusCode, 401)), []Violation{v(KeyHTTPStatusCode, ReasonUnexpected)}},
			{"on a failure", WriterRequest, with(refused, attribute.String(KeyOutcome, OutcomeFailure), attribute.String(KeyLegacyOutcome, OutcomeFailure)),
				[]Violation{v(KeyDenialReason, ReasonUnexpected)}},
			{"on a success", WriterRequest, with(refused, attribute.String(KeyOutcome, OutcomeSuccess), attribute.String(KeyLegacyOutcome, OutcomeSuccess)),
				[]Violation{v(KeyDenialReason, ReasonUnexpected)}},
			{"with no outcome", WriterRequest, without(refused, KeyOutcome, KeyLegacyOutcome),
				[]Violation{v(KeyDenialReason, ReasonUnexpected), v(KeyOutcome, ReasonMissing)}},
			{"on a controller", WriterController, with(deniedRecord(baseRecord(WriterController)), attribute.String(KeyDenialReason, reason)),
				[]Violation{v(KeyDenialReason, ReasonBadEnum)}},
			{"on the gateway", WriterGateway, with(deniedRecord(baseRecord(WriterGateway)), attribute.String(KeyDenialReason, reason)),
				[]Violation{v(KeyDenialReason, ReasonNotForWriter)}},
		} {
			t.Run(reason+": "+tc.name, func(t *testing.T) {
				if got := Check(tc.w, tc.attrs); !slices.Equal(got, tc.want) {
					t.Errorf("Check(%s):\n got %v\nwant %v", tc.w, got, tc.want)
				}
			})
		}
	}
	// The two are distinct values, and neither is another reason's spelling.
	if DenialReasonSubjectTokenExpired != "subject_token_expired" || DenialReasonSubjectTokenInvalid != "subject_token_invalid" {
		t.Errorf("constants %q, %q", DenialReasonSubjectTokenExpired, DenialReasonSubjectTokenInvalid)
	}
	d, _ := LookupKey(KeyDenialReason)
	for _, r := range []string{"subject_token_expired", "subject_token_invalid"} {
		if !slices.Contains(d.Writers[WriterRequest].Values, r) || slices.Contains(d.Writers[WriterController].Values, r) {
			t.Errorf("%s: the request writer's value only", r)
		}
	}
}

// Emit writes either reason on a denied /delegate record that Check accepts.
func TestEmit_SubjectTokenRefusal(t *testing.T) {
	for _, reason := range []string{DenialReasonSubjectTokenExpired, DenialReasonSubjectTokenInvalid} {
		e, rec := newEmitter(t, WithWriter(WriterRequest))
		e.Emit(WithSessionIDForTest(t, spanCtx(t), "s1"), Event{UserName: "example-agent", ActorClass: ClassAgent,
			Action: "authn.delegate", Verb: "create", HTTPMethod: "POST", Outcome: OutcomeDenied, DenialReason: reason,
			Namespace: "example-system", Group: "serviceaccount.authn.krateo.io", Version: "v1alpha1", Resource: "serviceaccounts",
			ObjectName: "example-agent", Preview: PreviewFalse, RequestURI: "/delegate", SourceIPs: []string{"192.0.2.10"}})
		got := attrs(only(t, rec))
		if got[KeyDenialReason] != attribute.StringValue(reason) {
			t.Errorf("%s: denial_reason = %v", reason, got[KeyDenialReason].Emit())
		}
		if _, ok := got[KeyHTTPStatusCode]; ok {
			t.Errorf("%s: a status code on the refusal", reason)
		}
		if vs := Check(WriterRequest, kvs(got)); len(vs) > 0 {
			t.Errorf("%s: %v", reason, vs)
		}
	}
}
