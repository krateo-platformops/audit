package audit

import (
	"slices"
	"testing"

	"go.opentelemetry.io/otel/attribute"
)

// v0.8.0 (audit#20, authn#132): authn's refusals of an identity that has
// already verified. Denied, no status code, the request writer's alone. The
// ServiceAccount cases name the mapping resource without a name.
var postVerificationReasons = []string{
	DenialReasonStepupNotEnabled, DenialReasonInsufficientAssurance, DenialReasonStaleAuthentication,
	DenialReasonNoMapping, DenialReasonAmbiguousMapping, DenialReasonNotAServiceAccount,
}

// postVerificationRefusal is authn's denied record for reason: a step-up
// names the user's step-up Secret; a ServiceAccount login names the mapping
// resource and no mapping (there is none, or no single one).
func postVerificationRefusal(reason string) []attribute.KeyValue {
	base := deniedRecord(baseRecord(WriterRequest))
	switch reason {
	case DenialReasonStepupNotEnabled, DenialReasonInsufficientAssurance, DenialReasonStaleAuthentication:
		base = with(onObject(base, "", "secrets", ""), attribute.String(KeyAction, "authn.stepup"), attribute.String(KeyRequestURI, "/stepup"),
			attribute.String(KeyObjectName, "example-stepup"), attribute.String(KeyLegacyResourceName, "example-stepup"))
	default:
		base = with(without(onObject(base, "serviceaccount.authn.krateo.io", "serviceaccounts", ""), KeyObjectName, KeyLegacyResourceName),
			attribute.String(KeyAction, "authn.login.serviceaccount"), attribute.String(KeyRequestURI, "/serviceaccount/login"))
	}
	return with(base, attribute.String(KeyDenialReason, reason))
}

func TestCheck_PostVerificationReasons(t *testing.T) {
	v := func(k string, r Reason) Violation { return Violation{Key: k, Reason: r} }
	for _, reason := range postVerificationReasons {
		refused := postVerificationRefusal(reason)
		for _, tc := range []struct {
			name  string
			w     Writer
			attrs []attribute.KeyValue
			want  []Violation
		}{
			{"the refusal", WriterRequest, refused, nil},
			{"with a status code", WriterRequest, with(refused, attribute.Int(KeyHTTPStatusCode, 403)), []Violation{v(KeyHTTPStatusCode, ReasonUnexpected)}},
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

	// The values, by hand, and the request writer's only. The cases #20 rules
	// out are not values.
	want := []string{"stepup_not_enabled", "insufficient_assurance", "stale_authentication", "no_mapping", "ambiguous_mapping", "not_a_service_account"}
	if !slices.Equal(postVerificationReasons, want) {
		t.Errorf("constants %v, want %v", postVerificationReasons, want)
	}
	d, _ := LookupKey(KeyDenialReason)
	for _, r := range want {
		if !slices.Contains(d.Writers[WriterRequest].Values, r) || slices.Contains(d.Writers[WriterController].Values, r) {
			t.Errorf("%s: the request writer's value only", r)
		}
	}
	for _, r := range []string{"audience_mismatch", "mapping_lookup_failed", "stepup_misconfigured"} {
		if slices.Contains(d.Writers[WriterRequest].Values, r) {
			t.Errorf("%s is a denial reason; #20 rules it out", r)
		}
	}
}

// The failures after verification that #20 keeps out of the denial reasons
// are failure rows. The status code is the authority's answer, never
// authn's own 500: MappingLookupFailed carries the apiserver's code for the
// lookup when it answered, and none when nothing answered. StepUpMisconfigured
// carries none. A failure row never carries a denial reason.
func TestCheck_PostVerificationFailureRows(t *testing.T) {
	v := func(k string, r Reason) Violation { return Violation{Key: k, Reason: r} }
	failed := func(attrs []attribute.KeyValue) []attribute.KeyValue {
		return with(without(attrs, KeyDenialReason, KeyHTTPStatusCode),
			attribute.String(KeyOutcome, OutcomeFailure), attribute.String(KeyLegacyOutcome, OutcomeFailure))
	}
	lookup := failed(postVerificationRefusal(DenialReasonNoMapping))
	stepup := failed(postVerificationRefusal(DenialReasonStepupNotEnabled))
	for _, tc := range []struct {
		name  string
		attrs []attribute.KeyValue
		want  []Violation
	}{
		{"mapping lookup failed, the apiserver answered 403", with(lookup, attribute.Int(KeyHTTPStatusCode, 403)), nil},
		{"mapping lookup failed, the apiserver answered 503", with(lookup, attribute.Int(KeyHTTPStatusCode, 503)), nil},
		{"mapping lookup failed, nothing answered", lookup, nil},
		{"step-up misconfigured", stepup, nil},
		{"a failure row with a denial reason", with(lookup, attribute.String(KeyDenialReason, DenialReasonNoMapping)), []Violation{v(KeyDenialReason, ReasonUnexpected)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Check(WriterRequest, tc.attrs); !slices.Equal(got, tc.want) {
				t.Errorf("Check(request):\n got %v\nwant %v", got, tc.want)
			}
		})
	}
}

// Emit writes each reason on a denied record that Check accepts, with no
// status code.
func TestEmit_PostVerificationRefusal(t *testing.T) {
	for _, reason := range postVerificationReasons {
		e, rec := newEmitter(t, WithWriter(WriterRequest))
		e.Emit(WithSessionIDForTest(t, spanCtx(t), "s1"), Event{UserName: "example-user", ActorClass: ClassHuman,
			Action: "authn.login.serviceaccount", Verb: "create", HTTPMethod: "POST", Outcome: OutcomeDenied, DenialReason: reason,
			Namespace: "example-system", Group: "serviceaccount.authn.krateo.io", Version: "v1alpha1", Resource: "serviceaccounts",
			Preview: PreviewFalse, RequestURI: "/serviceaccount/login", SourceIPs: []string{"192.0.2.10"}})
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
