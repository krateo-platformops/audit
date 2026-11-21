package audit

import (
	"slices"
	"testing"

	"go.opentelemetry.io/otel/attribute"
)

// subject_not_a_person (v0.16.0, authn#165): authn's /delegate verified an
// identity provider's subject token, but it carries no user session (a
// service account's client-credentials token), so it names no person to act
// for. The request writer's value only, on a denied record, never beside a
// status code: no authority answered.
func TestCheck_SubjectNotAPerson(t *testing.T) {
	if DenialReasonSubjectNotAPerson != "subject_not_a_person" {
		t.Errorf("constant %q", DenialReasonSubjectNotAPerson)
	}
	r := DenialReasonSubjectNotAPerson
	runV15(t, []v15Case{
		{"on /delegate", WriterRequest, delegateRefusal(r), nil},
		{"with a status code", WriterRequest, with(delegateRefusal(r), attribute.Int(KeyHTTPStatusCode, 403)), []Violation{v15v(KeyHTTPStatusCode, ReasonUnexpected)}},
		{"on a success", WriterRequest, with(delegateRecord(), attribute.String(KeyDenialReason, r)), []Violation{v15v(KeyDenialReason, ReasonUnexpected)}},
		{"on a controller", WriterController, with(deniedRecord(baseRecord(WriterController)), attribute.String(KeyDenialReason, r)), []Violation{v15v(KeyDenialReason, ReasonBadEnum)}},
		{"on the gateway", WriterGateway, with(deniedRecord(baseRecord(WriterGateway)), attribute.String(KeyDenialReason, r)), []Violation{v15v(KeyDenialReason, ReasonNotForWriter)}},
	})
	d, _ := LookupKey(KeyDenialReason)
	if !slices.Contains(d.Writers[WriterRequest].Values, r) || slices.Contains(d.Writers[WriterController].Values, r) {
		t.Errorf("%s: the request writer's value only", r)
	}
}
