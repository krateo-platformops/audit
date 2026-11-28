package audit

import (
	"os"
	"slices"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
)

// audience_mismatch (v0.17.0, snowplow#1596): a recipient refused a bearer
// token that VERIFIED but whose `aud` names only other recipients (or is an
// empty list). The request writer's value only, on a denied record, never
// beside a status code: no authority answered. The earlier rule, that an
// audience mismatch is a counted refusal and never a row, no longer stands:
// the signature is verified when the audience is looked at, so the sender is
// known, and the row names it.
func TestCheck_AudienceMismatch(t *testing.T) {
	if DenialReasonAudienceMismatch != "audience_mismatch" {
		t.Errorf("constant %q", DenialReasonAudienceMismatch)
	}
	r := DenialReasonAudienceMismatch
	refused := with(deniedRecord(pathRecord()), attribute.String(KeyDenialReason, r))
	runV15(t, []v15Case{
		{"a recipient refusing a verified token", WriterRequest, refused, nil},
		{"with a status code", WriterRequest, with(refused, attribute.Int(KeyHTTPStatusCode, 401)), []Violation{v15v(KeyHTTPStatusCode, ReasonUnexpected)}},
		{"on a success", WriterRequest, with(baseRecord(WriterRequest), attribute.String(KeyDenialReason, r)), []Violation{v15v(KeyDenialReason, ReasonUnexpected)}},
		{"on a controller", WriterController, with(deniedRecord(baseRecord(WriterController)), attribute.String(KeyDenialReason, r)), []Violation{v15v(KeyDenialReason, ReasonBadEnum)}},
		{"on the gateway", WriterGateway, with(deniedRecord(baseRecord(WriterGateway)), attribute.String(KeyDenialReason, r)), []Violation{v15v(KeyDenialReason, ReasonNotForWriter)}},
	})
	d, _ := LookupKey(KeyDenialReason)
	if !slices.Contains(d.Writers[WriterRequest].Values, r) || slices.Contains(d.Writers[WriterController].Values, r) {
		t.Errorf("%s: the request writer's value only", r)
	}
}

// The schema no longer says an audience mismatch is never a row, and says why
// it is one: the token verified, so the sender is known.
func TestSchema_AudienceMismatchIsARow(t *testing.T) {
	b, err := os.ReadFile("schema/v1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, stale := range []string{"counted\n      #   pre-verification refusal and never a row", "never a row.\n      # platform_group"} {
		if strings.Contains(s, stale) {
			t.Errorf("schema/v1.yaml still says an audience mismatch is never a row: %q", stale)
		}
	}
	for _, want := range []string{"audience_mismatch (v0.17.0)", "The signature IS\n      # verified when the audience is looked at, so the sender is known"} {
		if !strings.Contains(s, want) {
			t.Errorf("schema/v1.yaml does not say %q", want)
		}
	}
}
