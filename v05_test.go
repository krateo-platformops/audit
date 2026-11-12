package audit

import (
	"slices"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
)

// The v0.5.0 additions: krateo.audit.cause_ref.* (audit#8) and
// krateo.audit.denial_reason (audit#10).

var exampleCause = []attribute.KeyValue{
	attribute.String(KeyCauseAPIGroup, "composition.krateo.io"),
	attribute.String(KeyCauseAPIVersion, "v1-2-0"),
	attribute.String(KeyCauseResource, "exampleapps"),
	attribute.String(KeyCauseNamespace, "example-ns"),
	attribute.String(KeyCauseName, "example-composition"),
	attribute.String(KeyCauseUID, "uid-c"),
	attribute.Int64(KeyCauseGeneration, 4),
}

// deniedRecord is attrs refused by the writer itself: outcome denied, and no
// status code, since no authority answered (v0.6.0, audit#13).
func deniedRecord(attrs []attribute.KeyValue) []attribute.KeyValue {
	return with(without(attrs, KeyHTTPStatusCode), attribute.String(KeyOutcome, OutcomeDenied), attribute.String(KeyLegacyOutcome, OutcomeDenied))
}

// Accepted where the schema allows them, reported everywhere else.
func TestCheck_CauseRefAndDenialReason(t *testing.T) {
	v := func(k string, r Reason) Violation { return Violation{Key: k, Reason: r} }
	ctrl := baseRecord(WriterController)
	caused := with(ctrl, exampleCause...)
	child := with(without(ctrl, KeyServerAddress), // the object written: a helm child
		attribute.String(KeyVerb, "delete"),
		attribute.String(KeyNamespace, "example-ns"),
		attribute.String(KeyObjectAPIVersion, "v1"), attribute.String(KeyLegacyResourceVersion, "v1"),
		attribute.String(KeyObjectResource, "persistentvolumeclaims"), attribute.String(KeyLegacyResourceResource, "persistentvolumeclaims"),
		attribute.String(KeyObjectName, "example-data"), attribute.String(KeyLegacyResourceName, "example-data"),
		attribute.Bool(KeyPreview, false))
	child = with(child, exampleCause...)
	kept := with(deniedRecord(child), attribute.String(KeyDenialReason, DenialReasonKeptResourcePolicy))
	req := baseRecord(WriterRequest)
	authnDenied := with(deniedRecord(req), attribute.String(KeyDenialReason, DenialReasonNameClaimed))

	for _, tc := range []struct {
		name  string
		w     Writer
		attrs []attribute.KeyValue
		want  []Violation
	}{
		// cause_ref: optional for a controller, all of a piece once named.
		{"controller without cause_ref", WriterController, ctrl, nil},
		{"controller with cause_ref and an endpoint", WriterController, caused, nil},
		{"controller with cause_ref and the object written", WriterController, child, nil},
		{"cause_ref of a core, cluster-scoped object with no generation", WriterController, without(caused, KeyCauseAPIGroup, KeyCauseNamespace, KeyCauseGeneration), nil},
		{"a cause is not a target", WriterController, without(caused, KeyServerAddress), []Violation{v(RuleTarget, ReasonMissing)}},
		{"cause_ref with a name only", WriterController, with(ctrl, attribute.String(KeyCauseName, "example-composition")),
			[]Violation{v(KeyCauseAPIVersion, ReasonMissing), v(KeyCauseResource, ReasonMissing), v(KeyCauseUID, ReasonMissing)}},
		{"cause_ref without its uid", WriterController, without(caused, KeyCauseUID), []Violation{v(KeyCauseUID, ReasonMissing)}},
		{"cause_ref generation as a string", WriterController, with(caused, attribute.String(KeyCauseGeneration, "4")), []Violation{v(KeyCauseGeneration, ReasonBadType)}},
		{"cause_ref uid empty", WriterController, with(caused, attribute.String(KeyCauseUID, "")), []Violation{v(KeyCauseUID, ReasonEmpty)}},
		{"request writes cause_ref", WriterRequest, with(req, attribute.String(KeyCauseUID, "uid-c")), []Violation{v(KeyCauseUID, ReasonNotForWriter)}},
		{"gateway writes cause_ref", WriterGateway, with(baseRecord(WriterGateway), attribute.String(KeyCauseName, "x")), []Violation{v(KeyCauseName, ReasonNotForWriter)}},
		{"action writes cause_ref", WriterAction, with(baseRecord(WriterAction), attribute.Int64(KeyCauseGeneration, 1)), []Violation{v(KeyCauseGeneration, ReasonNotForWriter)}},

		// denial_reason: only on a denied record, one of the writer's own values.
		{"kept deletion", WriterController, kept, nil},
		{"denied without a reason", WriterController, deniedRecord(child), nil},
		{"authn refusal", WriterRequest, authnDenied, nil},
		{"another authn value", WriterRequest, with(authnDenied, attribute.String(KeyDenialReason, DenialReasonSystemGroup)), nil},
		// authn's OIDC allowedGroups gate: a verified identity in none of the admitted groups.
		{"authn group gate", WriterRequest, with(authnDenied, attribute.String(KeyDenialReason, DenialReasonGroupNotAllowed)), nil},
		{"authn group gate on a success", WriterRequest, with(authnDenied, attribute.String(KeyDenialReason, DenialReasonGroupNotAllowed), attribute.String(KeyOutcome, OutcomeSuccess), attribute.String(KeyLegacyOutcome, OutcomeSuccess)), []Violation{v(KeyDenialReason, ReasonUnexpected)}},
		{"authn group gate on a controller", WriterController, with(kept, attribute.String(KeyDenialReason, DenialReasonGroupNotAllowed)), []Violation{v(KeyDenialReason, ReasonBadEnum)}},
		{"a reason on a success", WriterController, with(kept, attribute.String(KeyOutcome, OutcomeSuccess), attribute.String(KeyLegacyOutcome, OutcomeSuccess)), []Violation{v(KeyDenialReason, ReasonUnexpected)}},
		{"a reason on a failure", WriterRequest, with(authnDenied, attribute.String(KeyOutcome, OutcomeFailure), attribute.String(KeyLegacyOutcome, OutcomeFailure)), []Violation{v(KeyDenialReason, ReasonUnexpected)}},
		{"a reason with no outcome at all", WriterController, without(kept, KeyOutcome, KeyLegacyOutcome), []Violation{v(KeyDenialReason, ReasonUnexpected), v(KeyOutcome, ReasonMissing)}},
		{"a reason beside the v0.3 outcome only", WriterController, without(kept, KeyOutcome),
			[]Violation{v(KeyDenialReason, ReasonUnexpected), v(KeyOutcome, ReasonMissing), v(KeyLegacyOutcome, ReasonLegacyWithoutReplacement)}},
		{"another writer's value", WriterController, with(kept, attribute.String(KeyDenialReason, DenialReasonNameClaimed)), []Violation{v(KeyDenialReason, ReasonBadEnum)}},
		{"the controller's value on a request", WriterRequest, with(authnDenied, attribute.String(KeyDenialReason, DenialReasonKeptResourcePolicy)), []Violation{v(KeyDenialReason, ReasonBadEnum)}},
		{"the body text as a reason", WriterController, with(kept, attribute.String(KeyDenialReason, "kept: resource-policy")), []Violation{v(KeyDenialReason, ReasonBadEnum)}},
		{"a reason as a list", WriterController, with(kept, attribute.StringSlice(KeyDenialReason, []string{DenialReasonKeptResourcePolicy})), []Violation{v(KeyDenialReason, ReasonBadType)}},
		{"an empty reason", WriterController, with(kept, attribute.String(KeyDenialReason, "")), []Violation{v(KeyDenialReason, ReasonEmpty)}},
		{"gateway writes a reason", WriterGateway, with(deniedRecord(baseRecord(WriterGateway)), attribute.String(KeyDenialReason, DenialReasonNameClaimed)), []Violation{v(KeyDenialReason, ReasonNotForWriter)}},
		{"action writes a reason", WriterAction, with(deniedRecord(baseRecord(WriterAction)), attribute.String(KeyDenialReason, DenialReasonKeptResourcePolicy)), []Violation{v(KeyDenialReason, ReasonNotForWriter)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Check(tc.w, tc.attrs); !slices.Equal(got, tc.want) {
				t.Errorf("Check(%s):\n got %v\nwant %v", tc.w, got, tc.want)
			}
		})
	}

	if got := RequiredKeys(WriterController, caused); !slices.Contains(got, KeyCauseUID) || slices.Contains(got, KeyCauseGeneration) {
		t.Errorf("a record naming a cause must carry its uid, and its generation when it has one (not checked): %v", got)
	}
	if got := RequiredKeys(WriterController, ctrl); slices.Contains(got, KeyCauseUID) {
		t.Errorf("a record naming no cause needs no cause_ref: %v", got)
	}
}

// The schema states the two rulings as asked: cause_ref is the controller's
// alone and never required of it outright; denial_reason exists only on a
// denied record, with authn's six values for the request writer and the kept
// deletion for the controller.
func TestSchema_CauseRefAndDenialReason(t *testing.T) {
	causes := 0
	for _, k := range Keys() {
		if !strings.HasPrefix(k.Name, causeRefPrefix) {
			continue
		}
		causes++
		for _, w := range []Writer{WriterRequest, WriterGateway, WriterAction} {
			if k.Writers[w].Level != LevelNotApplicable {
				t.Errorf("%s for %s = %v, want not_applicable", k.Name, w, k.Writers[w].Level)
			}
		}
		if r := k.Writers[WriterController]; r.Level != LevelConditional || r.Markable {
			t.Errorf("%s for the controller = %+v, want conditional on naming a cause, never marked", k.Name, r)
		}
		if LegacyKey(k.Name) != "" || k.Identity {
			t.Errorf("%s: no v0.3 twin, no identity", k.Name)
		}
	}
	if causes != 7 {
		t.Errorf("%d cause_ref keys, want 7 (api_group, api_version, resource, namespace, name, uid, generation)", causes)
	}

	d, ok := LookupKey(KeyDenialReason)
	if !ok {
		t.Fatal("no denial_reason")
	}
	if d.OnlyWhen != CondDenied || d.Type != TypeString || len(d.Values) != 0 {
		t.Errorf("denial_reason: %+v", d)
	}
	want := map[Writer][]string{
		// v0.5.0's seven, then v0.6.0's /delegate refusals and the krateo:
		// group refusal (audit#12).
		WriterRequest: {"name_reserved", "name_claimed", "name_held_legacy", "name_provisioned", "name_bound", "system_group", "group_not_allowed",
			"delegation_not_allowed", "delegation_too_deep", "platform_group", "name_missing",
			"subject_token_expired", "subject_token_invalid", // v0.7.0 (audit#18)
			"stepup_not_enabled", "insufficient_assurance", "stale_authentication", "no_mapping", "ambiguous_mapping", "not_a_service_account", // v0.8.0 (audit#20)
			"username_check_not_allowed",         // v0.9.0 (audit#23)
			"invalid_request", "name_not_issued", // v0.10.0 (audit#29)
			// v0.12.0 (audit#22): snowplow's refusals.
			"destination_refused", "per_user_credential_ref", "endpoint_ref_malformed", "internal_identity_context",
			"write_refused", "dry_run_not_executed", "dependency_failed", "uaf_on_write_verb", "invalid_path", "template_error",
			"session_credential_missing", "step_up_required"},
		WriterController: {"kept_resource_policy"},
	}
	for _, w := range Writers() {
		r := d.Writers[w]
		if !slices.Equal(r.Values, want[w]) {
			t.Errorf("denial_reason values for %s = %v, want %v", w, r.Values, want[w])
		}
		if wantLevel := map[bool]Level{true: LevelOptional, false: LevelNotApplicable}[want[w] != nil]; r.Level != wantLevel {
			t.Errorf("denial_reason for %s = %v, want %v", w, r.Level, wantLevel)
		}
	}
	for c, v := range map[string]string{
		DenialReasonNameReserved: "name_reserved", DenialReasonNameClaimed: "name_claimed",
		DenialReasonNameHeldLegacy: "name_held_legacy", DenialReasonNameProvisioned: "name_provisioned",
		DenialReasonNameBound: "name_bound", DenialReasonSystemGroup: "system_group",
		DenialReasonGroupNotAllowed:    "group_not_allowed",
		DenialReasonKeptResourcePolicy: "kept_resource_policy",
	} {
		if c != v {
			t.Errorf("constant %q, want %q", c, v)
		}
	}

	// authn's request rows land apart from snowplow's.
	var authn []Population
	for _, p := range Populations() {
		if p.Scope == "github.com/krateo-platformops/authn/audit" || p.Scope == "github.com/krateo-platformops/authn/audit/controller" {
			authn = append(authn, p)
		}
	}
	if len(authn) != 2 || authn[0].Writer != WriterRequest || authn[1].Writer != WriterController {
		t.Errorf("authn's populations: %+v", authn)
	}

	// The per-writer values are copies, like the rest of a KeySpec.
	d.Writers[WriterController].Values[0] = "mutated"
	if again, _ := LookupKey(KeyDenialReason); again.Writers[WriterController].Values[0] != "kept_resource_policy" {
		t.Errorf("LookupKey shares a writer's values with its caller")
	}
}

// Emit writes Event.Cause as cause_ref.* and Event.DenialReason as
// denial_reason, with no v0.3 twin, and a v0.4 caller that sets neither gets
// neither.
func TestEmit_CauseAndDenialReason(t *testing.T) {
	e, rec := newEmitter(t, WithActor("system:serviceaccount:example-system:example-controller", ClassController), WithWriter(WriterController))
	e.Emit(spanCtx(t), Event{Action: "helm.uninstall", Verb: "delete", Outcome: OutcomeDenied, DenialReason: DenialReasonKeptResourcePolicy,
		Namespace: "example-ns", Version: "v1", Resource: "persistentvolumeclaims", ObjectName: "example-data", Preview: PreviewFalse,
		Cause: CauseRef{Group: "composition.krateo.io", Version: "v1-2-0", Resource: "exampleapps", Namespace: "example-ns",
			Name: "example-composition", UID: "uid-c", Generation: 5}})
	got := attrs(only(t, rec))
	for k, want := range map[string]attribute.Value{
		KeyCauseAPIGroup: attribute.StringValue("composition.krateo.io"), KeyCauseAPIVersion: attribute.StringValue("v1-2-0"),
		KeyCauseResource: attribute.StringValue("exampleapps"), KeyCauseNamespace: attribute.StringValue("example-ns"),
		KeyCauseName: attribute.StringValue("example-composition"), KeyCauseUID: attribute.StringValue("uid-c"),
		KeyCauseGeneration: attribute.Int64Value(5), KeyDenialReason: attribute.StringValue("kept_resource_policy"),
	} {
		if got[k] != want {
			t.Errorf("%s = %v, want %v", k, got[k].Emit(), want.Emit())
		}
	}
	for k := range got {
		if spec, _ := LookupKey(k); spec.ReplacedBy != "" && (spec.ReplacedBy == KeyDenialReason || strings.HasPrefix(spec.ReplacedBy, causeRefPrefix)) {
			t.Errorf("%s: a v0.3 twin of a v0.5 key", k)
		}
	}
	var kvs []attribute.KeyValue
	for k, v := range got {
		kvs = append(kvs, attribute.KeyValue{Key: attribute.Key(k), Value: v})
	}
	if vs := Check(WriterController, kvs); len(vs) > 0 {
		t.Errorf("Emit's kept deletion: %v", vs)
	}

	e2, rec2 := newEmitter(t, WithActor("system:serviceaccount:example-system:example-controller", ClassController))
	e2.Emit(spanCtx(t), Event{Action: "rest.write", Verb: "post", Outcome: OutcomeSuccess, ServerAddress: "api.example.com"})
	for k := range attrs(only(t, rec2)) {
		if k == KeyDenialReason || strings.HasPrefix(k, causeRefPrefix) {
			t.Errorf("%s written for an Event that does not set it", k)
		}
	}
}
