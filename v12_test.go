package audit

import (
	"slices"
	"testing"

	"go.opentelemetry.io/otel/attribute"
)

// v0.12.0 (audit#22): the endpointRef a stage dialled through, the request
// writer's non-resource path target, and snowplow's refusal reasons.

// stageRecord is snowplow's record of a RESTAction stage that dialled an
// external endpoint through an endpointRef: the target is server.address.
func stageRecord() []attribute.KeyValue {
	return with(without(baseRecord(WriterRequest),
		KeyNamespace, KeyObjectAPIVersion, KeyLegacyResourceVersion, KeyObjectResource, KeyLegacyResourceResource,
		KeyObjectName, KeyLegacyResourceName, KeyPreview),
		attribute.String(KeyAction, "restaction"), attribute.String(KeyVerb, "post"), attribute.String(KeyHTTPMethod, "POST"),
		attribute.String(KeyServerAddress, "api.example.com"),
		attribute.String(KeyRESTActionNamespace, "example-ns"), attribute.String(KeyRESTActionName, "example-restaction"),
		attribute.String(KeyRESTActionStage, "example-stage"),
		attribute.String(KeyEndpointRefNamespace, "example-ns"), attribute.String(KeyEndpointRefName, "example-endpoint"))
}

// pathRecord is snowplow's record of POST /debug/shadow-parity: a
// non-resource path is its target.
func pathRecord() []attribute.KeyValue {
	return with(without(baseRecord(WriterRequest),
		KeyNamespace, KeyObjectAPIVersion, KeyLegacyResourceVersion, KeyObjectResource, KeyLegacyResourceResource,
		KeyObjectName, KeyLegacyResourceName, KeyPreview, KeyHTTPStatusCode),
		attribute.String(KeyAction, "debug.shadowParity"), attribute.String(KeyVerb, "post"), attribute.String(KeyHTTPMethod, "POST"),
		attribute.String(KeyURLPath, "/debug/shadow-parity"), attribute.String(KeyRequestURI, "/debug/shadow-parity"))
}

func TestCheck_EndpointRef(t *testing.T) {
	v := func(k string, r Reason) Violation { return Violation{Key: k, Reason: r} }
	rec := stageRecord()
	for _, tc := range []struct {
		name  string
		w     Writer
		attrs []attribute.KeyValue
		want  []Violation
	}{
		{"a stage through an endpointRef", WriterRequest, rec, nil},
		{"no endpointRef: optional", WriterRequest, without(rec, KeyEndpointRefNamespace, KeyEndpointRefName), nil},
		{"on an object target", WriterRequest, with(baseRecord(WriterRequest), attribute.String(KeyEndpointRefName, "example-endpoint")),
			[]Violation{v(KeyEndpointRefName, ReasonUnexpected)}},
		{"on a path target", WriterRequest, with(pathRecord(), attribute.String(KeyEndpointRefNamespace, "example-ns")),
			[]Violation{v(KeyEndpointRefNamespace, ReasonUnexpected)}},
		// A per-user clientconfig Secret's name embeds a username: never named.
		{"a per-user clientconfig Secret", WriterRequest, with(rec, attribute.String(KeyEndpointRefName, "example-user-clientconfig")),
			[]Violation{v(KeyEndpointRefName, ReasonBadFormat)}},
		{"a per-user step-up Secret", WriterRequest, with(rec, attribute.String(KeyEndpointRefName, "example-user-clientconfig-stepup")),
			[]Violation{v(KeyEndpointRefName, ReasonBadFormat)}},
		{"a namespace that isn't one", WriterRequest, with(rec, attribute.String(KeyEndpointRefNamespace, "Example NS")),
			[]Violation{v(KeyEndpointRefNamespace, ReasonBadFormat)}},
		{"on the gateway", WriterGateway, with(baseRecord(WriterGateway), attribute.String(KeyEndpointRefName, "example-endpoint")),
			[]Violation{v(KeyEndpointRefName, ReasonNotForWriter)}},
		{"on a controller", WriterController, with(baseRecord(WriterController), attribute.String(KeyEndpointRefNamespace, "example-ns")),
			[]Violation{v(KeyEndpointRefNamespace, ReasonNotForWriter)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Check(tc.w, tc.attrs); !slices.Equal(got, tc.want) {
				t.Errorf("Check(%s):\n got %v\nwant %v", tc.w, got, tc.want)
			}
		})
	}
	for _, k := range []string{KeyEndpointRefNamespace, KeyEndpointRefName} {
		spec, _ := LookupKey(k)
		if spec.OnlyWhen != CondEndpointTarget || !spec.CredentialFree || spec.Writers[WriterRequest].Level != LevelOptional {
			t.Errorf("%s: only_when %q, credential_free %v, request level %s", k, spec.OnlyWhen, spec.CredentialFree, spec.Writers[WriterRequest].Level)
		}
	}
}

// url.path is the request writer's third target form: exactly one of
// object_ref, server.address and url.path. Other writers keep their two.
func TestCheck_URLPathTarget(t *testing.T) {
	v := func(k string, r Reason) Violation { return Violation{Key: k, Reason: r} }
	path := pathRecord()
	for _, tc := range []struct {
		name  string
		w     Writer
		attrs []attribute.KeyValue
		want  []Violation
	}{
		{"a non-resource path", WriterRequest, path, nil},
		{"beside an object", WriterRequest, with(baseRecord(WriterRequest), attribute.String(KeyURLPath, "/debug/shadow-parity")),
			[]Violation{v(RuleTarget, ReasonTwoTargets)}},
		{"beside an endpoint", WriterRequest, with(stageRecord(), attribute.String(KeyURLPath, "/debug/shadow-parity")),
			[]Violation{v(RuleTarget, ReasonTwoTargets)}},
		{"no target", WriterRequest, without(path, KeyURLPath), []Violation{v(RuleTarget, ReasonMissing)}},
		{"no target, marked", WriterRequest, with(without(path, KeyURLPath), attribute.String(KeyIncomplete, "target")),
			[]Violation{v(RuleTarget, ReasonIncomplete)}},
		{"a path marked as missing", WriterRequest, with(path, attribute.String(KeyIncomplete, "target")),
			[]Violation{v(RuleTarget, ReasonMarkedButPresent)}},
		{"a path with a query", WriterRequest, with(path, attribute.String(KeyURLPath, "/debug/shadow-parity?token=x")),
			[]Violation{v(KeyURLPath, ReasonBadFormat)}},
		// The gateway has no path target: the key isn't its, and its record
		// still needs one of its own two.
		{"a path on the gateway", WriterGateway, with(without(baseRecord(WriterGateway), KeyServerAddress), attribute.String(KeyURLPath, "/x")),
			[]Violation{v(KeyURLPath, ReasonNotForWriter), v(KeyServerAddress, ReasonMissing), v(RuleTarget, ReasonMissing)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Check(tc.w, tc.attrs); !slices.Equal(got, tc.want) {
				t.Errorf("Check(%s):\n got %v\nwant %v", tc.w, got, tc.want)
			}
		})
	}
	tr := Target()
	if !slices.Equal(tr.KeysFor(WriterRequest), []string{KeyObjectResource, KeyServerAddress, KeyURLPath}) {
		t.Errorf("request target keys = %v", tr.KeysFor(WriterRequest))
	}
	for _, w := range []Writer{WriterGateway, WriterAction, WriterController} {
		if !slices.Equal(tr.KeysFor(w), []string{KeyObjectResource, KeyServerAddress}) {
			t.Errorf("%s target keys = %v", w, tr.KeysFor(w))
		}
	}
	tr.WriterKeys[WriterRequest][0] = "changed"
	if Target().KeysFor(WriterRequest)[2] != KeyURLPath {
		t.Error("Target hands out its own WriterKeys: a caller's change reaches the rule")
	}
	// The marker logic: a path is a target for the request writer, so its
	// record is not marked target; with no writer declared, the gap is the
	// one every writer shares, and a path is a request writer's target.
	if m := missingMarkers([]Writer{WriterRequest}, path); slices.Contains(m, "target") {
		t.Errorf("a path record marked target: %v", m)
	}
	if m := missingMarkers([]Writer{WriterGateway}, []attribute.KeyValue{attribute.String(KeyURLPath, "/x")}); !slices.Contains(m, "target") {
		t.Errorf("a gateway record with only a path is not marked target: %v", m)
	}
	// An undeclared Emitter marks what every writer lacks: a path is the
	// request writer's target, so it is no gap, whichever writer comes first.
	for _, ws := range [][]Writer{schemaWriters, {WriterGateway, WriterRequest}, {WriterController, WriterAction, WriterRequest}} {
		if m := missingMarkers(ws, path); slices.Contains(m, "target") {
			t.Errorf("writers %v: a path record marked target: %v", ws, m)
		}
	}
}

// snowplow's refusals (audit#22): the request writer's, each a denied record
// with no status code.
var snowplowRefusals = []string{
	DenialReasonDestinationRefused, DenialReasonPerUserCredentialRef, DenialReasonEndpointRefMalformed, DenialReasonInternalIdentityContext,
	DenialReasonWriteRefused, DenialReasonDryRunNotExecuted, DenialReasonDependencyFailed, DenialReasonUafOnWriteVerb,
	DenialReasonInvalidPath, DenialReasonTemplateError, DenialReasonSessionCredentialMissing, DenialReasonStepUpRequired,
}

func TestCheck_SnowplowRefusals(t *testing.T) {
	v := func(k string, r Reason) Violation { return Violation{Key: k, Reason: r} }
	// The refusals before the endpoint is resolved may know no address:
	// the record marks target.
	beforeResolution := []string{DenialReasonPerUserCredentialRef, DenialReasonEndpointRefMalformed, DenialReasonInternalIdentityContext,
		DenialReasonInvalidPath, DenialReasonTemplateError}
	for _, r := range snowplowRefusals {
		refused := with(deniedRecord(stageRecord()), attribute.String(KeyDenialReason, r))
		cases := []struct {
			name  string
			w     Writer
			attrs []attribute.KeyValue
			want  []Violation
		}{
			{"on a stage record", WriterRequest, refused, nil},
			{"with a status code", WriterRequest, with(refused, attribute.Int(KeyHTTPStatusCode, 403)), []Violation{v(KeyHTTPStatusCode, ReasonUnexpected)}},
			{"on a failure", WriterRequest, with(refused, attribute.String(KeyOutcome, OutcomeFailure), attribute.String(KeyLegacyOutcome, OutcomeFailure)),
				[]Violation{v(KeyDenialReason, ReasonUnexpected)}},
			{"on a controller", WriterController, with(deniedRecord(baseRecord(WriterController)), attribute.String(KeyDenialReason, r)),
				[]Violation{v(KeyDenialReason, ReasonBadEnum)}},
			{"on the gateway", WriterGateway, with(deniedRecord(baseRecord(WriterGateway)), attribute.String(KeyDenialReason, r)),
				[]Violation{v(KeyDenialReason, ReasonNotForWriter)}},
		}
		if slices.Contains(beforeResolution, r) {
			unresolved := with(without(refused, KeyServerAddress, KeyEndpointRefNamespace, KeyEndpointRefName), attribute.String(KeyIncomplete, "target"))
			cases = append(cases, struct {
				name  string
				w     Writer
				attrs []attribute.KeyValue
				want  []Violation
			}{"before resolution, no address: target marked", WriterRequest, unresolved, []Violation{v(RuleTarget, ReasonIncomplete)}})
		}
		for _, tc := range cases {
			t.Run(r+": "+tc.name, func(t *testing.T) {
				if got := Check(tc.w, tc.attrs); !slices.Equal(got, tc.want) {
					t.Errorf("Check(%s):\n got %v\nwant %v", tc.w, got, tc.want)
				}
			})
		}
	}
	// per_user_credential_ref never names the Secret it refused.
	perUser := with(deniedRecord(stageRecord()), attribute.String(KeyDenialReason, DenialReasonPerUserCredentialRef),
		attribute.String(KeyEndpointRefName, "example-user-clientconfig"))
	if got := Check(WriterRequest, perUser); !slices.Equal(got, []Violation{v(KeyEndpointRefName, ReasonBadFormat)}) {
		t.Errorf("per_user_credential_ref naming the per-user Secret: %v", got)
	}

	// By hand: the twelve values, the request writer's only.
	want := []string{"destination_refused", "per_user_credential_ref", "endpoint_ref_malformed", "internal_identity_context",
		"write_refused", "dry_run_not_executed", "dependency_failed", "uaf_on_write_verb", "invalid_path", "template_error",
		"session_credential_missing", "step_up_required"}
	if !slices.Equal(snowplowRefusals, want) {
		t.Errorf("constants %v, want %v", snowplowRefusals, want)
	}
	d, _ := LookupKey(KeyDenialReason)
	for _, r := range want {
		if !slices.Contains(d.Writers[WriterRequest].Values, r) || slices.Contains(d.Writers[WriterController].Values, r) {
			t.Errorf("%s: the request writer's value only", r)
		}
	}
}

// Emit writes the endpointRef and the path, and never a per-user Secret's
// name; its records pass Check.
func TestEmit_EndpointRefAndURLPath(t *testing.T) {
	stage := Event{UserName: "example-user", ActorClass: ClassHuman, Action: "restaction", Verb: "post", HTTPMethod: "POST", StatusCode: 201,
		Outcome: OutcomeSuccess, ServerAddress: "api.example.com", RESTActionNamespace: "example-ns", RESTActionName: "example-restaction",
		RESTActionStage: "example-stage", EndpointRefNamespace: "example-ns", EndpointRefName: "example-endpoint",
		RequestURI: "/call", SourceIPs: []string{"192.0.2.10"}}
	e, rec := newEmitter(t, WithWriter(WriterRequest))
	e.Emit(WithSessionIDForTest(t, spanCtx(t), "s1"), stage)
	got := attrs(only(t, rec))
	if got[KeyEndpointRefNamespace] != attribute.StringValue("example-ns") || got[KeyEndpointRefName] != attribute.StringValue("example-endpoint") {
		t.Errorf("endpoint_ref = %v / %v", got[KeyEndpointRefNamespace].Emit(), got[KeyEndpointRefName].Emit())
	}
	if vs := Check(WriterRequest, kvs(got)); len(vs) > 0 {
		t.Errorf("stage record: %v", vs)
	}

	for _, name := range []string{"example-user-clientconfig", "example-user-clientconfig-stepup", "Not-A-Name"} {
		perUser := stage
		perUser.EndpointRefName = name
		e, rec := newEmitter(t, WithWriter(WriterRequest))
		e.Emit(WithSessionIDForTest(t, spanCtx(t), "s1"), perUser)
		got := attrs(only(t, rec))
		if _, here := got[KeyEndpointRefName]; here {
			t.Errorf("Emit wrote endpoint_ref.name %q", name)
		}
		if vs := Check(WriterRequest, kvs(got)); len(vs) > 0 {
			t.Errorf("%q: %v", name, vs)
		}
	}

	e, rec = newEmitter(t, WithWriter(WriterRequest))
	e.Emit(WithSessionIDForTest(t, spanCtx(t), "s1"), Event{UserName: "example-user", ActorClass: ClassHuman,
		Action: "debug.shadowParity", Verb: "post", HTTPMethod: "POST", Outcome: OutcomeSuccess,
		URLPath: "/debug/shadow-parity", RequestURI: "/debug/shadow-parity", SourceIPs: []string{"192.0.2.10"}})
	got = attrs(only(t, rec))
	if got[KeyURLPath] != attribute.StringValue("/debug/shadow-parity") {
		t.Errorf("url.path = %v", got[KeyURLPath].Emit())
	}
	if vs := Check(WriterRequest, kvs(got)); len(vs) > 0 {
		t.Errorf("shadow-parity record: %v", vs)
	}
}
