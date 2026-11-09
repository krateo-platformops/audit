package audit

import (
	"slices"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
)

// A conformant record per writer, built by hand from the schema's rules (not
// by Emit), so Check is tested against a record it did not help make.
func baseRecord(w Writer) []attribute.KeyValue {
	common := []attribute.KeyValue{
		attribute.String(KeyEventName, "audit"),
		attribute.String(KeySchemaVersion, "1"),
		attribute.String(KeyOutcome, "success"),
		attribute.String(KeyLegacyOutcome, "success"),
	}
	switch w {
	case WriterRequest:
		return append(common,
			attribute.String(KeyUserName, "alice"), attribute.String(KeyLegacyEndUserID, "alice"),
			attribute.StringSlice(KeyUserRoles, []string{"devs"}),
			attribute.String(KeyActorClass, "human"),
			attribute.String(KeyAction, "call"), attribute.String(KeyVerb, "create"),
			attribute.String(KeyHTTPMethod, "POST"), attribute.Int(KeyHTTPStatusCode, 201),
			attribute.String(KeyRequestURI, "/call?name=cm"), attribute.StringSlice(KeySourceIPs, []string{"10.0.0.1"}),
			attribute.String(KeySessionID, "s1"),
			attribute.String(KeyNamespace, "tenant-a"),
			attribute.String(KeyObjectAPIVersion, "v1"), attribute.String(KeyLegacyResourceVersion, "v1"),
			attribute.String(KeyObjectResource, "configmaps"), attribute.String(KeyLegacyResourceResource, "configmaps"),
			attribute.String(KeyObjectName, "cm"), attribute.String(KeyLegacyResourceName, "cm"),
			attribute.Bool(KeyPreview, false),
		)
	case WriterGateway:
		return append(common,
			attribute.String(KeyUserName, "alice"), attribute.String(KeyLegacyEndUserID, "alice"),
			attribute.String(KeyActorClass, "human"),
			attribute.String(KeyAction, "gateway.mcp"), attribute.String(KeyVerb, "post"),
			attribute.String(KeyHTTPMethod, "POST"),
			attribute.String(KeyServerAddress, "mcp.example.com:8443"),
			attribute.StringSlice(KeySourceIPs, []string{"10.0.0.1"}),
			attribute.String(KeyGatewayRoute, "agents/mcp"),
			attribute.String(KeyAssertedAgentHost, "kagent-a"),
		)
	default: // action, controller
		return append(common,
			attribute.String(KeyUserName, "system:serviceaccount:krateo-system:rdc"),
			attribute.String(KeyLegacyEndUserID, "system:serviceaccount:krateo-system:rdc"),
			attribute.String(KeyActorClass, "controller"),
			attribute.String(KeyAction, "rest.write"), attribute.String(KeyVerb, "post"),
			attribute.String(KeyServerAddress, "api.example.com"),
		)
	}
}

func without(attrs []attribute.KeyValue, keys ...string) []attribute.KeyValue {
	return slices.DeleteFunc(slices.Clone(attrs), func(kv attribute.KeyValue) bool {
		return slices.Contains(keys, string(kv.Key))
	})
}

func with(attrs []attribute.KeyValue, kvs ...attribute.KeyValue) []attribute.KeyValue {
	out := slices.Clone(attrs)
	for _, kv := range kvs {
		out = without(out, string(kv.Key))
		out = append(out, kv)
	}
	return out
}

func TestCheck_BaseRecordsConform(t *testing.T) {
	for _, w := range Writers() {
		if vs := Check(w, baseRecord(w)); len(vs) > 0 {
			t.Errorf("%s base record: %v", w, vs)
		}
	}
}

func TestCheck_Violations(t *testing.T) {
	v := func(k string, r Reason) Violation { return Violation{Key: k, Reason: r} }
	ctrl := baseRecord(WriterController)
	req := baseRecord(WriterRequest)
	gw := baseRecord(WriterGateway)
	k8sCtrl := with(without(ctrl, KeyServerAddress),
		attribute.String(KeyNamespace, "tenant-a"),
		attribute.String(KeyObjectAPIVersion, "v1"), attribute.String(KeyLegacyResourceVersion, "v1"),
		attribute.String(KeyObjectResource, "configmaps"), attribute.String(KeyLegacyResourceResource, "configmaps"),
		attribute.Bool(KeyPreview, false))

	for _, tc := range []struct {
		name  string
		w     Writer
		attrs []attribute.KeyValue
		want  []Violation
	}{
		{"required key missing", WriterController, without(ctrl, KeyUserName, KeyLegacyEndUserID), []Violation{v(KeyUserName, ReasonMissing)}},
		{"required key marked", WriterController, with(without(ctrl, KeyVerb), attribute.String(KeyIncomplete, "verb")), []Violation{v(KeyVerb, ReasonIncomplete)}},
		{"unknown krateo.audit key", WriterController, with(ctrl, attribute.String("krateo.audit.bogus", "x")), []Violation{v("krateo.audit.bogus", ReasonNotInSchema)}},
		{"any unknown key: the closed set", WriterController, with(ctrl, attribute.String("foo", "x")), []Violation{v("foo", ReasonNotInSchema)}},
		{"gateway writes an object it cannot see", WriterGateway, with(gw, attribute.String(KeyObjectResource, "pods")), []Violation{v(KeyObjectResource, ReasonNotForWriter), v(RuleTarget, ReasonTwoTargets)}},
		{"controller writes a request URI", WriterController, with(ctrl, attribute.String(KeyRequestURI, "/x")), []Violation{v(KeyRequestURI, ReasonNotForWriter)}},
		{"bool as a string", WriterRequest, with(req, attribute.String(KeyPreview, "false")), []Violation{v(KeyPreview, ReasonBadType)}},
		{"int as a string", WriterRequest, with(req, attribute.String(KeyHTTPStatusCode, "201")), []Violation{v(KeyHTTPStatusCode, ReasonBadType)}},
		{"string list as a string", WriterRequest, with(req, attribute.String(KeyUserRoles, "devs")), []Violation{v(KeyUserRoles, ReasonBadType)}},
		{"string list as a SLICE of strings", WriterRequest, with(req, attribute.Slice(KeyUserRoles, attribute.StringValue("devs"))), nil},
		{"verb as a method", WriterController, with(ctrl, attribute.String(KeyVerb, "POST")), []Violation{v(KeyVerb, ReasonBadEnum)}},
		{"actor class out of the claim's set", WriterController, with(ctrl, attribute.String(KeyActorClass, "robot")), []Violation{v(KeyActorClass, ReasonBadEnum)}},
		{"method semconv does not name", WriterRequest, with(req, attribute.String(KeyHTTPMethod, "post")), []Violation{v(KeyHTTPMethod, ReasonBadEnum)}},
		{"delegation link without a class separator", WriterRequest, with(req, attribute.StringSlice(KeyDelegation, []string{"svc-bot"}), attribute.String(KeyOnBehalfOf, "alice")), []Violation{v(KeyDelegation, ReasonBadFormat)}},
		{"delegation link with an unknown class", WriterRequest, with(req, attribute.StringSlice(KeyDelegation, []string{"robot:svc-bot"}), attribute.String(KeyOnBehalfOf, "alice")), []Violation{v(KeyDelegation, ReasonBadFormat)}},
		{"delegation link with no class", WriterRequest, with(req, attribute.StringSlice(KeyDelegation, []string{":svc-bot", "human:alice"}), attribute.String(KeyOnBehalfOf, "alice")), nil},
		{"unknown marker", WriterController, with(ctrl, attribute.String(KeyIncomplete, "nope")), []Violation{v(KeyIncomplete, ReasonBadFormat)}},
		{"repeated marker", WriterController, with(without(ctrl, KeyVerb), attribute.String(KeyIncomplete, "verb,verb")), []Violation{v(KeyIncomplete, ReasonBadFormat), v(KeyVerb, ReasonIncomplete)}},
		{"marked but present", WriterController, with(ctrl, attribute.String(KeyIncomplete, "verb")), []Violation{v(KeyVerb, ReasonMarkedButPresent)}},
		{"target marked but present", WriterController, with(ctrl, attribute.String(KeyIncomplete, "target")), []Violation{v(RuleTarget, ReasonMarkedButPresent)}},
		{"empty value", WriterController, with(ctrl, attribute.String(KeyAction, "")), []Violation{v(KeyAction, ReasonEmpty)}},
		{"empty list", WriterRequest, with(req, attribute.StringSlice(KeyUserRoles, nil)), []Violation{v(KeyUserRoles, ReasonEmpty)}},
		{"invalid UTF-8 value", WriterController, with(ctrl, attribute.String(KeyAction, "rest.\xff")), []Violation{v(KeyAction, ReasonInvalidUTF8)}},
		{"invalid UTF-8 key", WriterController, with(ctrl, attribute.String("bad-\xff", "x")), []Violation{v("bad-�", ReasonInvalidUTF8)}},
		{"duplicate key", WriterController, append(slices.Clone(ctrl), attribute.String(KeyAction, "again")), []Violation{v(KeyAction, ReasonDuplicate)}},
		{"two targets for a request", WriterRequest, with(req, attribute.String(KeyServerAddress, "api.example.com")), []Violation{v(RuleTarget, ReasonTwoTargets)}},
		{"a controller names its object and its endpoint", WriterController, with(k8sCtrl, attribute.String(KeyServerAddress, "api.example.com")), nil},
		{"no target", WriterController, without(ctrl, KeyServerAddress), []Violation{v(RuleTarget, ReasonMissing)}},
		{"no target, marked", WriterController, with(without(ctrl, KeyServerAddress), attribute.String(KeyIncomplete, "target")), []Violation{v(RuleTarget, ReasonIncomplete)}},
		{"gap d: kind without resource", WriterController, with(without(k8sCtrl, KeyObjectResource, KeyLegacyResourceResource), attribute.String(KeyObjectKind, "Repo"), attribute.String(KeyLegacyResourceKind, "Repo"), attribute.String(KeyServerAddress, "api.example.com")),
			[]Violation{v(KeyObjectResource, ReasonMissing)}},
		{"namespaced target without preview", WriterController, without(k8sCtrl, KeyPreview), []Violation{v(KeyPreview, ReasonMissing)}},
		{"namespaced target, preview marked", WriterController, with(without(k8sCtrl, KeyPreview), attribute.String(KeyIncomplete, "preview")), []Violation{v(KeyPreview, ReasonIncomplete)}},
		// installer#716 §2.4: preview is false for a cluster-scoped target, and required there too.
		{"cluster-scoped target without preview", WriterController, without(k8sCtrl, KeyNamespace, KeyPreview), []Violation{v(KeyPreview, ReasonMissing)}},
		{"cluster-scoped target, preview false", WriterController, without(k8sCtrl, KeyNamespace), nil},
		{"external endpoint alone needs no preview", WriterController, ctrl, nil},
		// semconv: a method recorded as _OTHER carries the method as given.
		{"_OTHER without the method as given", WriterRequest, with(req, attribute.String(KeyHTTPMethod, "_OTHER")), []Violation{v(KeyHTTPMethodOriginal, ReasonMissing)}},
		{"_OTHER with the method as given", WriterRequest, with(req, attribute.String(KeyHTTPMethod, "_OTHER"), attribute.String(KeyHTTPMethodOriginal, "post")), nil},
		// method_original only when the method is _OTHER (schema only_when: method_other).
		{"method_original beside a method semconv names", WriterRequest, with(req, attribute.String(KeyHTTPMethodOriginal, "POST")), []Violation{v(KeyHTTPMethodOriginal, ReasonUnexpected)}},
		{"method_original beside a canonicalised method", WriterRequest, with(req, attribute.String(KeyHTTPMethodOriginal, "post")), []Violation{v(KeyHTTPMethodOriginal, ReasonUnexpected)}},
		{"method_original with no method at all", WriterController, with(ctrl, attribute.String(KeyHTTPMethodOriginal, "post")), []Violation{v(KeyHTTPMethodOriginal, ReasonUnexpected)}},
		{"actor class missing for a controller is not excused by a mark", WriterController, with(without(ctrl, KeyActorClass), attribute.String(KeyIncomplete, "actor_class")), []Violation{v(KeyActorClass, ReasonMissing)}},
		{"actor class missing for a request must be marked", WriterRequest, without(req, KeyActorClass), []Violation{v(KeyActorClass, ReasonMissing)}},
		{"actor class marked for a request", WriterRequest, with(without(req, KeyActorClass), attribute.String(KeyIncomplete, "actor_class")), []Violation{v(KeyActorClass, ReasonIncomplete)}},
		{"on_behalf_of without the chain", WriterRequest, with(req, attribute.String(KeyOnBehalfOf, "alice")), []Violation{v(KeyDelegation, ReasonMissing)}},
		{"impersonated roles without the user", WriterController, with(ctrl, attribute.StringSlice(KeyImpersonatedRoles, []string{"g"})), []Violation{v(KeyImpersonatedUser, ReasonMissing)}},
		{"W1: v0.3 key without its replacement", WriterController, without(ctrl, KeyOutcome), []Violation{v(KeyOutcome, ReasonMissing), v(KeyLegacyOutcome, ReasonLegacyWithoutReplacement)}},
		{"W1: v0.3 key disagrees", WriterController, with(ctrl, attribute.String(KeyLegacyOutcome, "failure")), []Violation{v(KeyLegacyOutcome, ReasonLegacyDisagrees)}},
		{"W1: enduser.id is not the actor", WriterController, with(ctrl, attribute.String(KeyLegacyEndUserID, "alice")), []Violation{v(KeyLegacyEndUserID, ReasonLegacyDisagrees)}},
		{"W1: v0.3 key of the wrong type", WriterController, with(k8sCtrl, attribute.Int64(KeyObjectGeneration, 3), attribute.String(KeyLegacyObjectGeneration, "3")), []Violation{v(KeyLegacyObjectGeneration, ReasonBadType), v(KeyLegacyObjectGeneration, ReasonLegacyDisagrees)}},
		{"gap b: the affected user is the actor", WriterController, with(ctrl, attribute.String(KeyAffectedUser, "system:serviceaccount:krateo-system:rdc")), []Violation{v(KeyAffectedUser, ReasonAffectedUserIsActor)}},
		{"gap b: the affected user is someone else", WriterController, with(ctrl, attribute.String(KeyAffectedUser, "alice")), nil},
		{"unknown writer", Writer("human"), ctrl, []Violation{{Reason: ReasonUnknownWriter}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Check(tc.w, tc.attrs); !slices.Equal(got, tc.want) {
				t.Errorf("Check(%s):\n got %v\nwant %v", tc.w, got, tc.want)
			}
		})
	}
}

func TestCheckRecord_EventName(t *testing.T) {
	ctrl := baseRecord(WriterController)
	if vs := CheckRecord(WriterController, "audit", ctrl); len(vs) > 0 {
		t.Errorf("conformant record: %v", vs)
	}
	for _, name := range []string{"", "request"} {
		vs := CheckRecord(WriterController, name, ctrl)
		if !slices.Equal(vs, []Violation{{Key: KeyLogRecordEventName, Reason: ReasonBadEventName}}) {
			t.Errorf("EventName %q: %v", name, vs)
		}
	}
}

// A violation names a key and a reason, never a value: audit values carry
// identity, and violations end up in test output and CI logs.
func TestCheck_ViolationsNeverCarryAValue(t *testing.T) {
	const secret = "alice.identity.marker"
	attrs := []attribute.KeyValue{
		attribute.String(KeyUserName, secret),
		attribute.String(KeyAffectedUser, secret),
		attribute.String(KeyVerb, secret),
		attribute.String("unknown."+"key", secret),
		attribute.String(KeyIncomplete, secret),
		attribute.StringSlice(KeyDelegation, []string{secret}),
	}
	for _, w := range Writers() {
		for _, v := range CheckRecord(w, secret, attrs) {
			if strings.Contains(v.String(), secret) {
				t.Errorf("%s: violation %q carries a value", w, v)
			}
		}
	}
}

func TestRequiredKeys_FollowTheRecord(t *testing.T) {
	ctrl := baseRecord(WriterController)
	if got := RequiredKeys(WriterController, ctrl); slices.Contains(got, KeyObjectResource) {
		t.Errorf("an endpoint-only record does not need object_ref.resource: %v", got)
	}
	k8s := with(ctrl, attribute.String(KeyObjectKind, "Repo"))
	if got := RequiredKeys(WriterController, k8s); !slices.Contains(got, KeyObjectResource) || !slices.Contains(got, KeyObjectAPIVersion) {
		t.Errorf("a record naming an object needs its resource and version: %v", got)
	}
}

func TestMissingMarkers(t *testing.T) {
	bare := []attribute.KeyValue{attribute.String(KeyUserName, "u")}
	// No writer declared: a gap is marked when every writer that can write the
	// key must. http.request.method is required of request and gateway
	// writers only, so it is not marked; preview is not established by the
	// gateway, so it is marked for any Kubernetes object.
	k8s := append(slices.Clone(bare), attribute.String(KeyNamespace, "ns"), attribute.String(KeyObjectResource, "pods"))
	if got, want := missingMarkers(schemaWriters, k8s), []string{"actor_class", "action", "verb", "preview"}; !slices.Equal(got, want) {
		t.Errorf("no writer: %v, want %v", got, want)
	}
	cluster := append(slices.Clone(bare), attribute.String(KeyObjectAPIVersion, "v1"), attribute.String(KeyObjectResource, "clusterrolebindings"))
	if got, want := missingMarkers(schemaWriters, cluster), []string{"actor_class", "action", "verb", "preview"}; !slices.Equal(got, want) {
		t.Errorf("cluster-scoped object: %v, want %v (preview is required there too)", got, want)
	}
	if got, want := missingMarkers([]Writer{WriterRequest}, k8s), []string{"actor_class", "action", "verb", "method", "preview"}; !slices.Equal(got, want) {
		t.Errorf("request writer: %v, want %v", got, want)
	}
	if got, want := missingMarkers(schemaWriters, bare), []string{"actor_class", "action", "verb", "target"}; !slices.Equal(got, want) {
		t.Errorf("no target: %v, want %v", got, want)
	}
}
