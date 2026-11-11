package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
)

// The v0.6.0 additions (audit#12, audit#13): no status code on a denied
// record, a content hash never on a credential target, the client-asserted
// provenance keys, three request denial reasons, and the per-module scopes of
// access-review and identity-lifecycle.

const (
	exampleSHA     = "2bbf0a0f3ccc266c6ee429376afbd9a20714a80d5b03a753bbb29ec8c1fee232"
	exampleSetSHA  = "0a08bb91090b111f15a045b6061bccc4d0b8488d85f99ba57d8632e17061c277"
	exampleConfirm = "00000000-0000-4000-8000-0000000000aa"
)

// portalProvenance is an accepted header's keys, as snowplow writes them.
var portalProvenance = []attribute.KeyValue{
	attribute.String(KeyClientSource, ClientSourcePortal),
	attribute.String(KeyClientAgentSessionID, "example-agent-session"),
	attribute.String(KeyClientConfirmationID, exampleConfirm),
	attribute.Int64(KeyClientConfirmedSetCount, 3),
	attribute.Bool(KeyClientConfirmedSetIrreversible, true),
	attribute.String(KeyClientConfirmedSetSHA256, exampleSetSHA),
	attribute.Int64(KeyClientConfirmedSetOp, 2),
	attribute.String(KeyClientRequestedAt, "2026-11-11T10:00:00.123Z"),
}

// onObject is attrs with its target replaced by the object (group, resource,
// subresource).
func onObject(attrs []attribute.KeyValue, group, resource, subresource string) []attribute.KeyValue {
	out := with(without(attrs, KeyObjectAPIGroup, KeyLegacyResourceGroup, KeyObjectSubresource, KeyLegacyResourceSubresource),
		attribute.String(KeyObjectResource, resource), attribute.String(KeyLegacyResourceResource, resource))
	if group != "" {
		out = with(out, attribute.String(KeyObjectAPIGroup, group), attribute.String(KeyLegacyResourceGroup, group))
	}
	if subresource != "" {
		out = with(out, attribute.String(KeyObjectSubresource, subresource), attribute.String(KeyLegacyResourceSubresource, subresource))
	}
	return out
}

func withVerb(attrs []attribute.KeyValue, verb string) []attribute.KeyValue {
	return with(attrs, attribute.String(KeyVerb, verb))
}

func TestCheck_V060Rules(t *testing.T) {
	v := func(k string, r Reason) Violation { return Violation{Key: k, Reason: r} }
	req := baseRecord(WriterRequest) // a configmaps create, status 201
	gw := baseRecord(WriterGateway)
	act := baseRecord(WriterAction)
	ctrl := baseRecord(WriterController)
	hashed := with(req, attribute.String(KeyObjectContentSHA256, exampleSHA))
	portal := with(req, portalProvenance...)
	rejected := with(req, attribute.String(KeyClientRejected, ClientRejectedSchema))
	authnRefused := deniedRecord(req)

	cases := []struct {
		name  string
		w     Writer
		attrs []attribute.KeyValue
		want  []Violation
	}{
		// audit#13: denied means the writer refused, so no authority answered.
		{"request: status code on a denied record", WriterRequest, with(authnRefused, attribute.Int(KeyHTTPStatusCode, 403)), []Violation{v(KeyHTTPStatusCode, ReasonUnexpected)}},
		{"gateway: status code on a denied record", WriterGateway, with(deniedRecord(gw), attribute.Int(KeyHTTPStatusCode, 403)), []Violation{v(KeyHTTPStatusCode, ReasonUnexpected)}},
		{"action: status code on a denied record", WriterAction, with(deniedRecord(act), attribute.Int(KeyHTTPStatusCode, 403)), []Violation{v(KeyHTTPStatusCode, ReasonUnexpected)}},
		{"controller: status code on a kept deletion", WriterController, with(deniedRecord(ctrl), attribute.Int(KeyHTTPStatusCode, 200)), []Violation{v(KeyHTTPStatusCode, ReasonUnexpected)}},
		{"a denied record without a status code", WriterRequest, authnRefused, nil},
		{"a status code on a success", WriterRequest, req, nil},
		{"a status code on a failure", WriterRequest, with(req, attribute.String(KeyOutcome, OutcomeFailure), attribute.String(KeyLegacyOutcome, OutcomeFailure), attribute.Int(KeyHTTPStatusCode, 409)), nil},

		// Three new request denial reasons; each writer keeps its own set.
		{"authn: delegation not allowed", WriterRequest, with(authnRefused, attribute.String(KeyDenialReason, DenialReasonDelegationNotAllowed)), nil},
		{"authn: delegation too deep", WriterRequest, with(authnRefused, attribute.String(KeyDenialReason, DenialReasonDelegationTooDeep)), nil},
		{"authn: an IdP asserted a krateo: group", WriterRequest, with(authnRefused, attribute.String(KeyDenialReason, DenialReasonPlatformGroup)), nil},
		{"an unknown request reason", WriterRequest, with(authnRefused, attribute.String(KeyDenialReason, "krateo_group")), []Violation{v(KeyDenialReason, ReasonBadEnum)}},
		{"a delegation reason on a controller", WriterController, with(deniedRecord(ctrl), attribute.String(KeyDenialReason, DenialReasonDelegationTooDeep)), []Violation{v(KeyDenialReason, ReasonBadEnum)}},
		{"platform_group on a success", WriterRequest, with(req, attribute.String(KeyDenialReason, DenialReasonPlatformGroup)), []Violation{v(KeyDenialReason, ReasonUnexpected)}},

		// content_sha256: create or update of a non-credential object only.
		{"content hash on a create", WriterRequest, hashed, nil},
		{"content hash on an update", WriterRequest, withVerb(hashed, "update"), nil},
		{"content hash on a dry-run create", WriterRequest, with(hashed, attribute.Bool(KeyDryRun, true)), nil},
		{"content hash on a controller's evidence create", WriterController, with(onObject(with(without(ctrl, KeyServerAddress), attribute.String(KeyNamespace, "ns"), attribute.String(KeyObjectAPIVersion, "v1"), attribute.String(KeyLegacyResourceVersion, "v1"), attribute.Bool(KeyPreview, false)), "", "configmaps", ""),
			attribute.String(KeyVerb, "create"), attribute.String(KeyObjectContentSHA256, exampleSHA)), nil},
		{"content hash on a patch", WriterRequest, withVerb(hashed, "patch"), []Violation{v(KeyObjectContentSHA256, ReasonUnexpected)}},
		{"content hash on a delete", WriterRequest, withVerb(hashed, "delete"), []Violation{v(KeyObjectContentSHA256, ReasonUnexpected)}},
		{"content hash on a read", WriterRequest, without(withVerb(hashed, "get"), KeyDryRun), []Violation{v(KeyObjectContentSHA256, ReasonUnexpected)}},
		{"content hash of a Secret", WriterRequest, onObject(hashed, "", "secrets", ""), []Violation{v(KeyObjectContentSHA256, ReasonNotForTarget)}},
		{"content hash of a Secret's subresource", WriterRequest, onObject(hashed, "", "secrets", "status"), []Violation{v(KeyObjectContentSHA256, ReasonNotForTarget)}},
		{"content hash of a token request", WriterRequest, onObject(hashed, "", "serviceaccounts", "token"), []Violation{v(KeyObjectContentSHA256, ReasonNotForTarget)}},
		{"content hash of a ServiceAccount itself", WriterRequest, onObject(hashed, "", "serviceaccounts", ""), nil},
		{"content hash of a CRD named secrets", WriterRequest, onObject(hashed, "example.krateo.io", "secrets", ""), nil},
		{"content hash of a Secret, read", WriterRequest, without(withVerb(onObject(hashed, "", "secrets", ""), "get"), KeyDryRun),
			[]Violation{v(KeyObjectContentSHA256, ReasonUnexpected), v(KeyObjectContentSHA256, ReasonNotForTarget)}},
		{"content hash in upper case", WriterRequest, with(hashed, attribute.String(KeyObjectContentSHA256, strings.ToUpper(exampleSHA))), []Violation{v(KeyObjectContentSHA256, ReasonBadFormat)}},
		{"content hash too short", WriterRequest, with(hashed, attribute.String(KeyObjectContentSHA256, exampleSHA[:63])), []Violation{v(KeyObjectContentSHA256, ReasonBadFormat)}},
		{"content hash on the gateway", WriterGateway, with(withVerb(gw, "create"), attribute.String(KeyObjectContentSHA256, exampleSHA)), []Violation{v(KeyObjectContentSHA256, ReasonNotForWriter)}},

		// The client-asserted provenance.
		{"the portal's provenance on a write", WriterRequest, portal, nil},
		{"the portal's provenance on an action writer's write", WriterAction, with(act, portalProvenance...), nil},
		{"a header with no confirmed set", WriterRequest, without(portal, KeyClientConfirmedSetCount, KeyClientConfirmedSetIrreversible, KeyClientConfirmedSetSHA256, KeyClientConfirmedSetOp), nil},
		{"source alone", WriterRequest, with(req, attribute.String(KeyClientSource, ClientSourcePortal)), nil},
		{"provenance without its source", WriterRequest, without(portal, KeyClientSource), []Violation{v(KeyClientSource, ReasonMissing)}},
		{"a confirmed set without its hash", WriterRequest, without(portal, KeyClientConfirmedSetSHA256), []Violation{v(KeyClientConfirmedSetSHA256, ReasonMissing)}},
		{"a confirmed set with its op only", WriterRequest, with(req, attribute.String(KeyClientSource, ClientSourcePortal), attribute.Int64(KeyClientConfirmedSetOp, 0)),
			[]Violation{v(KeyClientConfirmedSetCount, ReasonMissing), v(KeyClientConfirmedSetIrreversible, ReasonMissing), v(KeyClientConfirmedSetSHA256, ReasonMissing)}},
		{"op equal to count", WriterRequest, with(portal, attribute.Int64(KeyClientConfirmedSetOp, 3)), []Violation{v(KeyClientConfirmedSetOp, ReasonOutOfRange)}},
		{"op beyond count", WriterRequest, with(portal, attribute.Int64(KeyClientConfirmedSetOp, 7)), []Violation{v(KeyClientConfirmedSetOp, ReasonOutOfRange)}},
		{"op 0 of 1", WriterRequest, with(portal, attribute.Int64(KeyClientConfirmedSetOp, 0), attribute.Int64(KeyClientConfirmedSetCount, 1)), nil},
		{"a negative op", WriterRequest, with(portal, attribute.Int64(KeyClientConfirmedSetOp, -1)), []Violation{v(KeyClientConfirmedSetOp, ReasonOutOfRange)}},
		{"an empty set", WriterRequest, with(portal, attribute.Int64(KeyClientConfirmedSetCount, 0), attribute.Int64(KeyClientConfirmedSetOp, 0)),
			[]Violation{v(KeyClientConfirmedSetCount, ReasonOutOfRange), v(KeyClientConfirmedSetOp, ReasonOutOfRange)}},
		{"count as a string", WriterRequest, with(portal, attribute.String(KeyClientConfirmedSetCount, "3")), []Violation{v(KeyClientConfirmedSetCount, ReasonBadType)}},
		{"another source", WriterRequest, with(portal, attribute.String(KeyClientSource, "browser")), []Violation{v(KeyClientSource, ReasonBadEnum)}},
		{"a confirmation id in upper case", WriterRequest, with(portal, attribute.String(KeyClientConfirmationID, strings.ToUpper(exampleConfirm))), []Violation{v(KeyClientConfirmationID, ReasonBadFormat)}},
		{"a confirmation id that is not a UUID", WriterRequest, with(portal, attribute.String(KeyClientConfirmationID, "press-1")), []Violation{v(KeyClientConfirmationID, ReasonBadFormat)}},
		{"a session id with a dot", WriterRequest, with(portal, attribute.String(KeyClientAgentSessionID, "a.b")), []Violation{v(KeyClientAgentSessionID, ReasonBadFormat)}},
		{"a session id of 129 characters", WriterRequest, with(portal, attribute.String(KeyClientAgentSessionID, strings.Repeat("a", 129))), []Violation{v(KeyClientAgentSessionID, ReasonBadFormat)}},
		{"a session id of 128 characters", WriterRequest, with(portal, attribute.String(KeyClientAgentSessionID, strings.Repeat("a", 128))), nil},
		{"requested_at without a zone", WriterRequest, with(portal, attribute.String(KeyClientRequestedAt, "2026-11-11T10:00:00")), []Violation{v(KeyClientRequestedAt, ReasonBadFormat)}},
		{"requested_at as Unix time", WriterRequest, with(portal, attribute.String(KeyClientRequestedAt, "1762855200")), []Violation{v(KeyClientRequestedAt, ReasonBadFormat)}},
		{"provenance on a read", WriterRequest, without(withVerb(with(req, attribute.String(KeyClientSource, ClientSourcePortal), attribute.String(KeyClientConfirmationID, exampleConfirm)), "get"), KeyDryRun),
			[]Violation{v(KeyClientSource, ReasonUnexpected), v(KeyClientConfirmationID, ReasonUnexpected)}},
		{"provenance on a gateway record", WriterGateway, with(gw, attribute.String(KeyClientSource, ClientSourcePortal)), []Violation{v(KeyClientSource, ReasonNotForWriter)}},
		{"provenance on a controller record", WriterController, with(ctrl, attribute.String(KeyClientRejected, ClientRejectedSchema)), []Violation{v(KeyClientRejected, ReasonNotForWriter)}},

		// A rejected header: rejected, and no other client key.
		{"a rejected header", WriterRequest, rejected, nil},
		{"every rejection reason", WriterRequest, with(rejected, attribute.String(KeyClientRejected, ClientRejectedEncoding)), nil},
		{"a rejection reason outside the set", WriterRequest, with(rejected, attribute.String(KeyClientRejected, "too_big")), []Violation{v(KeyClientRejected, ReasonBadEnum)}},
		{"a rejected header on a read", WriterRequest, without(withVerb(rejected, "get"), KeyDryRun), []Violation{v(KeyClientRejected, ReasonUnexpected)}},
		{"a rejected header with its source", WriterRequest, with(rejected, attribute.String(KeyClientSource, ClientSourcePortal)), []Violation{v(KeyClientSource, ReasonUnexpected)}},
		{"a rejected header with all of the provenance", WriterRequest, with(portal, attribute.String(KeyClientRejected, ClientRejectedOversize)), []Violation{
			v(KeyClientSource, ReasonUnexpected), v(KeyClientAgentSessionID, ReasonUnexpected), v(KeyClientConfirmationID, ReasonUnexpected),
			v(KeyClientConfirmedSetCount, ReasonUnexpected), v(KeyClientConfirmedSetIrreversible, ReasonUnexpected),
			v(KeyClientConfirmedSetSHA256, ReasonUnexpected), v(KeyClientConfirmedSetOp, ReasonUnexpected), v(KeyClientRequestedAt, ReasonUnexpected)}},
	}
	// A rejected header beside each other client key alone: that key, and
	// only it, is unexpected.
	for _, kv := range portalProvenance {
		cases = append(cases, struct {
			name  string
			w     Writer
			attrs []attribute.KeyValue
			want  []Violation
		}{"a rejected header with " + string(kv.Key), WriterRequest, with(rejected, kv), rejectedBeside(string(kv.Key))})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Check(tc.w, tc.attrs); !slices.Equal(got, tc.want) {
				t.Errorf("Check(%s):\n got %v\nwant %v", tc.w, got, tc.want)
			}
		})
	}
}

// rejectedBeside is what Check reports for a rejected header beside the
// client key k alone: k unexpected, and the keys k makes required (source
// beside any other key; the rest of a confirmed set) missing.
func rejectedBeside(k string) []Violation {
	out := []Violation{{Key: k, Reason: ReasonUnexpected}}
	var missing []string
	if k != KeyClientSource {
		missing = append(missing, KeyClientSource)
	}
	if strings.HasPrefix(k, confirmedSetPrefix) {
		for _, m := range []string{KeyClientConfirmedSetCount, KeyClientConfirmedSetIrreversible, KeyClientConfirmedSetSHA256, KeyClientConfirmedSetOp} {
			if m != k {
				missing = append(missing, m)
			}
		}
	}
	for _, m := range missing {
		out = append(out, Violation{Key: m, Reason: ReasonMissing})
	}
	return out
}

// The schema states the v0.6.0 rulings as asked.
func TestSchema_V060(t *testing.T) {
	get := func(k string) KeySpec {
		s, ok := LookupKey(k)
		if !ok {
			t.Fatalf("%s is not in the schema", k)
		}
		return s
	}
	if s := get(KeyHTTPStatusCode); s.NotWhen != CondDenied || s.OnlyWhen != "" {
		t.Errorf("status code: NotWhen %q, OnlyWhen %q; want never on denied", s.NotWhen, s.OnlyWhen)
	}

	c := get(KeyObjectContentSHA256)
	if !c.CredentialFree || c.OnlyWhen != CondContentWrite || c.Format != "sha256_hex" || c.Identity || c.Asserted || LegacyKey(c.Name) != "" {
		t.Errorf("content_sha256: %+v", c)
	}
	for w, want := range map[Writer]Level{WriterRequest: LevelOptional, WriterGateway: LevelNotEstablished, WriterAction: LevelOptional, WriterController: LevelOptional} {
		if got := c.Writers[w].Level; got != want {
			t.Errorf("content_sha256 for %s = %v, want %v", w, got, want)
		}
	}
	if got := ContentWriteVerbs(); !slices.Equal(got, []string{"create", "update"}) {
		t.Errorf("content-write verbs = %v", got)
	}
	// Written out by hand: the credential targets, and what matches them.
	if got, want := CredentialTargets(), []CredentialTarget{{"", "secrets", ""}, {"", "serviceaccounts", "token"}}; !slices.Equal(got, want) {
		t.Errorf("credential targets = %v, want %v", got, want)
	}
	for _, tc := range []struct {
		g, r, s string
		want    bool
	}{
		{"", "secrets", "", true}, {"", "secrets", "status", true}, {"", "serviceaccounts", "token", true},
		{"", "serviceaccounts", "", false}, {"", "configmaps", "", false}, {"example.krateo.io", "secrets", "", false},
	} {
		if got := IsCredentialTarget(tc.g, tc.r, tc.s); got != tc.want {
			t.Errorf("IsCredentialTarget(%q, %q, %q) = %v", tc.g, tc.r, tc.s, got)
		}
	}
	// Only content_sha256 is credential-free.
	for _, k := range Keys() {
		if k.CredentialFree != (k.Name == KeyObjectContentSHA256) {
			t.Errorf("%s: CredentialFree = %v", k.Name, k.CredentialFree)
		}
	}

	// The client keys, by hand: their names, never identity, outcome or
	// target; asserted; never required, never marked; request and action only.
	wantClient := []string{"krateo.audit.client.source", "krateo.audit.client.agent_session_id", "krateo.audit.client.confirmation_id",
		"krateo.audit.client.confirmed_set.count", "krateo.audit.client.confirmed_set.irreversible", "krateo.audit.client.confirmed_set.sha256",
		"krateo.audit.client.confirmed_set.op", "krateo.audit.client.requested_at", "krateo.audit.client.rejected"}
	var gotClient []string
	for _, k := range Keys() {
		if !strings.HasPrefix(k.Name, clientPrefix) {
			continue
		}
		gotClient = append(gotClient, k.Name)
		if !k.Asserted || k.Identity || k.Marker != "" || slices.Contains(Target().Keys, k.Name) || k.ReplacedBy != "" {
			t.Errorf("%s: asserted, never identity, marker, target or v0.3 key: %+v", k.Name, k)
		}
		if k.OnlyWhen != CondWrite {
			t.Errorf("%s: OnlyWhen %q, want write", k.Name, k.OnlyWhen)
		}
		if wantNot := map[bool]Condition{true: "", false: CondClientRejected}[k.Name == KeyClientRejected]; k.NotWhen != wantNot {
			t.Errorf("%s: NotWhen %q, want %q", k.Name, k.NotWhen, wantNot)
		}
		for _, w := range Writers() {
			r := k.Writers[w]
			writes := w == WriterRequest || w == WriterAction
			if writes != (r.Level > LevelNotEstablished) || r.Level == LevelRequired || r.Markable {
				t.Errorf("%s for %s = %+v", k.Name, w, r)
			}
		}
	}
	if !slices.Equal(gotClient, wantClient) {
		t.Errorf("client keys:\n got %v\nwant %v", gotClient, wantClient)
	}
	if s := get(KeyClientSource); !slices.Equal(s.Values, []string{ClientSourcePortal}) {
		t.Errorf("source values %v", s.Values)
	}
	if s := get(KeyClientRejected); !slices.Equal(s.Values, []string{ClientRejectedOversize, ClientRejectedEncoding, ClientRejectedVersion, ClientRejectedSchema}) {
		t.Errorf("rejected values %v, want the constants", s.Values)
	}
	if s := get(KeyClientConfirmedSetOp); s.Min == nil || *s.Min != 0 || s.LessThan != KeyClientConfirmedSetCount {
		t.Errorf("op bounds: %+v", s)
	}
	if s := get(KeyClientConfirmedSetCount); s.Min == nil || *s.Min != 1 {
		t.Errorf("count bound: %+v", s)
	}
	// The bound is a copy, like the rest of a KeySpec.
	s := get(KeyClientConfirmedSetCount)
	*s.Min = 99
	if again := get(KeyClientConfirmedSetCount); *again.Min != 1 {
		t.Errorf("LookupKey shares Min with its caller")
	}

	// The three request denial reasons.
	for c, v := range map[string]string{DenialReasonDelegationNotAllowed: "delegation_not_allowed", DenialReasonDelegationTooDeep: "delegation_too_deep", DenialReasonPlatformGroup: "platform_group"} {
		if c != v || !slices.Contains(get(KeyDenialReason).Writers[WriterRequest].Values, v) || slices.Contains(get(KeyDenialReason).Writers[WriterController].Values, v) {
			t.Errorf("denial reason %q: the request writer's only", v)
		}
	}

	// The per-module scopes, and the shared one kept for historical rows.
	scopes := map[string]Writer{}
	for _, p := range Populations() {
		scopes[p.Scope] = p.Writer
	}
	for _, sc := range []string{"github.com/krateo-platformops/access-review/audit", "github.com/krateo-platformops/identity-lifecycle/audit", "github.com/krateo-platformops/audit"} {
		if scopes[sc] != WriterController {
			t.Errorf("scope %s: writer %q, want controller", sc, scopes[sc])
		}
	}
}

// Emit writes Event.ContentSHA256 and Event.Client; a rejected header alone;
// a v0.5 caller that sets neither gets neither.
func TestEmit_ContentHashAndClientProvenance(t *testing.T) {
	ev := Event{UserName: "alice", ActorClass: ClassHuman, Action: "call", Verb: "create", HTTPMethod: "POST", StatusCode: 201,
		Outcome: OutcomeSuccess, Namespace: "tenant-a", Version: "v1", Resource: "configmaps", ObjectName: "cm", Preview: PreviewFalse,
		RequestURI: "/call", SourceIPs: []string{"10.0.0.1"}, ContentSHA256: exampleSHA,
		Client: ClientProvenance{Source: ClientSourcePortal, AgentSessionID: "example-agent-session", ConfirmationID: exampleConfirm,
			ConfirmedSet: &ConfirmedSet{Count: 3, Irreversible: true, SHA256: exampleSetSHA, Op: 0},
			RequestedAt:  time.Date(2026, 11, 11, 11, 0, 0, 123456789, time.FixedZone("CET", 3600))}}
	e, rec := newEmitter(t, WithWriter(WriterRequest))
	e.Emit(WithSessionIDForTest(t, spanCtx(t), "s1"), ev)
	got := attrs(only(t, rec))
	for k, want := range map[string]attribute.Value{
		KeyObjectContentSHA256:            attribute.StringValue(exampleSHA),
		KeyClientSource:                   attribute.StringValue("portal"),
		KeyClientAgentSessionID:           attribute.StringValue("example-agent-session"),
		KeyClientConfirmationID:           attribute.StringValue(exampleConfirm),
		KeyClientConfirmedSetCount:        attribute.Int64Value(3),
		KeyClientConfirmedSetIrreversible: attribute.BoolValue(true),
		KeyClientConfirmedSetSHA256:       attribute.StringValue(exampleSetSHA),
		KeyClientConfirmedSetOp:           attribute.Int64Value(0), // op 0 is written: the first write of the set
		KeyClientRequestedAt:              attribute.StringValue("2026-11-11T10:00:00.123Z"),
	} {
		if got[k] != want {
			t.Errorf("%s = %v, want %v", k, got[k].Emit(), want.Emit())
		}
	}
	if _, ok := got[KeyClientRejected]; ok {
		t.Errorf("rejected written for an accepted header")
	}
	if vs := Check(WriterRequest, kvs(got)); len(vs) > 0 {
		t.Errorf("Emit's record: %v", vs)
	}

	// A rejected header: rejected alone, whatever else the caller set.
	ev.Client.Rejected = ClientRejectedOversize
	e2, rec2 := newEmitter(t, WithWriter(WriterRequest))
	e2.Emit(WithSessionIDForTest(t, spanCtx(t), "s1"), ev)
	got = attrs(only(t, rec2))
	var client []string
	for k := range got {
		if strings.HasPrefix(k, clientPrefix) {
			client = append(client, k)
		}
	}
	if !slices.Equal(client, []string{KeyClientRejected}) || got[KeyClientRejected] != attribute.StringValue("oversize") {
		t.Errorf("a rejected header's client keys = %v", client)
	}
	if vs := Check(WriterRequest, kvs(got)); len(vs) > 0 {
		t.Errorf("Emit's rejected record: %v", vs)
	}

	// Neither set: no key.
	e3, rec3 := newEmitter(t, WithWriter(WriterRequest))
	e3.Emit(spanCtx(t), Event{Action: "call", Verb: "create", Outcome: OutcomeSuccess, Resource: "configmaps"})
	for k := range attrs(only(t, rec3)) {
		if k == KeyObjectContentSHA256 || strings.HasPrefix(k, clientPrefix) {
			t.Errorf("%s written for an Event that does not set it", k)
		}
	}
}

func kvs(m map[string]attribute.Value) []attribute.KeyValue {
	var out []attribute.KeyValue
	for k, v := range m {
		out = append(out, attribute.KeyValue{Key: attribute.Key(k), Value: v})
	}
	return out
}

// The content hash test vector, computed from three spellings of the same
// ConfigMap, matches the bytes and the hash docs/schema.md shows.
func TestContentSHA256_Vector(t *testing.T) {
	const wantBytes = `{"binaryData":{"logo":"iVBORw=="},"data":{"a\"b":"line1\nline2","k":"<é>"}}`
	unstructured := map[string]any{
		"apiVersion": "v1", "kind": "ConfigMap", "immutable": true,
		"metadata":   map[string]any{"name": "example-evidence", "namespace": "example-ns", "uid": "uid-e"},
		"data":       map[string]any{"k": "<é>", "a\"b": "line1\nline2"},
		"binaryData": map[string]any{"logo": "iVBORw=="},
	}
	type configMap struct { // the shape of corev1.ConfigMap, fields in its order
		Kind       string            `json:"kind,omitempty"`
		Metadata   map[string]string `json:"metadata,omitempty"`
		Immutable  *bool             `json:"immutable,omitempty"`
		Data       map[string]string `json:"data,omitempty"`
		BinaryData map[string][]byte `json:"binaryData,omitempty"`
	}
	yes := true
	typed := configMap{Kind: "ConfigMap", Metadata: map[string]string{"name": "other-name"}, Immutable: &yes,
		Data: map[string]string{"a\"b": "line1\nline2", "k": "<é>"}, BinaryData: map[string][]byte{"logo": {0x89, 0x50, 0x4e, 0x47}}}
	raw := json.RawMessage(`{ "data" : { "k" : "<é>", "a\"b" : "line1\nline2" }, "binaryData": {"logo":"iVBORw=="}, "status": {"x": 1} }`)
	for name, obj := range map[string]any{"unstructured": unstructured, "typed": typed, "raw JSON": raw} {
		got, err := ContentSHA256("", "configmaps", obj)
		if err != nil || got != exampleSHA {
			t.Errorf("%s: %q, %v; want %s", name, got, err, exampleSHA)
		}
	}
	var b bytes.Buffer
	if err := canonicalJSON(&b, map[string]any{"data": unstructured["data"], "binaryData": unstructured["binaryData"]}); err != nil || b.String() != wantBytes {
		t.Errorf("canonical bytes %q, %v; want %q", b.String(), err, wantBytes)
	}
	doc, err := os.ReadFile("docs/schema.md")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(doc, []byte(wantBytes)) || !bytes.Contains(doc, []byte(exampleSHA)) {
		t.Errorf("docs/schema.md does not show the test vector")
	}
}

// The content of each kind family, and what is refused.
func TestContentSHA256_Families(t *testing.T) {
	hash := func(group, resource string, obj any) string {
		t.Helper()
		h, err := ContentSHA256(group, resource, obj)
		if err != nil {
			t.Fatalf("%s/%s: %v", group, resource, err)
		}
		return h
	}
	cm := map[string]any{"data": map[string]any{"a": "1"}}
	if hash("", "configmaps", cm) != hash("", "configmaps", map[string]any{"data": map[string]any{"a": "1"}, "immutable": true, "metadata": map[string]any{"labels": map[string]any{"x": "y"}}}) {
		t.Errorf("a ConfigMap's hash depends on more than data and binaryData")
	}
	if hash("", "configmaps", cm) == hash("", "configmaps", map[string]any{"data": map[string]any{"a": "2"}}) {
		t.Errorf("a ConfigMap's hash ignores its data")
	}
	if hash("", "configmaps", map[string]any{"data": nil}) != hash("", "configmaps", map[string]any{}) {
		t.Errorf("a null field is not left out")
	}
	cr := map[string]any{"apiVersion": "example.krateo.io/v1", "kind": "Campaign", "spec": map[string]any{"n": 3, "decisions": []any{"keep"}},
		"metadata": map[string]any{"generation": 4}, "status": map[string]any{"phase": "Done"}}
	if hash("example.krateo.io", "campaigns", cr) != hash("example.krateo.io", "campaigns", map[string]any{"spec": map[string]any{"decisions": []any{"keep"}, "n": 3}}) {
		t.Errorf("a custom resource's hash depends on apiVersion, kind, metadata or status")
	}
	if hash("rbac.authorization.k8s.io", "rolebindings", map[string]any{"roleRef": "r", "subjects": []any{"s"}}) ==
		hash("rbac.authorization.k8s.io", "rolebindings", map[string]any{"roleRef": "r"}) {
		t.Errorf("a RoleBinding's hash ignores its subjects")
	}
	// The configmaps family is the core group's only: a CRD named configmaps
	// hashes its spec.
	if hash("example.krateo.io", "configmaps", map[string]any{"spec": 1, "data": map[string]any{"a": "1"}}) == hash("", "configmaps", map[string]any{"spec": 1, "data": map[string]any{"a": "1"}}) {
		t.Errorf("a CRD named configmaps is hashed as a ConfigMap")
	}

	for name, tc := range map[string]struct {
		group, resource string
		obj             any
		credential      bool
	}{
		"a Secret":          {"", "secrets", map[string]any{"data": map[string]any{"password": "aGk="}}, true},
		"a float":           {"example.krateo.io", "things", map[string]any{"spec": map[string]any{"ratio": 0.5}}, false},
		"an exponent":       {"example.krateo.io", "things", json.RawMessage(`{"spec":1e3}`), false},
		"not an object":     {"", "configmaps", []string{"a"}, false},
		"not JSON at all":   {"", "configmaps", func() {}, false},
		"a negative zero":   {"example.krateo.io", "things", json.RawMessage(`{"spec":-0}`), false},
		"an integer as 1.0": {"example.krateo.io", "things", json.RawMessage(`{"spec":[1.0]}`), false},
	} {
		h, err := ContentSHA256(tc.group, tc.resource, tc.obj)
		if err == nil || h != "" {
			t.Errorf("%s: %q, %v; want refused", name, h, err)
		}
		if errors.Is(err, ErrCredentialTarget) != tc.credential {
			t.Errorf("%s: %v; ErrCredentialTarget %v", name, err, tc.credential)
		}
	}
	if h := hash("example.krateo.io", "things", map[string]any{"spec": map[string]any{"n": -12, "z": 0}}); h == "" {
		t.Errorf("integers have a canonical form")
	}
}

// The canonical form escapes what JSON requires and nothing else: no HTML
// escaping, U+2028 raw, control characters as \u00xx; and its rules agree
// with snowplow#1333's golden vector for the confirmed set, which states the
// same rules.
func TestCanonicalJSON(t *testing.T) {
	for in, want := range map[string]string{
		"<a&b>":       `"<a&b>"`,
		"x y":         "\"x y\"",
		"\x01\x1f":    `"\u0001\u001f"`,
		"\b\f\n\r\t":  `"\b\f\n\r\t"`,
		`q"\`:         `"q\"\\"`,
		"é😀":          `"é😀"`,
		"\x7f is DEL": "\"\x7f is DEL\"",
	} {
		var b bytes.Buffer
		if err := canonicalJSON(&b, in); err != nil || b.String() != want {
			t.Errorf("%q: %s, %v; want %s", in, b.String(), err, want)
		}
	}
	var b bytes.Buffer
	if err := canonicalString(&b, "bad-\xff"); err == nil {
		t.Errorf("invalid UTF-8 written")
	}

	op := func(group, name, resource, verb, version string, irreversible bool) map[string]any {
		return map[string]any{"group": group, "irreversible": irreversible, "name": name, "namespace": "example-ns", "resource": resource, "verb": verb, "version": version}
	}
	set := []any{
		op("composition.krateo.io", "example-a", "examplecatalogs", "POST", "v1-2-0", false),
		op("", "example-b", "configmaps", "DELETE", "v1", true),
		op("apps", "", "deployments", "POST", "v1", false),
	}
	raw, _ := json.Marshal(set)
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var decoded any
	if err := dec.Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	b.Reset()
	if err := canonicalJSON(&b, decoded); err != nil {
		t.Fatal(err)
	}
	const golden = `[{"group":"composition.krateo.io","irreversible":false,"name":"example-a","namespace":"example-ns","resource":"examplecatalogs","verb":"POST","version":"v1-2-0"},{"group":"","irreversible":true,"name":"example-b","namespace":"example-ns","resource":"configmaps","verb":"DELETE","version":"v1"},{"group":"apps","irreversible":false,"name":"","namespace":"example-ns","resource":"deployments","verb":"POST","version":"v1"}]`
	if b.String() != golden {
		t.Errorf("the confirmed set's canonical bytes:\n got %s\nwant %s", b.String(), golden)
	}
	if sum := sha256.Sum256(b.Bytes()); hex.EncodeToString(sum[:]) != exampleSetSHA {
		t.Errorf("the confirmed set's hash is not snowplow#1333's")
	}
}
