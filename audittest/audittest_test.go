package audittest_test

import (
	"context"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/krateo-platformops/audit"
	"github.com/krateo-platformops/audit/audittest"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func spanCtx(t *testing.T) context.Context {
	t.Helper()
	tp := sdktrace.NewTracerProvider()
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	ctx, span := tp.Tracer("test").Start(context.Background(), "op")
	t.Cleanup(func() { span.End() })
	return ctx
}

func sessionCtx(t *testing.T) context.Context {
	t.Helper()
	m, _ := baggage.NewMember(audit.BaggageSessionKey, "sess-1")
	b, _ := baggage.New(m)
	return baggage.ContextWithBaggage(spanCtx(t), b)
}

const sa = "system:serviceaccount:krateo-system:controller"

// Each Go writer's records, as the callers will write them after adopting
// v0.4.0, conform; and every key the writer must write is load-bearing.
func TestWriters_ConformAndEveryRequiredKeyIsDetected(t *testing.T) {
	for _, tc := range []struct {
		name  string
		w     audit.Writer
		opts  []audit.Option
		ctx   func(*testing.T) context.Context
		ev    audit.Event
		allow []string
	}{
		{
			name: "rest-dynamic-controller external write", w: audit.WriterController,
			opts: []audit.Option{audit.WithActor(sa, audit.ClassController)}, ctx: spanCtx,
			ev: audit.Event{Message: "external write succeeded", Action: "rest.write", Verb: "post", HTTPMethod: "POST", StatusCode: 201,
				Outcome: audit.OutcomeSuccess, Namespace: "tenant-a", Group: "github.krateo.io", Version: "v1alpha1",
				Resource: "repoes", Kind: "Repo", ObjectName: "demo", ObjectUID: "uid-1", ObjectGeneration: 3,
				ServerAddress: "https://api.github.com/orgs/x/repos", Preview: audit.PreviewFalse},
		},
		{
			name: "access-review revoke", w: audit.WriterController,
			opts: []audit.Option{audit.WithActor(sa, audit.ClassController)}, ctx: spanCtx,
			ev: audit.Event{Message: "grant revoked", AffectedUser: "alice", Action: "revoke", Verb: "delete",
				Outcome: audit.OutcomeSuccess, Namespace: "tenant-a", Group: "rbac.authorization.k8s.io", Version: "v1",
				Resource: "rolebindings", Kind: "RoleBinding", ObjectName: "alice-edit", Preview: audit.PreviewFalse},
		},
		{
			name: "identity-lifecycle deactivation (cluster-scoped IdP action)", w: audit.WriterController,
			opts: []audit.Option{audit.WithActor(sa, audit.ClassController)}, ctx: spanCtx,
			ev: audit.Event{Message: "account disabled", AffectedUser: "bob", Action: "deactivate", Verb: "post",
				Outcome: audit.OutcomeSuccess, ServerAddress: "idp.example.com"},
		},
		{
			name: "tool executor", w: audit.WriterAction,
			opts: []audit.Option{audit.WithActor("kagent-tools", audit.ClassAgent), audit.WithWriter(audit.WriterAction)}, ctx: sessionCtx,
			ev: audit.Event{Action: "tool.k8s.create", Verb: "create", Outcome: audit.OutcomeSuccess,
				Namespace: "krateo-preview", Version: "v1", Resource: "configmaps", ObjectName: "draft", Preview: audit.PreviewTrue},
		},
		{
			name: "snowplow /call, delegated token", w: audit.WriterRequest,
			opts: []audit.Option{audit.WithWriter(audit.WriterRequest)}, ctx: sessionCtx,
			ev: audit.Event{UserName: "svc-bot", ActorClass: audit.ClassAgent, OnBehalfOf: "alice",
				Delegation: []audit.Link{{Class: audit.ClassAgent, Subject: "svc-bot"}, {Class: audit.ClassHuman, Subject: "alice"}},
				Action:     "call", Verb: "create", HTTPMethod: "POST", StatusCode: 201, Outcome: audit.OutcomeSuccess,
				Namespace: "tenant-a", Version: "v1", Resource: "configmaps", ObjectName: "cm", Preview: audit.PreviewFalse,
				RequestURI: "/call?name=cm", SourceIPs: []string{"10.0.0.1"}, UserAgent: "portal/1.0"},
		},
		{
			name: "snowplow /call, token minted before the principal claim", w: audit.WriterRequest,
			opts: []audit.Option{audit.WithWriter(audit.WriterRequest)}, ctx: sessionCtx,
			ev: audit.Event{UserName: "alice", UserRoles: []string{"devs"}, Action: "call", Verb: "get", HTTPMethod: "GET",
				StatusCode: 200, Outcome: audit.OutcomeSuccess, ServerAddress: "api.example.com",
				RequestURI: "/call", SourceIPs: []string{"10.0.0.1"}},
			allow: []string{audit.KeyActorClass},
		},
		// v0.5.0: a controller names the object it reconciled in Cause.
		{
			name: "external write caused by a CR (v0.5: the CR in cause_ref)", w: audit.WriterController,
			opts: []audit.Option{audit.WithActor(sa, audit.ClassController), audit.WithWriter(audit.WriterController)}, ctx: spanCtx,
			ev: audit.Event{Action: "rest.write", Verb: "post", HTTPMethod: "POST", StatusCode: 201, Outcome: audit.OutcomeSuccess,
				ServerAddress: "api.example.com",
				Cause: audit.CauseRef{Group: "example.krateo.io", Version: "v1alpha1", Resource: "examplerepos", Namespace: "example-ns",
					Name: "example-repo", UID: "uid-r", Generation: 3}},
		},
		{
			name: "status write of the reconciled CR itself", w: audit.WriterController,
			opts: []audit.Option{audit.WithActor(sa, audit.ClassController), audit.WithWriter(audit.WriterController)}, ctx: spanCtx,
			ev: audit.Event{Action: "status.update", Verb: "update", Outcome: audit.OutcomeSuccess,
				Namespace: "example-ns", Group: "example.krateo.io", Version: "v1alpha1", Resource: "examplerepos", Subresource: "status",
				ObjectName: "example-repo", ObjectUID: "uid-r", Preview: audit.PreviewFalse,
				Cause: audit.CauseRef{Group: "example.krateo.io", Version: "v1alpha1", Resource: "examplerepos", Namespace: "example-ns",
					Name: "example-repo", UID: "uid-r", Generation: 3}},
		},
		// authn, a request writer: a login writes the credential Secret; a refused name is denied with its reason.
		{
			name: "authn login", w: audit.WriterRequest,
			opts: []audit.Option{audit.WithWriter(audit.WriterRequest)}, ctx: sessionCtx,
			ev: audit.Event{UserName: "example-user", UserRoles: []string{"example-group"}, ActorClass: audit.ClassHuman,
				Action: "authn.login.oidc", Verb: "update", HTTPMethod: "PUT", StatusCode: 200, Outcome: audit.OutcomeSuccess,
				Namespace: "example-system", Version: "v1", Resource: "secrets", ObjectName: "example-user-clientconfig",
				ObjectUID: "uid-s", ObjectResourceVersion: "42", Preview: audit.PreviewFalse,
				RequestURI: "/oidc/callback", SourceIPs: []string{"192.0.2.10"}},
		},
		{
			name: "authn login refused: the name is claimed", w: audit.WriterRequest,
			opts: []audit.Option{audit.WithWriter(audit.WriterRequest)}, ctx: sessionCtx,
			ev: audit.Event{UserName: "example-user", ActorClass: audit.ClassHuman,
				Action: "authn.login.oidc", Verb: "update", HTTPMethod: "PUT", Outcome: audit.OutcomeDenied,
				DenialReason: audit.DenialReasonNameClaimed,
				Namespace:    "example-system", Version: "v1", Resource: "secrets", ObjectName: "example-user-clientconfig", Preview: audit.PreviewFalse,
				RequestURI: "/oidc/callback", SourceIPs: []string{"192.0.2.10"}},
		},
		// v0.6.0 (audit#12): authn's /delegate refusals, the portal's
		// provenance on a /call write, and a content hash.
		{
			name: "authn /delegate refused: the chain is too deep", w: audit.WriterRequest,
			opts: []audit.Option{audit.WithWriter(audit.WriterRequest)}, ctx: sessionCtx,
			ev: audit.Event{UserName: "example-agent", ActorClass: audit.ClassAgent,
				Action: "authn.delegate", Verb: "create", HTTPMethod: "POST", Outcome: audit.OutcomeDenied,
				DenialReason: audit.DenialReasonDelegationTooDeep,
				Namespace:    "example-system", Group: "authn.krateo.io", Version: "v1alpha1", Resource: "serviceaccounts",
				ObjectName: "example-agent", Preview: audit.PreviewFalse,
				RequestURI: "/delegate", SourceIPs: []string{"192.0.2.10"}},
		},
		{
			name: "snowplow /call, the portal's provenance and a content hash", w: audit.WriterRequest,
			opts: []audit.Option{audit.WithWriter(audit.WriterRequest)}, ctx: sessionCtx,
			ev: audit.Event{UserName: "alice", ActorClass: audit.ClassHuman, Action: "call", Verb: "create", HTTPMethod: "POST",
				StatusCode: 201, Outcome: audit.OutcomeSuccess, Namespace: "tenant-a", Version: "v1", Resource: "configmaps",
				ObjectName: "cm", Preview: audit.PreviewFalse, RequestURI: "/call?name=cm", SourceIPs: []string{"10.0.0.1"},
				ContentSHA256: "c1:2bbf0a0f3ccc266c6ee429376afbd9a20714a80d5b03a753bbb29ec8c1fee232",
				Client: audit.ClientProvenance{Source: audit.ClientSourcePortal, ConfirmationID: "00000000-0000-4000-8000-0000000000aa",
					ConfirmedSet: &audit.ConfirmedSet{Count: 3, Irreversible: true, SHA256: "0a08bb91090b111f15a045b6061bccc4d0b8488d85f99ba57d8632e17061c277", Op: 0}}},
		},
		{
			name: "snowplow /call, the provenance header rejected", w: audit.WriterRequest,
			opts: []audit.Option{audit.WithWriter(audit.WriterRequest)}, ctx: sessionCtx,
			ev: audit.Event{UserName: "alice", ActorClass: audit.ClassHuman, Action: "call", Verb: "delete", HTTPMethod: "DELETE",
				StatusCode: 200, Outcome: audit.OutcomeSuccess, Namespace: "tenant-a", Version: "v1", Resource: "configmaps",
				ObjectName: "cm", Preview: audit.PreviewFalse, RequestURI: "/call?name=cm", SourceIPs: []string{"10.0.0.1"},
				Client: audit.ClientProvenance{Rejected: audit.ClientRejectedOversize}},
		},
		{
			name: "access-review evidence ConfigMap, with its content hash", w: audit.WriterController,
			opts: []audit.Option{audit.WithActor(sa, audit.ClassController), audit.WithWriter(audit.WriterController)}, ctx: spanCtx,
			ev: audit.Event{Action: "campaign.evidence", Verb: "create", HTTPMethod: "POST", StatusCode: 201, Outcome: audit.OutcomeSuccess,
				Namespace: "example-ns", Version: "v1", Resource: "configmaps", ObjectName: "example-evidence", ObjectUID: "uid-e",
				ObjectResourceVersion: "77", Preview: audit.PreviewFalse,
				ContentSHA256: "c1:2bbf0a0f3ccc266c6ee429376afbd9a20714a80d5b03a753bbb29ec8c1fee232",
				Cause: audit.CauseRef{Group: "accessreview.krateo.io", Version: "v1alpha1", Resource: "campaigns", Namespace: "example-ns",
					Name: "example-campaign", UID: "uid-c", Generation: 2}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := audittest.NewRecorder(t)
			e := audit.New(rec.Logger("test/audit"), tc.opts...)
			e.Emit(tc.ctx(t), tc.ev)
			r := rec.Only(t)
			opts := []audittest.Option{audittest.AllowIncomplete(tc.allow...)}
			audittest.AssertConformant(t, tc.w, r, opts...)
			audittest.AssertRequiredKeysDetected(t, tc.w, r, opts...)
			audittest.AssertEnumsDetected(t, tc.w, r, opts...)
		})
	}
}

// The falsifier covers cause_ref where it is required: once a record names a
// cause, removing its uid, version, resource or name alone is caught.
func TestAssertRequiredKeysDetected_CoversCauseRef(t *testing.T) {
	rec, w := controllerRecord(t, audit.Event{Action: "rest.write", Verb: "post", Outcome: audit.OutcomeSuccess, ServerAddress: "api.example.com",
		Cause: audit.CauseRef{Version: "v1", Resource: "examplerepos", Name: "example-repo", UID: "uid-r", Generation: 3}})
	r := rec.Only(t)
	required := audit.RequiredKeys(w, audittest.Attributes(r))
	for _, k := range []string{audit.KeyCauseAPIVersion, audit.KeyCauseResource, audit.KeyCauseName, audit.KeyCauseUID} {
		if !slices.Contains(required, k) {
			t.Errorf("%s is not required of a record that names a cause: %v", k, required)
		}
		if msgs := failures(t, func(tb testing.TB) { audittest.AssertRemovalDetected(tb, w, r, k) }); len(msgs) != 0 {
			t.Errorf("removing %s: %q", k, msgs)
		}
	}
	// generation is required only when the object has one, which the record
	// cannot show: removing it is not detected, and the falsifier says so.
	if msgs := failures(t, func(tb testing.TB) { audittest.AssertRemovalDetected(tb, w, r, audit.KeyCauseGeneration) }); len(msgs) == 0 || !strings.Contains(msgs[0], "is not detected") {
		t.Errorf("removing cause_ref.generation was reported as detected: %q", msgs)
	}
}

// The falsifier covers the client keys where they are required: once a record
// carries the portal's provenance, removing its source, or any one key of its
// confirmed set, is caught; and the closed sets of source and rejected are
// exercised.
func TestFalsifiers_CoverClientProvenance(t *testing.T) {
	rec := audittest.NewRecorder(t)
	e := audit.New(rec.Logger("test/audit"), audit.WithWriter(audit.WriterRequest))
	base := audit.Event{UserName: "alice", ActorClass: audit.ClassHuman, Action: "call", Verb: "patch", HTTPMethod: "PATCH",
		StatusCode: 200, Outcome: audit.OutcomeSuccess, Namespace: "tenant-a", Version: "v1", Resource: "configmaps",
		ObjectName: "cm", Preview: audit.PreviewFalse, RequestURI: "/call?name=cm", SourceIPs: []string{"10.0.0.1"}}
	accepted := base
	accepted.Client = audit.ClientProvenance{Source: audit.ClientSourcePortal, AgentSessionID: "example-session",
		ConfirmedSet: &audit.ConfirmedSet{Count: 2, SHA256: "0a08bb91090b111f15a045b6061bccc4d0b8488d85f99ba57d8632e17061c277", Op: 1}}
	e.Emit(sessionCtx(t), accepted)
	r := rec.Only(t)
	required := audit.RequiredKeys(audit.WriterRequest, audittest.Attributes(r))
	for _, k := range []string{audit.KeyClientSource, audit.KeyClientConfirmedSetCount, audit.KeyClientConfirmedSetIrreversible,
		audit.KeyClientConfirmedSetSHA256, audit.KeyClientConfirmedSetOp} {
		if !slices.Contains(required, k) {
			t.Errorf("%s is not required of a record that carries the portal's provenance: %v", k, required)
		}
		if msgs := failures(t, func(tb testing.TB) { audittest.AssertRemovalDetected(tb, audit.WriterRequest, r, k) }); len(msgs) != 0 {
			t.Errorf("removing %s: %q", k, msgs)
		}
	}

	audittest.AssertEnumsDetected(t, audit.WriterRequest, r)
	// The rejected header's record: rejected alone, a closed set of its own
	// (TestAssertEnumsDetected_ExercisesTheClientSets pins that it is tried).
	rec.Reset()
	rejected := base
	rejected.Client = audit.ClientProvenance{Rejected: audit.ClientRejectedSchema}
	e.Emit(sessionCtx(t), rejected)
	audittest.AssertConformant(t, audit.WriterRequest, rec.Only(t))
	audittest.AssertEnumsDetected(t, audit.WriterRequest, rec.Only(t))
}

// The #33 review's probe values for an inbound session.id, through the real
// Emit: each record is conformant with the session gap allowed, and carries
// the marker, never the value.
func TestEmit_InvalidInboundSessionIDConformsMarked(t *testing.T) {
	for _, v := range []string{"a:b", "a+b=c", "a b", "x/y@z"} {
		m, err := baggage.NewMemberRaw(audit.BaggageSessionKey, v)
		if err != nil {
			t.Fatalf("%q: %v", v, err)
		}
		b, _ := baggage.New(m)
		ctx := baggage.ContextWithBaggage(spanCtx(t), b)
		rec := audittest.NewRecorder(t)
		audit.New(rec.Logger("test/audit"), audit.WithWriter(audit.WriterRequest)).Emit(ctx, audit.Event{
			UserName: "system:serviceaccount:example-system:example-controller", ActorClass: audit.ClassService,
			Action: "authn.username.check", Verb: "get", HTTPMethod: "GET", Outcome: audit.OutcomeSuccess,
			CheckResult: audit.CheckResultAvailable, Namespace: "example-system", Version: "v1", Resource: "secrets",
			ObjectName: "example-user-clientconfig", Preview: audit.PreviewFalse, RequestURI: "/usernames/check",
			SourceIPs: []string{"192.0.2.10"}})
		r := rec.Only(t)
		audittest.AssertConformant(t, audit.WriterRequest, r, audittest.AllowIncomplete(audit.KeySessionID))
		marked := false
		for _, kv := range audittest.Attributes(r) {
			switch string(kv.Key) {
			case audit.KeySessionID:
				t.Errorf("%q: session.id written", v)
			case audit.KeyIncomplete:
				marked = slices.Contains(strings.Split(kv.Value.AsString(), ","), "session")
			}
		}
		if !marked {
			t.Errorf("%q: the record is not marked session", v)
		}
	}
}

// audit#26: the falsifiers run on a conformant authn.username.check success
// record. Removing krateo.action makes Check report check_result
// not-for-action, which is right (its closed set is the action's), so the
// falsifier counts it as related, not as collateral damage: the relation is
// read from the schema's per-action sets, not named.
func TestFalsifiers_UsernameCheckSuccess(t *testing.T) {
	rec := audittest.NewRecorder(t)
	audit.New(rec.Logger("test/audit"), audit.WithWriter(audit.WriterRequest)).Emit(sessionCtx(t), audit.Event{
		UserName: "system:serviceaccount:example-system:example-controller", ActorClass: audit.ClassService,
		Action: "authn.username.check", Verb: "get", HTTPMethod: "GET", Outcome: audit.OutcomeSuccess,
		CheckResult: audit.CheckResultAvailable, Namespace: "example-system", Version: "v1", Resource: "secrets",
		ObjectName: "example-user-clientconfig", Preview: audit.PreviewFalse, RequestURI: "/usernames/check",
		SourceIPs: []string{"192.0.2.10"}})
	r := rec.Only(t)
	audittest.AssertConformant(t, audit.WriterRequest, r)

	// The precondition the fix is about: without krateo.action, Check reports
	// the check result too. Without it this test would prove nothing.
	removed := audit.Check(audit.WriterRequest, audittest.Without(audittest.Attributes(r), audit.KeyAction))
	if !slices.Contains(removed, audit.Violation{Key: audit.KeyCheckResult, Reason: audit.ReasonNotForAction}) {
		t.Fatalf("precondition: removing krateo.action does not report check_result not-for-action: %v", removed)
	}

	if msgs := failures(t, func(tb testing.TB) { audittest.AssertRemovalDetected(tb, audit.WriterRequest, r, audit.KeyAction) }); len(msgs) != 0 {
		t.Errorf("AssertRemovalDetected(krateo.action): %q", msgs)
	}
	if msgs := failures(t, func(tb testing.TB) { audittest.AssertRequiredKeysDetected(tb, audit.WriterRequest, r) }); len(msgs) != 0 {
		t.Errorf("AssertRequiredKeysDetected: %q", msgs)
	}
	if msgs := failures(t, func(tb testing.TB) { audittest.AssertEnumsDetected(tb, audit.WriterRequest, r) }); len(msgs) != 0 {
		t.Errorf("AssertEnumsDetected: %q", msgs)
	}
	// The removal is still detected: krateo.action is reported missing.
	if !slices.Contains(removed, audit.Violation{Key: audit.KeyAction, Reason: audit.ReasonMissing}) {
		t.Errorf("removing krateo.action is not reported missing: %v", removed)
	}
}

// AssertEnumsDetected replaces each closed-set value, the writer's own
// denial reason included, and needs a conformant record to start from.
func TestAssertEnumsDetected(t *testing.T) {
	rec, w := controllerRecord(t, audit.Event{Action: "rest.write", Verb: "delete", Outcome: audit.OutcomeDenied,
		DenialReason: audit.DenialReasonKeptResourcePolicy, ServerAddress: "api.example.com"})
	r := rec.Only(t)
	if msgs := failures(t, func(tb testing.TB) { audittest.AssertEnumsDetected(tb, w, r) }); len(msgs) != 0 {
		t.Errorf("a conformant kept deletion: %q", msgs)
	}
	// The same record judged as a request writer's is not conformant.
	msgs := failures(t, func(tb testing.TB) { audittest.AssertEnumsDetected(tb, audit.WriterRequest, r) })
	if len(msgs) != 1 || !strings.Contains(msgs[0], "needs a conformant record") {
		t.Errorf("falsifier on a non-conformant record: %q", msgs)
	}
	// A denial reason outside the writer's set is what the falsifier writes:
	// Check must report it, or the check the falsifier relies on is gone.
	bad := slices.Clone(audittest.Attributes(r))
	for i, kv := range bad {
		if kv.Key == audit.KeyDenialReason {
			bad[i] = attribute.String(audit.KeyDenialReason, audit.DenialReasonNameClaimed) // authn's value, not the controller's
		}
	}
	audittest.AssertViolation(t, w, bad, audit.KeyDenialReason)
}

// fakeTB records failures instead of failing, so the helpers' own failures
// can be asserted. Fatalf ends the goroutine, as testing.T's does.
type fakeTB struct {
	testing.TB
	mu   sync.Mutex
	msgs []string
}

func (f *fakeTB) Helper() {}
func (f *fakeTB) Errorf(format string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.msgs = append(f.msgs, fmt.Sprintf(format, args...))
}
func (f *fakeTB) Fatalf(format string, args ...any) {
	f.Errorf(format, args...)
	runtime.Goexit()
}

// failures runs fn against a fakeTB and returns what it reported.
func failures(t *testing.T, fn func(tb testing.TB)) []string {
	f := &fakeTB{TB: t}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		fn(f)
	}()
	wg.Wait()
	return f.msgs
}

func controllerRecord(t *testing.T, ev audit.Event) (*audittest.Recorder, audit.Writer) {
	rec := audittest.NewRecorder(t)
	audit.New(rec.Logger("test/audit"), audit.WithActor(sa, audit.ClassController)).Emit(spanCtx(t), ev)
	return rec, audit.WriterController
}

func TestAssertConformant_FailsOnABreach(t *testing.T) {
	rec, w := controllerRecord(t, audit.Event{Action: "rest.write", ServerAddress: "h", Outcome: audit.OutcomeSuccess}) // no verb
	r := rec.Only(t)
	msgs := failures(t, func(tb testing.TB) { audittest.AssertConformant(tb, w, r) })
	if len(msgs) != 1 || !strings.Contains(msgs[0], audit.KeyVerb+": incomplete") {
		t.Errorf("AssertConformant on a record without a verb reported %q", msgs)
	}
	if msgs := failures(t, func(tb testing.TB) { audittest.AssertConformant(tb, w, r, audittest.AllowIncomplete(audit.KeyVerb)) }); len(msgs) != 0 {
		t.Errorf("AllowIncomplete(verb) still fails: %q", msgs)
	}
}

func TestAssertRemovalDetected_FailsWhenTheRemovalIsNotCaught(t *testing.T) {
	rec, w := controllerRecord(t, audit.Event{Action: "rest.write", Verb: "post", ServerAddress: "h", Outcome: audit.OutcomeSuccess, StatusCode: 201})
	r := rec.Only(t)
	// http.response.status_code is conditional on what the record cannot show:
	// removing it is not detected, and the falsifier must say so.
	msgs := failures(t, func(tb testing.TB) { audittest.AssertRemovalDetected(tb, w, r, audit.KeyHTTPStatusCode) })
	if len(msgs) == 0 || !strings.Contains(msgs[0], "is not detected") {
		t.Errorf("removing an optional key was reported as detected: %q", msgs)
	}
	// Positive control: a required key is caught.
	if msgs := failures(t, func(tb testing.TB) { audittest.AssertRemovalDetected(tb, w, r, audit.KeyVerb) }); len(msgs) != 0 {
		t.Errorf("removing verb: %q", msgs)
	}
	// A key the record does not carry proves nothing.
	if msgs := failures(t, func(tb testing.TB) { audittest.AssertRemovalDetected(tb, w, r, audit.KeyPreview) }); len(msgs) != 1 || !strings.Contains(msgs[0], "does not carry") {
		t.Errorf("removing an absent key: %q", msgs)
	}
}

func TestAssertRemovalDetected_NeedsAConformantRecord(t *testing.T) {
	rec, w := controllerRecord(t, audit.Event{Action: "rest.write", ServerAddress: "h", Outcome: audit.OutcomeSuccess}) // no verb
	r := rec.Only(t)
	msgs := failures(t, func(tb testing.TB) { audittest.AssertRemovalDetected(tb, w, r, audit.KeyAction) })
	if len(msgs) != 1 || !strings.Contains(msgs[0], "needs a conformant record") {
		t.Errorf("falsifier on a non-conformant record: %q", msgs)
	}
}

func TestAssertViolation(t *testing.T) {
	attrs := []attribute.KeyValue{attribute.String("krateo.audit.bogus", "x")}
	if msgs := failures(t, func(tb testing.TB) {
		audittest.AssertViolation(tb, audit.WriterController, attrs, "krateo.audit.bogus")
	}); len(msgs) != 0 {
		t.Errorf("an unknown key is not a violation: %q", msgs)
	}
	if msgs := failures(t, func(tb testing.TB) { audittest.AssertViolation(tb, audit.WriterController, attrs, audit.KeyObjectKind) }); len(msgs) != 1 {
		t.Errorf("AssertViolation passed for a key with no violation: %q", msgs)
	}
}

// The helpers' messages name keys and reasons, never a value.
func TestHelpers_NeverPrintAValue(t *testing.T) {
	const secret = "carol.identity.marker"
	rec, w := controllerRecord(t, audit.Event{Action: secret, AffectedUser: secret, ObjectName: secret, Outcome: "nope-" + secret})
	r := rec.Only(t)
	all := failures(t, func(tb testing.TB) { audittest.AssertConformant(tb, w, r) })
	all = append(all, failures(t, func(tb testing.TB) { audittest.AssertRemovalDetected(tb, w, r, audit.KeyAction) })...)
	if len(all) == 0 {
		t.Fatal("precondition: the record should fail")
	}
	for _, m := range all {
		if strings.Contains(m, secret) {
			t.Errorf("a helper printed a value: %q", m)
		}
	}
}
