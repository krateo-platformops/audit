package audit

// A caller that only bumps from v0.3.0 to v0.4.x keeps emitting every record
// it emitted before, with every attribute it carried and the same value: v0.4
// adds keys and marks gaps, and never drops a record (installer#407: the trail
// records everything).
//
// The oracle, v03Attributes, is v0.3.0's attribute builder (audit.go at tag
// v0.3.0) copied verbatim, so the arm does not lean on v0.4's code to say what
// v0.3 wrote. The shapes are the Events the three v0.3 callers build today,
// field for field.

import (
	"context"
	"maps"
	"slices"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/trace"
)

// v03Attributes is v0.3.0's Emit, from building attrs to rec.AddAttributes.
func v03Attributes(ctx context.Context, ev Event) []attribute.KeyValue {
	attrs := []attribute.KeyValue{attribute.String("event.name", EventName)}
	add := func(k, v string) {
		if v != "" {
			attrs = append(attrs, attribute.String(k, v))
		}
	}
	add("enduser.id", ev.EndUserID)
	add("user.name", ev.UserName)
	add("k8s.namespace.name", ev.Namespace)
	add("k8s.resource.group", ev.Group)
	add("k8s.resource.version", ev.Version)
	add("k8s.resource.resource", ev.Resource)
	add("k8s.resource.subresource", ev.Subresource)
	add("k8s.resource.kind", ev.Kind)
	add("k8s.resource.name", ev.ObjectName)
	add("k8s.object.uid", ev.ObjectUID)
	add("k8s.object.resource_version", ev.ObjectResourceVersion)
	add("server.address", hostPort(ev.ServerAddress))
	add("krateo.action", ev.Action)
	add("http.request.method", ev.HTTPMethod)
	add("outcome", ev.Outcome)

	if ev.ObjectGeneration != 0 {
		attrs = append(attrs, attribute.Int64("k8s.object.generation", ev.ObjectGeneration))
	}
	if len(ev.UserRoles) > 0 {
		vals := make([]attribute.Value, len(ev.UserRoles))
		for i, r := range ev.UserRoles {
			vals[i] = attribute.StringValue(r)
		}
		attrs = append(attrs, attribute.Slice("user.roles", vals...))
	}
	if ev.StatusCode != 0 {
		attrs = append(attrs, attribute.Int("http.response.status_code", ev.StatusCode))
	}
	if m := baggage.FromContext(ctx).Member(BaggageSessionKey); m.Key() != "" {
		attrs = append(attrs, attribute.String("session.id", m.Value()))
	}
	if sc := trace.SpanContextFromContext(ctx); !sc.IsValid() {
		attrs = append(attrs, attribute.Bool("krateo.audit.no_trace_context", true))
	}
	return attrs
}

// v03CallerShapes are the Events the v0.3 callers emit, as their code builds
// them (access-review campaign.go, identity-lifecycle userlifecycle.go and
// groupmembership.go, rest-dynamic-controller restResources.go emitAudit).
var v03CallerShapes = map[string]Event{
	"access-review remove": {Message: "campaign removed", Namespace: "krateo-system",
		Group: "access.krateo.io", Version: "v1alpha1", Resource: "accessreviewcampaigns", Kind: "AccessReviewCampaign",
		ObjectName: "q3", Action: "campaign.remove", Outcome: "success"},
	"access-review snapshot failed": {Message: "failed to snapshot", Namespace: "krateo-system", Group: "", Version: "v1",
		Resource: "configmaps", Kind: "ConfigMap", ObjectName: "q3-snapshot", Action: "campaign.snapshot", Outcome: "failure"},
	"access-review snapshot": {Message: "snapshotted 3 grant(s)", Namespace: "krateo-system", Version: "v1",
		Resource: "configmaps", Kind: "ConfigMap", ObjectName: "q3-snapshot", Action: "campaign.snapshot", Outcome: "success"},
	"access-review evidence": {Message: "evidence report emitted", Namespace: "krateo-system", Version: "v1",
		Resource: "configmaps", Kind: "ConfigMap", ObjectName: "q3-evidence", Action: "campaign.evidence", Outcome: "success"},
	"access-review close": {Message: "campaign closed", Namespace: "krateo-system", Version: "v1",
		Resource: "configmaps", Kind: "ConfigMap", ObjectName: "q3-evidence", Action: "campaign.close", Outcome: "success"},
	"access-review revoke": {Message: "grant revoked", EndUserID: "alice", UserName: "alice", UserRoles: []string{"bob"},
		Namespace: "tenant-a", Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "rolebindings",
		Kind: "RoleBinding", ObjectName: "alice-edit", Action: "campaign.revoke", Outcome: OutcomeDenied},
	"identity-lifecycle deactivate": {Message: "disabled user", EndUserID: "carol", UserName: "carol",
		Namespace: "krateo-system", Group: "identity.krateo.io", Version: "v1alpha1", Resource: "userlifecycles",
		Kind: "UserLifecycle", ObjectName: "carol", Action: "user.deactivate", Outcome: "success"},
	"identity-lifecycle group join": {Message: "joined group", EndUserID: "carol", UserName: "carol",
		Namespace: "krateo-system", Group: "identity.krateo.io", Version: "v1alpha1", Resource: "groupmemberships",
		Kind: "GroupMembership", ObjectName: "carol-devs", Action: "group.join", Outcome: "success"},
	"rest-dynamic-controller write": {Message: "external write succeeded",
		ObjectUID: "uid-1", ObjectGeneration: 4, ObjectResourceVersion: "77",
		Namespace: "tenant-a", Group: "github.krateo.io", Version: "v1alpha1", Kind: "Repo", ObjectName: "demo",
		ServerAddress: "https://api.example.com/v1/repos?token=SECRET", Action: "rest.write", HTTPMethod: "POST",
		StatusCode: 201, Outcome: OutcomeSuccess},
	"rest-dynamic-controller failed write": {Message: "external write failed",
		ObjectUID: "uid-1", ObjectGeneration: 4, Namespace: "tenant-a", Group: "github.krateo.io", Version: "v1alpha1",
		Kind: "Repo", ObjectName: "demo", ServerAddress: "api.example.com", Action: "rest.write", HTTPMethod: "PUT",
		StatusCode: 409, Outcome: OutcomeFailure},
	// No caller sends these today (the RestDefinition CRD's method enum is
	// GET/POST/PUT/DELETE/PATCH), but the library takes any string: v0.3 wrote
	// it as given, and v0.4 must not lose it.
	"a v0.3 caller with a lowercase method": {Message: "external write succeeded",
		ObjectUID: "uid-1", ObjectGeneration: 4, Namespace: "tenant-a", Group: "github.krateo.io", Version: "v1alpha1",
		Kind: "Repo", ObjectName: "demo", ServerAddress: "api.example.com", Action: "rest.write", HTTPMethod: "post",
		StatusCode: 201, Outcome: OutcomeSuccess},
	"a v0.3 caller with a method semconv does not name": {Message: "external write succeeded",
		ServerAddress: "dav.example.com", Action: "rest.write", HTTPMethod: "PROPFIND", StatusCode: 207, Outcome: OutcomeSuccess},
	// A cluster-scoped target: access-review's revoke of a ClusterRoleBinding has no namespace.
	"access-review revoke of a ClusterRoleBinding": {Message: "grant revoked", EndUserID: "alice", UserName: "alice",
		UserRoles: []string{"bob"}, Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterrolebindings",
		Kind: "ClusterRoleBinding", ObjectName: "alice-admin", Action: "campaign.revoke", Outcome: OutcomeDenied},
	"rest-dynamic-controller delegated write": {Message: "external write succeeded",
		ObjectUID: "uid-1", ObjectGeneration: 4, Namespace: "tenant-a", Group: "github.krateo.io", Version: "v1alpha1",
		Kind: "Repo", ObjectName: "demo", ServerAddress: "https://api.example.com", Action: "rest.write",
		Outcome: OutcomeSuccess},
}

func TestV03_APlainBumpKeepsEveryRecordAndEveryAttribute(t *testing.T) {
	for name, ev := range v03CallerShapes {
		for _, ctxName := range []string{"with a span", "without a span"} {
			t.Run(name+", "+ctxName, func(t *testing.T) {
				ctx := context.Background()
				if ctxName == "with a span" {
					ctx = spanCtx(t)
				}
				rec := &recorder{}
				e := New(loggerFor(t, rec)) // a plain bump: v0.3's constructor call, no option
				e.Emit(ctx, ev)
				if len(rec.records) != 1 {
					t.Fatalf("%d records, want the 1 v0.3 emitted", len(rec.records))
				}
				got := attrs(rec.records[0])
				for _, kv := range v03Attributes(ctx, ev) {
					if !keeps(kv, got) {
						v := got[string(kv.Key)]
						t.Errorf("%s: v0.3 wrote %v, v0.4 keeps it nowhere (writes %v)", kv.Key, kv.Value.String(), v.String())
					}
				}
				// krateo.audit.dry_run: a v0.3 caller declares no writer class
				// and sets no DryRun, and the key is the writer class's to
				// require (request and action writes), so a plain bump adds
				// none.
				if v, ok := got[KeyDryRun]; ok {
					t.Errorf("a plain bump added krateo.audit.dry_run = %v", v.String())
				}
				// A shape that names no actor is emitted marked actor, not dropped.
				if m := strings.Split(got[KeyIncomplete].AsString(), ","); (ev.UserName == "") != slices.Contains(m, "actor") {
					t.Errorf("actor marked = %v for UserName %q (incomplete = %q)", !(ev.UserName == ""), ev.UserName, got[KeyIncomplete].AsString())
				}
			})
		}
	}
}

// krateo.audit.dry_run=false appears only where the writer class says so: the
// same v0.3 shapes, emitted by an Emitter that declares a request or action
// writer, as a write, gain dry_run=false, and still lose and change no v0.3
// value. Declared as a controller (rest-dynamic-controller, access-review,
// identity-lifecycle when they adopt), they gain none.
func TestV03_DryRunFalseOnlyWhereTheWriterClassSaysSo(t *testing.T) {
	for name, ev := range v03CallerShapes {
		ev.Verb = "create" // a write, as an adopting caller sets it
		for _, w := range []Writer{WriterRequest, WriterAction, WriterController} {
			ctx := spanCtx(t)
			rec := &recorder{}
			New(loggerFor(t, rec), WithWriter(w)).Emit(ctx, ev)
			if len(rec.records) != 1 {
				t.Fatalf("%s, %s: %d records", name, w, len(rec.records))
			}
			got := attrs(rec.records[0])
			if n := missingV03(v03Attributes(ctx, ev), got); n != 0 {
				t.Errorf("%s, %s: %d v0.3 values lost or changed", name, w, n)
			}
			v, ok := got[KeyDryRun]
			switch want := w != WriterController; {
			case want && (!ok || v.Type() != attribute.BOOL || v.AsBool()):
				t.Errorf("%s, %s: dry_run = %v (present %v), want false", name, w, v.String(), ok)
			case !want && ok:
				t.Errorf("%s, %s: a controller record gained dry_run = %v", name, w, v.String())
			}
		}
	}
}

// The arm's comparison can fail: a lost v0.3 key, or a changed value, on the
// record v0.4 really emits for an actor-less shape is caught. (A dropped
// record fails the arm's record count before any comparison.)
func TestV03_TheComparisonCanFail(t *testing.T) {
	ev := v03CallerShapes["access-review remove"] // names no actor
	ctx := spanCtx(t)
	want := v03Attributes(ctx, ev)
	rec := &recorder{}
	New(loggerFor(t, rec)).Emit(ctx, ev)
	if len(rec.records) != 1 {
		t.Fatalf("precondition: %d records", len(rec.records))
	}
	got := attrs(rec.records[0])
	if n := missingV03(want, got); n != 0 {
		t.Fatalf("precondition: the real record already misses %d v0.3 attributes", n)
	}
	delete(got, "k8s.resource.kind")
	got["outcome"] = attribute.StringValue("failure")
	if n := missingV03(want, got); n != 2 {
		t.Errorf("a lost key and a changed value: %d caught, want 2", n)
	}
}

// The one sanctioned move, a method semconv does not name recorded as _OTHER,
// is accepted only while http.request.method_original holds v0.3's value.
func TestV03_TheMethodMoveCanFail(t *testing.T) {
	ev := v03CallerShapes["a v0.3 caller with a lowercase method"]
	ctx := spanCtx(t)
	want := v03Attributes(ctx, ev)
	rec := &recorder{}
	New(loggerFor(t, rec)).Emit(ctx, ev)
	got := attrs(rec.records[0])
	if got[KeyHTTPMethod].AsString() != "_OTHER" || missingV03(want, got) != 0 {
		t.Fatalf("precondition: method %q, %d v0.3 attributes missing", got[KeyHTTPMethod].AsString(), missingV03(want, got))
	}
	lost := maps.Clone(got)
	delete(lost, KeyHTTPMethodOriginal)
	changed := maps.Clone(got)
	changed[KeyHTTPMethodOriginal] = attribute.StringValue("POST")
	for name, m := range map[string]map[string]attribute.Value{"lost": lost, "changed": changed} {
		if n := missingV03(want, m); n != 1 {
			t.Errorf("method_original %s: %d caught, want 1", name, n)
		}
	}
}

// loggerFor is a real SDK logger exporting into rec.
func loggerFor(t *testing.T, rec *recorder) otellog.Logger {
	t.Helper()
	lp := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(rec)))
	t.Cleanup(func() { _ = lp.Shutdown(context.Background()) })
	return lp.Logger("test")
}

func missingV03(want []attribute.KeyValue, got map[string]attribute.Value) int {
	n := 0
	for _, kv := range want {
		if !keeps(kv, got) {
			n++
		}
	}
	return n
}

// keeps reports whether the v0.4 record got still carries the v0.3 attribute
// kv: under its own key with the same value, or, for the one move semconv
// requires, a method v0.4 records as _OTHER, under http.request.method_original
// with the same value.
func keeps(kv attribute.KeyValue, got map[string]attribute.Value) bool {
	if v, ok := got[string(kv.Key)]; ok && sameValue(kv.Value, v) {
		return true
	}
	if string(kv.Key) == KeyHTTPMethod && got[KeyHTTPMethod].AsString() == "_OTHER" {
		orig, ok := got[KeyHTTPMethodOriginal]
		return ok && sameValue(kv.Value, orig)
	}
	return false
}

// sameValue compares as the wire does: a SLICE of strings and a STRINGSLICE
// are the same OTLP array of strings.
func sameValue(a, b attribute.Value) bool {
	if hasType(TypeStringSlice, a) && hasType(TypeStringSlice, b) {
		return slices.Equal(stringList(a), stringList(b))
	}
	return a.Type() == b.Type() && a.String() == b.String()
}
