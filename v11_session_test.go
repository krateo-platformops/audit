package audit

import (
	"context"
	"slices"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
)

// session_id's character set, pinned by hand (the #33 review): these rows are
// written out, not derived from the generated pattern, so widening the
// pattern (to ':' or '/', say) and regenerating turns this test red.
var sessionIDPins = []struct {
	name  string
	value string
	valid bool
}{
	{"an id authn mints (32 lowercase hex)", "0123456789abcdef0123456789abcdef", true},
	{"a trace id (32 hex)", "4bf92f3577b34da6a3ce929d0e0e4736", true},
	{"a UUID", "00000000-0000-4000-8000-0000000000aa", true},
	{"example-session", "example-session", true},
	{"exactly 128 characters", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true},
	{"':'", "a:b", false},
	{"'/'", "a/b", false},
	{"'+'", "a+b", false},
	{"'='", "a=b", false},
	{"'@'", "a@b", false},
	{"a space", "a b", false},
	{"empty", "", false},
	{"129 characters", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false},
}

func TestSessionID_CharacterSetIsPinned(t *testing.T) {
	if n := len(sessionIDPins[4].value); n != 128 {
		t.Fatalf("precondition: the 128-character row is %d long", n)
	}
	if n := len(sessionIDPins[len(sessionIDPins)-1].value); n != 129 {
		t.Fatalf("precondition: the 129-character row is %d long", n)
	}
	for _, p := range sessionIDPins {
		t.Run(p.name, func(t *testing.T) {
			if got := ValidSessionID(p.value); got != p.valid {
				t.Errorf("ValidSessionID(%q) = %v, want %v", p.value, got, p.valid)
			}
			if err := ValidValue(KeySessionID, p.value); (err == nil) != p.valid {
				t.Errorf("ValidValue(session.id, %q) = %v, want valid %v", p.value, err, p.valid)
			}
			rec := with(baseRecord(WriterRequest), attribute.String(KeySessionID, p.value))
			reported := slices.ContainsFunc(Check(WriterRequest, rec), func(v Violation) bool { return v.Key == KeySessionID })
			if reported == p.valid {
				t.Errorf("Check on session.id = %q reports it %v, want valid %v", p.value, reported, p.valid)
			}
		})
	}
}

// usernameCheckEvent is a conforming request Event: authn's completed check.
func usernameCheckEvent() Event {
	return Event{UserName: "system:serviceaccount:example-system:example-controller", ActorClass: ClassService,
		Action: usernameCheck, Verb: "get", HTTPMethod: "GET", Outcome: OutcomeSuccess, CheckResult: CheckResultAvailable,
		Namespace: "example-system", Version: "v1", Resource: "secrets", ObjectName: "example-user-clientconfig",
		Preview: PreviewFalse, RequestURI: "/usernames/check", SourceIPs: []string{"192.0.2.10"}}
}

// withRawSession is ctx whose baggage carries session.id = v, as an inbound
// baggage header can, unvalidated.
func withRawSession(t testing.TB, ctx context.Context, v string) (context.Context, bool) {
	t.Helper()
	m, err := baggage.NewMemberRaw(BaggageSessionKey, v)
	if err != nil {
		return ctx, false
	}
	b, err := baggage.New(m)
	if err != nil {
		return ctx, false
	}
	return baggage.ContextWithBaggage(ctx, b), true
}

// emitWithSession emits the conforming Event under a raw inbound session.id
// and returns the record's attributes.
func emitWithSession(t testing.TB, v string) (map[string]attribute.Value, bool) {
	t.Helper()
	ctx, ok := withRawSession(t, context.Background(), v)
	if !ok {
		return nil, false
	}
	e, rec := newEmitter(t.(*testing.T), WithWriter(WriterRequest))
	e.Emit(ctx, usernameCheckEvent())
	return attrs(only(t.(*testing.T), rec)), true
}

// Emit never writes an inbound session.id its own Check rejects (the #33
// review): it omits the key and marks it session. A valid one is written.
func TestEmit_InvalidInboundSessionIDIsOmittedAndMarked(t *testing.T) {
	for _, v := range []string{"a:b", "a+b=c", "a b", "x/y@z"} {
		got, ok := emitWithSession(t, v)
		if !ok {
			t.Fatalf("%q: no baggage member", v)
		}
		if _, here := got[KeySessionID]; here {
			t.Errorf("%q: Emit wrote it", v)
		}
		if !slices.Contains(strings.Split(got[KeyIncomplete].AsString(), ","), "session") {
			t.Errorf("%q: not marked session: incomplete = %q", v, got[KeyIncomplete].AsString())
		}
		if vs := Check(WriterRequest, kvs(got)); !slices.Equal(vs, []Violation{{Key: KeySessionID, Reason: ReasonIncomplete}}) {
			t.Errorf("%q: Check = %v, want only session.id marked incomplete", v, vs)
		}
	}
	got, _ := emitWithSession(t, "example-session")
	if got[KeySessionID] != attribute.StringValue("example-session") {
		t.Errorf("a valid session.id is not written: %v", got[KeySessionID].Emit())
	}
	if vs := Check(WriterRequest, kvs(got)); len(vs) > 0 {
		t.Errorf("a valid session.id: %v", vs)
	}
}

// For any inbound session.id, Emit's record passes its own Check: the record
// conforms with the id, or carries only the session mark without it.
func FuzzEmit_RecordPassesItsOwnCheck(f *testing.F) {
	for _, p := range sessionIDPins {
		f.Add(p.value)
	}
	for _, v := range []string{"a:b", "a+b=c", "a b", "x/y@z", "\n", "\x00", "é", "a,b;c", "%20"} {
		f.Add(v)
	}
	f.Fuzz(func(t *testing.T, v string) {
		ctx, ok := withRawSession(t, context.Background(), v)
		if !ok {
			return // not a value baggage can carry
		}
		e, rec := newEmitter(t, WithWriter(WriterRequest))
		e.Emit(ctx, usernameCheckEvent())
		got := attrs(only(t, rec))
		vs := Check(WriterRequest, kvs(got))
		switch {
		case ValidSessionID(v):
			if len(vs) > 0 || got[KeySessionID] != attribute.StringValue(v) {
				t.Fatalf("valid %q: violations %v, session.id %v", v, vs, got[KeySessionID].Emit())
			}
		default:
			if !slices.Equal(vs, []Violation{{Key: KeySessionID, Reason: ReasonIncomplete}}) {
				t.Fatalf("invalid %q: Check = %v, want only session.id marked incomplete", v, vs)
			}
		}
	})
}
