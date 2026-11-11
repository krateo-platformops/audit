// Package audittest helps a writer test its own emit sites against the audit
// schema: drive each site through the real OTel Logs SDK, assert the record
// conforms, and prove the check can fail on it.
//
//	rec := audittest.NewRecorder(t)
//	e := audit.New(rec.Logger("my-controller/audit"), audit.WithActor(sa, audit.ClassController))
//	runTheEmitSite(ctx, e)
//	r := rec.Only(t)
//	audittest.AssertConformant(t, audit.WriterController, r)
//	audittest.AssertRequiredKeysDetected(t, audit.WriterController, r) // the falsifier
//	audittest.AssertEnumsDetected(t, audit.WriterController, r)        // and for the closed sets
//
// Failure messages name keys and reasons, never values: audit values carry
// identity.
package audittest

import (
	"context"
	"slices"
	"sync"
	"testing"

	"github.com/krateo-platformops/audit"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

// Recorder is a real OTel Logs SDK LoggerProvider whose exporter keeps every
// record in memory, so a test sees what the SDK would export.
type Recorder struct {
	lp *sdklog.LoggerProvider

	mu      sync.Mutex
	records []sdklog.Record
}

// NewRecorder returns a Recorder, shut down when t ends.
func NewRecorder(t testing.TB) *Recorder {
	t.Helper()
	r := &Recorder{}
	r.lp = sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(exporter{r})))
	t.Cleanup(func() { _ = r.lp.Shutdown(context.Background()) })
	return r
}

// Logger returns a logger of the Recorder's provider with the given
// instrumentation scope name.
func (r *Recorder) Logger(scope string) log.Logger { return r.lp.Logger(scope) }

// Records returns every record emitted so far.
func (r *Recorder) Records() []sdklog.Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.records)
}

// Only returns the one record emitted so far, and fails t unless there is
// exactly one.
func (r *Recorder) Only(t testing.TB) sdklog.Record {
	t.Helper()
	recs := r.Records()
	if len(recs) != 1 {
		t.Fatalf("audittest: %d records emitted, want exactly 1", len(recs))
	}
	return recs[0]
}

// Reset forgets every record emitted so far.
func (r *Recorder) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = nil
}

type exporter struct{ r *Recorder }

func (e exporter) Export(_ context.Context, recs []sdklog.Record) error {
	e.r.mu.Lock()
	defer e.r.mu.Unlock()
	for _, rec := range recs {
		e.r.records = append(e.r.records, rec.Clone())
	}
	return nil
}
func (exporter) Shutdown(context.Context) error   { return nil }
func (exporter) ForceFlush(context.Context) error { return nil }

// Attributes returns a record's attributes.
func Attributes(rec sdklog.Record) []attribute.KeyValue {
	out := make([]attribute.KeyValue, 0, rec.AttributesLen())
	rec.WalkAttributes(func(kv attribute.KeyValue) bool {
		out = append(out, kv)
		return true
	})
	return out
}

// Without returns attrs without key.
func Without(attrs []attribute.KeyValue, key string) []attribute.KeyValue {
	return slices.DeleteFunc(slices.Clone(attrs), func(kv attribute.KeyValue) bool { return string(kv.Key) == key })
}

// Option relaxes AssertConformant.
type Option func(*settings)

type settings struct{ allowIncomplete map[string]bool }

// AllowIncomplete accepts a record marked krateo.audit.incomplete for the
// given keys (or audit.RuleTarget): use it for a site whose record cannot
// establish them (the token carries no principal claim yet, a method the
// verb rule does not know). Every other violation still fails.
func AllowIncomplete(keys ...string) Option {
	return func(s *settings) {
		for _, k := range keys {
			s.allowIncomplete[k] = true
		}
	}
}

// AssertConformant fails t unless rec conforms to the schema for writer w:
// audit.CheckRecord reports nothing (apart from what AllowIncomplete
// accepts).
func AssertConformant(t testing.TB, w audit.Writer, rec sdklog.Record, opts ...Option) {
	t.Helper()
	for _, v := range unaccepted(audit.CheckRecord(w, rec.EventName(), Attributes(rec)), opts) {
		t.Errorf("audittest: %s record does not conform: %s", w, v)
	}
}

// unaccepted drops the violations opts accept.
func unaccepted(vs []audit.Violation, opts []Option) []audit.Violation {
	s := settings{allowIncomplete: map[string]bool{}}
	for _, o := range opts {
		o(&s)
	}
	return slices.DeleteFunc(vs, func(v audit.Violation) bool {
		return v.Reason == audit.ReasonIncomplete && s.allowIncomplete[v.Key]
	})
}

// AssertViolation fails t unless audit.Check, for writer w, reports a
// violation on key for attrs.
func AssertViolation(t testing.TB, w audit.Writer, attrs []attribute.KeyValue, key string) {
	t.Helper()
	vs := audit.Check(w, attrs)
	if !slices.ContainsFunc(vs, func(v audit.Violation) bool { return v.Key == key }) {
		t.Errorf("audittest: Check(%s) reports no violation on %s; it reports %v", w, key, vs)
	}
}

// AssertRemovalDetected is the falsifier for one key: rec must conform (opts
// as for AssertConformant), and the same attributes without key must make
// audit.Check newly report key missing. Any other new violation must name key,
// a v0.3 key it replaces, the target rule when key is a target key, or a key
// whose only_when condition held and no longer does once key is gone; anything
// else means the removal broke more than the one key.
//
// It mutates the checker's input, never its logic, so a green arm shows the
// check fails when the site stops writing key.
func AssertRemovalDetected(t testing.TB, w audit.Writer, rec sdklog.Record, key string, opts ...Option) {
	t.Helper()
	attrs := Attributes(rec)
	base := audit.CheckRecord(w, rec.EventName(), attrs)
	if vs := unaccepted(slices.Clone(base), opts); len(vs) > 0 {
		t.Fatalf("audittest: falsifier needs a conformant record first; it reports %v", vs)
	}
	if !carries(attrs, key) {
		t.Fatalf("audittest: the record does not carry %s, so removing it proves nothing", key)
	}
	removed := Without(attrs, key)
	related := relatedTo(key, attrs, removed)
	if slices.Contains(audit.Target().Keys, key) {
		related[audit.RuleTarget] = true
	}

	fresh := slices.DeleteFunc(audit.Check(w, removed), func(v audit.Violation) bool {
		return slices.Contains(base, v)
	})
	if !slices.Contains(fresh, audit.Violation{Key: key, Reason: audit.ReasonMissing}) {
		t.Errorf("audittest: removing %s from a %s record is not detected: Check newly reports %v", key, w, fresh)
	}
	for _, v := range fresh {
		if !related[v.Key] {
			t.Errorf("audittest: removing %s also reports %s", key, v)
		}
	}
}

// relatedTo is the keys a change to key from attrs to mutated may newly
// report besides key itself: its v0.3 name, every key written only under a
// condition that held on attrs and no longer does (krateo.audit.dry_run once
// krateo.audit.verb is gone, krateo.audit.denial_reason once the outcome is
// not denied). A key's not_when condition (http.response.status_code's
// denied, the client keys' client_rejected) never turns true under these
// mutations: removing a key or writing a value outside a closed set makes
// neither an outcome denied nor a header rejected.
func relatedTo(key string, attrs, mutated []attribute.KeyValue) map[string]bool {
	related := map[string]bool{key: true}
	for _, k := range audit.Keys() {
		if k.ReplacedBy == key {
			related[k.Name] = true
		}
		if k.OnlyWhen != "" && audit.Holds(k.OnlyWhen, attrs) && !audit.Holds(k.OnlyWhen, mutated) {
			related[k.Name] = true
		}
	}
	return related
}

// outsideTheSet is the value AssertEnumsDetected writes in place of a closed
// set's value: no schema enum names it.
const outsideTheSet = "audittest.outside-the-closed-set"

// AssertEnumsDetected is the falsifier for the closed sets: rec must conform
// (opts as for AssertConformant), and for every key rec carries whose values
// writer w may only pick from a closed set (the key's enum, or the writer's
// own set, as for krateo.audit.denial_reason), the same attributes with that
// value replaced by one outside the set must make audit.Check newly report
// the key bad-enum. Any other new violation must name the key, its v0.3 name,
// or a key whose only_when condition the new value turned false.
//
// It mutates the checker's input, never its logic, so a green arm shows the
// check fails when the site writes a value the schema does not allow.
func AssertEnumsDetected(t testing.TB, w audit.Writer, rec sdklog.Record, opts ...Option) {
	t.Helper()
	attrs := Attributes(rec)
	base := audit.CheckRecord(w, rec.EventName(), attrs)
	if vs := unaccepted(slices.Clone(base), opts); len(vs) > 0 {
		t.Fatalf("audittest: falsifier needs a conformant record first; it reports %v", vs)
	}
	var tested []string
	defer func() {
		if enumsTested != nil {
			enumsTested(tested)
		}
	}()
	for i, kv := range attrs {
		spec, ok := audit.LookupKey(string(kv.Key))
		if !ok || len(spec.Values)+len(spec.Writers[w].Values) == 0 {
			continue
		}
		var bad attribute.Value
		switch spec.Type {
		case audit.TypeString:
			bad = attribute.StringValue(outsideTheSet)
		case audit.TypeBool:
			bad = attribute.BoolValue(!kv.Value.AsBool())
		default:
			continue
		}
		tested = append(tested, spec.Name)
		mutated := slices.Clone(attrs)
		mutated[i] = attribute.KeyValue{Key: kv.Key, Value: bad}
		related := relatedTo(spec.Name, attrs, mutated)

		fresh := slices.DeleteFunc(audit.Check(w, mutated), func(v audit.Violation) bool {
			return slices.Contains(base, v)
		})
		if !slices.Contains(fresh, audit.Violation{Key: spec.Name, Reason: audit.ReasonBadEnum}) {
			t.Errorf("audittest: a %s value outside the closed set on a %s record is not detected: Check newly reports %v", spec.Name, w, fresh)
		}
		for _, v := range fresh {
			if !related[v.Key] {
				t.Errorf("audittest: a %s value outside the closed set also reports %s", spec.Name, v)
			}
		}
	}
	if len(tested) == 0 {
		t.Fatalf("audittest: the record carries no key with a closed set for %s: the falsifier would test nothing", w)
	}
}

// enumsTested, when set (by this package's own tests only), receives the keys
// one AssertEnumsDetected call exercised, so a test can pin which closed sets
// it covers: a writer's own set (krateo.audit.denial_reason) must not go quiet
// behind the key-level enums that every record carries.
var enumsTested func(keys []string)

// AssertRequiredKeysDetected runs AssertRemovalDetected for every key writer
// w must write on rec that rec carries (audit.RequiredKeys): each one, removed
// alone, must be caught.
func AssertRequiredKeysDetected(t testing.TB, w audit.Writer, rec sdklog.Record, opts ...Option) {
	t.Helper()
	attrs := Attributes(rec)
	keys := slices.DeleteFunc(audit.RequiredKeys(w, attrs), func(k string) bool { return !carries(attrs, k) })
	if len(keys) == 0 {
		t.Fatalf("audittest: the record carries no key %s must write: the falsifier would test nothing", w)
	}
	for _, k := range keys {
		AssertRemovalDetected(t, w, rec, k, opts...)
	}
}

func carries(attrs []attribute.KeyValue, key string) bool {
	return slices.ContainsFunc(attrs, func(kv attribute.KeyValue) bool { return string(kv.Key) == key })
}
