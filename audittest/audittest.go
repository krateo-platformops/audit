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
// a v0.3 key it replaces, or the target rule when key is a target key; anything else
// means the removal broke more than the one key.
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
	related := map[string]bool{key: true}
	for _, k := range audit.Keys() {
		if k.ReplacedBy == key {
			related[k.Name] = true // its v0.3 name, now without its replacement
		}
	}
	if slices.Contains(audit.Target().Keys, key) {
		related[audit.RuleTarget] = true
	}

	fresh := slices.DeleteFunc(audit.Check(w, Without(attrs, key)), func(v audit.Violation) bool {
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
