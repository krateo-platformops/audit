package audit

import (
	"slices"
	"strings"
	"unicode/utf8"

	"go.opentelemetry.io/otel/attribute"
)

// utf8Replacement replaces each invalid byte sequence of a value: U+FFFD, what
// the apiserver's JSON-encoded audit log writes for one (encoding/json).
const utf8Replacement = "�"

// Sanitize returns kv with its key and every string its value holds, at any
// depth, made valid UTF-8: each invalid byte sequence becomes U+FFFD. Emit
// calls it on every attribute, so no emit site can skip it.
//
// WHY. Many values on a record come from what a client or an upstream sent: a
// User-Agent, a request URI, a name decoded from a query (name=cm-%FF decodes
// to the byte 0xFF), an upstream's failure message. otlploghttp marshals a
// batch with protobuf, which refuses a string field that is not valid UTF-8
// ("string field contains invalid UTF-8"), and the batch processor then drops
// the WHOLE batch: every other record in it never reaches the trail, with
// nothing in the trail to show the gap (snowplow#1261). The apiserver's audit,
// whose semantics these records follow, is JSON-encoded and gets the same
// replacement from its encoder.
func Sanitize(kv attribute.KeyValue) attribute.KeyValue {
	return attribute.KeyValue{Key: attribute.Key(validUTF8(string(kv.Key))), Value: SanitizeValue(kv.Value)}
}

// SanitizeValue returns v with every string it holds made valid UTF-8, at any
// depth. It is TOTAL over the attribute value kinds of
// go.opentelemetry.io/otel/attribute: every kind has its own case, and
// TestSanitize_EveryKindHasACase fails when the API defines a kind this switch
// does not name. The LogRecord body is an attribute.Value too, so Emit sends
// the body through it as well.
//
//   - STRING, STRINGSLICE: each string is made valid.
//   - SLICE, MAP: recursed; a MAP's keys are strings on the wire too.
//   - BYTESLICE: left as it is. OTLP carries it as AnyValue.bytes_value, a
//     protobuf `bytes` field, which has no UTF-8 requirement.
//   - EMPTY, BOOL, INT64, FLOAT64 and their slices: hold no string.
//
// An unknown kind is returned unchanged: the exporter writes such a value as
// the string "INVALID", which cannot poison a batch.
func SanitizeValue(v attribute.Value) attribute.Value {
	switch v.Type() {
	case attribute.STRING:
		if s := v.AsString(); !utf8.ValidString(s) {
			return attribute.StringValue(validUTF8(s))
		}
	case attribute.STRINGSLICE:
		vs := v.AsStringSlice()
		for i, s := range vs {
			if !utf8.ValidString(s) {
				out := slices.Clone(vs)
				for j := i; j < len(out); j++ {
					out[j] = validUTF8(out[j])
				}
				return attribute.StringSliceValue(out)
			}
		}
	case attribute.SLICE:
		vs := v.AsSlice()
		out := make([]attribute.Value, len(vs))
		for i, e := range vs {
			out[i] = SanitizeValue(e)
		}
		return attribute.SliceValue(out...)
	case attribute.MAP:
		kvs := v.AsMap()
		out := make([]attribute.KeyValue, len(kvs))
		for i, kv := range kvs {
			out[i] = Sanitize(kv)
		}
		return attribute.MapValue(out...)
	case attribute.BYTESLICE:
		// protobuf bytes: no UTF-8 requirement (see above).
	case attribute.EMPTY, attribute.BOOL, attribute.INT64, attribute.FLOAT64,
		attribute.BOOLSLICE, attribute.INT64SLICE, attribute.FLOAT64SLICE:
		// no string inside.
	}
	return v
}

// sanitizeKindsHandled names every attribute kind SanitizeValue has a case
// for; TestSanitize_EveryKindHasACase compares it with the kinds the API
// defines.
var sanitizeKindsHandled = []attribute.Type{
	attribute.STRING, attribute.STRINGSLICE, attribute.SLICE, attribute.MAP, attribute.BYTESLICE,
	attribute.EMPTY, attribute.BOOL, attribute.INT64, attribute.FLOAT64,
	attribute.BOOLSLICE, attribute.INT64SLICE, attribute.FLOAT64SLICE,
}

// validUTF8 returns s with every invalid UTF-8 sequence replaced by U+FFFD.
func validUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(s, utf8Replacement)
}

// allValidUTF8 reports whether every string v holds, at any depth, is valid.
// BYTESLICE is bytes on the wire and is not a string.
func allValidUTF8(v attribute.Value) bool {
	switch v.Type() {
	case attribute.STRING:
		return utf8.ValidString(v.AsString())
	case attribute.STRINGSLICE:
		for _, s := range v.AsStringSlice() {
			if !utf8.ValidString(s) {
				return false
			}
		}
	case attribute.SLICE:
		for _, e := range v.AsSlice() {
			if !allValidUTF8(e) {
				return false
			}
		}
	case attribute.MAP:
		for _, kv := range v.AsMap() {
			if !utf8.ValidString(string(kv.Key)) || !allValidUTF8(kv.Value) {
				return false
			}
		}
	}
	return true
}
