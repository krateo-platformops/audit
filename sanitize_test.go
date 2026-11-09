package audit

// The UTF-8 sanitiser is TOTAL over the attribute value kinds of
// go.opentelemetry.io/otel/attribute (ported from snowplow#1261,
// TestUTF8_1251_K): every kind the API defines has a case in SanitizeValue and
// a sample here, and a kind added by an otel upgrade fails this arm until it
// gets both. internal/otlpwire sends the results through the real exporter.

import (
	"context"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"go.opentelemetry.io/otel/attribute"
)

// kindSamples is one value of each kind, holding invalid UTF-8 wherever the
// kind can hold a string.
var kindSamples = map[attribute.Type]attribute.Value{
	attribute.EMPTY:        {},
	attribute.BOOL:         attribute.BoolValue(true),
	attribute.INT64:        attribute.Int64Value(7),
	attribute.FLOAT64:      attribute.Float64Value(1.5),
	attribute.STRING:       attribute.StringValue("s-\xff"),
	attribute.BOOLSLICE:    attribute.BoolSliceValue([]bool{true}),
	attribute.INT64SLICE:   attribute.Int64SliceValue([]int64{1}),
	attribute.FLOAT64SLICE: attribute.Float64SliceValue([]float64{1}),
	attribute.STRINGSLICE:  attribute.StringSliceValue([]string{"ok", "ss-\xff"}),
	attribute.BYTESLICE:    attribute.ByteSliceValue([]byte{0xff, 0xfe}),
	attribute.SLICE: attribute.SliceValue(
		attribute.StringValue("n-\xff"),
		attribute.SliceValue(attribute.StringValue("nn-\xff")),
		attribute.MapValue(attribute.String("k", "nm-\xff"))),
	attribute.MAP: attribute.MapValue(
		attribute.String("key-\xff", "v-\xff"),
		attribute.Map("inner", attribute.String("ik", "iv-\xff")),
		attribute.Slice("list", attribute.StringValue("l-\xff"))),
}

// definedKinds is every attribute.Type the API names: the stringer writes
// "Type(N)" for a number it does not know.
func definedKinds() []attribute.Type {
	var out []attribute.Type
	for t := attribute.Type(0); t < 64; t++ {
		if !strings.HasPrefix(t.String(), "Type(") {
			out = append(out, t)
		}
	}
	return out
}

func TestSanitize_EveryKindHasACase(t *testing.T) {
	kinds := definedKinds()
	if len(kinds) < len(kindSamples) {
		t.Fatalf("the API names %d kinds, fewer than the %d samples: the kind enumeration is broken", len(kinds), len(kindSamples))
	}
	for _, k := range kinds {
		if !slices.Contains(sanitizeKindsHandled, k) {
			t.Errorf("attribute kind %v has no case in SanitizeValue: decide what an invalid string in it becomes", k)
		}
		in, ok := kindSamples[k]
		if !ok {
			t.Errorf("attribute kind %v has no sample in this arm", k)
			continue
		}
		if in.Type() != k {
			t.Fatalf("precondition: the %v sample is a %v", k, in.Type())
		}
		// Precondition: every sample that can hold a string holds an invalid one.
		holdsString := k == attribute.STRING || k == attribute.STRINGSLICE || k == attribute.SLICE || k == attribute.MAP
		if holdsString && allValidUTF8(in) {
			t.Fatalf("precondition: the %v sample holds no invalid string, so the arm proves nothing", k)
		}
		out := SanitizeValue(in)
		if out.Type() != k {
			t.Errorf("%v: the sanitiser changed the kind to %v", k, out.Type())
		}
		if !allValidUTF8(out) {
			t.Errorf("%v: a string is still not valid UTF-8 after the sanitiser: %v", k, out.String())
		}
		if k == attribute.BYTESLICE && string(out.AsByteSlice()) != "\xff\xfe" {
			t.Errorf("BYTESLICE changed (%q): bytes are not strings on the wire and stay as they are", out.AsByteSlice())
		}
	}
	if kv := Sanitize(attribute.String("bad-\xff-key", "v")); !utf8.ValidString(string(kv.Key)) {
		t.Errorf("key %q is still not valid UTF-8", kv.Key)
	}
}

func TestSanitize_ValidInputIsUnchanged(t *testing.T) {
	for k, v := range map[string]attribute.Value{
		"string": attribute.StringValue("café"),
		"slice":  attribute.StringSliceValue([]string{"a", "é"}),
		"map":    attribute.MapValue(attribute.String("k", "v")),
	} {
		if got := SanitizeValue(v); got.String() != v.String() || got.Type() != v.Type() {
			t.Errorf("%s: %v became %v", k, v.String(), got.String())
		}
	}
	if got := validUTF8("a\xffb"); got != "a�b" {
		t.Errorf("validUTF8 = %q, want U+FFFD for the invalid byte", got)
	}
}

// Emit sanitises every attribute and the body, for every field a client or an
// upstream can fill, including the W1 twin of a field.
func TestEmit_EveryStringIsValidUTF8(t *testing.T) {
	e, rec := newEmitter(t)
	e.Emit(context.Background(), Event{
		Message: "upstream said \xfe\xff", UserName: "bob-\xff", UserRoles: []string{"g-\xff"},
		Namespace: "ns", Version: "v1", Resource: "configmaps", ObjectName: "cm-\xff",
		Action: "call", Verb: "create", Outcome: OutcomeFailure, Preview: PreviewFalse,
		RequestURI: "/call?name=cm-\xff", UserAgent: "probe-\xff-ua", SourceIPs: []string{"203.0.113.7"},
		AffectedUser: "carol-\xff", Delegation: []Link{{ClassAgent, "bot-\xff"}},
	})
	r := only(t, rec)
	if !utf8.ValidString(r.Body().AsString()) {
		t.Errorf("body %q is not valid UTF-8", r.Body().AsString())
	}
	for k, v := range attrs(r) {
		if !utf8.ValidString(k) || !allValidUTF8(v) {
			t.Errorf("%s = %q is not valid UTF-8", k, v.String())
		}
	}
	if got := attrs(r)["k8s.resource.name"].AsString(); got != "cm-�" {
		t.Errorf("the W1 twin k8s.resource.name = %q, want it sanitised like its replacement", got)
	}
}

// The User-Agent is cut as the apiserver cuts it, never through a character.
func TestEmit_UserAgentIsCutOnACharacter(t *testing.T) {
	ua := strings.Repeat("a", maxUserAgentLength-1) + "é" + "tail"
	got := truncateUserAgent(ua)
	if !utf8.ValidString(got) {
		t.Fatalf("cut through a character: %q", got[len(got)-20:])
	}
	if want := strings.Repeat("a", maxUserAgentLength-1) + userAgentTruncateSuffix; got != want {
		t.Errorf("truncated UA = ...%q, want ...%q", got[len(got)-20:], want[len(want)-20:])
	}
	if short := "portal/1.0"; truncateUserAgent(short) != short {
		t.Errorf("a short UA changed")
	}
}
