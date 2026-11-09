package audit

import (
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"go.opentelemetry.io/otel/attribute"
)

// Reason says why a record breaks the schema.
type Reason string

// The violation reasons.
const (
	// ReasonMissing: a key the writer must write here is absent and not
	// marked in krateo.audit.incomplete.
	ReasonMissing Reason = "missing"
	// ReasonIncomplete: a key the writer must write here is absent and the
	// record marks it in krateo.audit.incomplete. The record is honest about
	// the gap, and still incomplete.
	ReasonIncomplete Reason = "incomplete"
	// ReasonNotInSchema: the key is not in the schema (the closed set).
	ReasonNotInSchema Reason = "not-in-schema"
	// ReasonNotForWriter: the schema says this writer cannot establish the
	// key (not_established) or that it does not apply (not_applicable).
	ReasonNotForWriter Reason = "not-for-writer"
	// ReasonBadType: the value has the wrong type.
	ReasonBadType Reason = "bad-type"
	// ReasonBadEnum: the value is not one of the key's values.
	ReasonBadEnum Reason = "bad-enum"
	// ReasonBadFormat: the value breaks the key's format (a delegation link,
	// a marker list).
	ReasonBadFormat Reason = "bad-format"
	// ReasonEmpty: the key is written with an empty value. An unset field is
	// omitted, never written empty.
	ReasonEmpty Reason = "empty"
	// ReasonInvalidUTF8: a string is not valid UTF-8; the OTLP exporter drops
	// the whole batch it is in.
	ReasonInvalidUTF8 Reason = "invalid-utf8"
	// ReasonDuplicate: the key appears more than once.
	ReasonDuplicate Reason = "duplicate"
	// ReasonMarkedButPresent: krateo.audit.incomplete marks a key the record
	// carries.
	ReasonMarkedButPresent Reason = "marked-but-present"
	// ReasonTwoTargets: the record names a Kubernetes object and an external
	// endpoint, for a writer whose record has exactly one target.
	ReasonTwoTargets Reason = "two-targets"
	// ReasonLegacyWithoutReplacement: a v0.3 key is written without the key
	// that replaces it.
	ReasonLegacyWithoutReplacement Reason = "legacy-without-replacement"
	// ReasonLegacyDisagrees: a v0.3 key and its replacement hold different
	// values.
	ReasonLegacyDisagrees Reason = "legacy-disagrees"
	// ReasonAffectedUserIsActor: krateo.audit.affected_user.name equals
	// user.name. The affected user is someone the actor acted on; when the
	// actor acted on themselves, user.name already says so.
	ReasonAffectedUserIsActor Reason = "affected-user-is-actor"
	// ReasonUnknownWriter: the writer class is not in the schema.
	ReasonUnknownWriter Reason = "unknown-writer"
	// ReasonBadEventName: the LogRecord EventName is not "audit".
	ReasonBadEventName Reason = "bad-event-name"
)

// Violation is one way a record breaks the schema. Key is an attribute key,
// RuleTarget for the target rule, KeyLogRecordEventName for the LogRecord
// EventName, or "" for the writer itself. It never holds a value: audit
// values are identity-bearing.
type Violation struct {
	Key    string
	Reason Reason
}

// KeyLogRecordEventName is the Violation.Key of the LogRecord EventName field.
const KeyLogRecordEventName = "LogRecord.EventName"

func (v Violation) String() string { return v.Key + ": " + string(v.Reason) }

// Check validates one record's attributes against the schema for writer w. It
// reports, in a fixed order: per attribute, keys outside the closed set, keys
// this writer cannot write, type, enum, format and UTF-8 errors, duplicates;
// then every key the writer must write here that is absent (missing, or
// incomplete when marked); then the target rule; then the W1 pairs; then an
// affected user equal to the actor. An empty result means the record
// conforms.
//
// Check sees attributes only. CheckRecord also checks the LogRecord EventName.
func Check(w Writer, attrs []attribute.KeyValue) []Violation {
	if !slices.Contains(schemaWriters, w) {
		return []Violation{{Reason: ReasonUnknownWriter}}
	}
	var out []Violation
	present := map[string]attribute.Value{}
	for _, kv := range attrs {
		k := string(kv.Key)
		if !utf8.ValidString(k) {
			out = append(out, Violation{Key: validUTF8(k), Reason: ReasonInvalidUTF8})
			continue
		}
		if _, dup := present[k]; dup {
			out = append(out, Violation{Key: k, Reason: ReasonDuplicate})
			continue
		}
		present[k] = kv.Value
		i, ok := schemaIndex[k]
		if !ok {
			out = append(out, Violation{Key: k, Reason: ReasonNotInSchema})
			continue
		}
		spec := &schemaKeys[i]
		if spec.Writers[w].Level <= LevelNotEstablished {
			out = append(out, Violation{Key: k, Reason: ReasonNotForWriter})
			continue
		}
		if r, bad := checkValue(spec, kv.Value); bad {
			out = append(out, Violation{Key: k, Reason: r})
		}
	}

	marked := markersOf(present)
	for _, m := range schemaMarkers {
		if !marked[m] {
			continue
		}
		if k, ok := markerKey[m]; ok {
			if _, here := present[k]; here {
				out = append(out, Violation{Key: k, Reason: ReasonMarkedButPresent})
			}
		} else if m == schemaTarget.Marker && targets(present) > 0 {
			out = append(out, Violation{Key: RuleTarget, Reason: ReasonMarkedButPresent})
		}
	}
	for i := range schemaKeys {
		spec := &schemaKeys[i]
		if _, here := present[spec.Name]; here || !mustWrite(spec.Writers[w], present) {
			continue
		}
		if spec.Writers[w].Markable && marked[spec.Marker] {
			out = append(out, Violation{Key: spec.Name, Reason: ReasonIncomplete})
		} else {
			out = append(out, Violation{Key: spec.Name, Reason: ReasonMissing})
		}
	}

	switch n := targets(present); {
	case n == 0 && marked[schemaTarget.Marker]:
		out = append(out, Violation{Key: RuleTarget, Reason: ReasonIncomplete})
	case n == 0:
		out = append(out, Violation{Key: RuleTarget, Reason: ReasonMissing})
	case n > 1 && schemaTarget.Writers[w] == TargetExactlyOne:
		out = append(out, Violation{Key: RuleTarget, Reason: ReasonTwoTargets})
	}

	for i := range schemaKeys {
		spec := &schemaKeys[i]
		old, here := present[spec.Name]
		if spec.ReplacedBy == "" || !here {
			continue
		}
		switch cur, ok := present[spec.ReplacedBy]; {
		case !ok:
			out = append(out, Violation{Key: spec.Name, Reason: ReasonLegacyWithoutReplacement})
		case old.Type() != cur.Type() || old.String() != cur.String():
			out = append(out, Violation{Key: spec.Name, Reason: ReasonLegacyDisagrees})
		}
	}

	if a, ok := present[KeyAffectedUser]; ok {
		if u, ok := present[KeyUserName]; ok && a.Type() == attribute.STRING && a.AsString() == u.AsString() {
			out = append(out, Violation{Key: KeyAffectedUser, Reason: ReasonAffectedUserIsActor})
		}
	}
	return out
}

// CheckRecord is Check plus the LogRecord EventName, which is a record field
// rather than an attribute.
func CheckRecord(w Writer, eventName string, attrs []attribute.KeyValue) []Violation {
	out := Check(w, attrs)
	if eventName != EventName {
		out = append(out, Violation{Key: KeyLogRecordEventName, Reason: ReasonBadEventName})
	}
	return out
}

// RequiredKeys returns the keys writer w must write on this record, as Check
// decides it: the required keys, and the conditional keys whose condition
// holds on attrs. It is what a falsifier removes, one at a time.
func RequiredKeys(w Writer, attrs []attribute.KeyValue) []string {
	present := map[string]attribute.Value{}
	for _, kv := range attrs {
		present[string(kv.Key)] = kv.Value
	}
	var out []string
	for i := range schemaKeys {
		if mustWrite(schemaKeys[i].Writers[w], present) {
			out = append(out, schemaKeys[i].Name)
		}
	}
	return out
}

// mustWrite reports whether a key with requirement r must be on a record that
// carries present: it is required, or conditional and its condition holds,
// or conditional on what the record cannot show and markable (so present or
// marked).
func mustWrite(r Requirement, present map[string]attribute.Value) bool {
	switch {
	case r.Level == LevelRequired:
		return true
	case r.Level != LevelConditional:
		return false
	case r.Check != "":
		holds, _ := evalCondition(r.Check, present)
		return holds
	default:
		return r.Markable
	}
}

// evalCondition evaluates c on the record's attributes. known is false for a
// condition this checker has no rule for; a test keeps that set empty.
func evalCondition(c Condition, present map[string]attribute.Value) (holds, known bool) {
	has := func(k string) bool { _, ok := present[k]; return ok }
	switch c {
	case CondK8sTarget:
		return k8sTarget(present), true
	case CondK8sTargetNamespaced:
		return k8sTarget(present) && has(KeyNamespace), true
	case CondDelegated:
		return has(KeyDelegation) || has(KeyOnBehalfOf), true
	case CondImpersonated:
		return has(KeyImpersonatedUser) || has(KeyImpersonatedRoles), true
	}
	return false, false
}

const objectRefPrefix = "krateo.audit.object_ref."

// k8sTarget reports whether the record names a Kubernetes object.
func k8sTarget(present map[string]attribute.Value) bool {
	if _, ok := present[KeyNamespace]; ok {
		return true
	}
	for k := range present {
		if strings.HasPrefix(k, objectRefPrefix) {
			return true
		}
	}
	return false
}

// targets counts the target keys the record carries.
func targets(present map[string]attribute.Value) int {
	n := 0
	for _, k := range schemaTarget.Keys {
		if _, ok := present[k]; ok {
			n++
		}
	}
	return n
}

// markerKey maps each key marker to its key.
var markerKey = func() map[string]string {
	m := map[string]string{}
	for _, k := range schemaKeys {
		if k.Marker != "" {
			m[k.Marker] = k.Name
		}
	}
	return m
}()

// markersOf returns the markers krateo.audit.incomplete lists.
func markersOf(present map[string]attribute.Value) map[string]bool {
	v, ok := present[KeyIncomplete]
	if !ok || v.Type() != attribute.STRING || v.AsString() == "" {
		return nil
	}
	out := map[string]bool{}
	for _, m := range strings.Split(v.AsString(), ",") {
		out[m] = true
	}
	return out
}

// missingMarkers returns, in schema order, the markers of the gaps attrs has
// for every writer in ws that can write the key: a key is marked when each of
// them would have to write it here. The target marker is listed when the
// record names no target.
func missingMarkers(ws []Writer, attrs []attribute.KeyValue) []string {
	present := map[string]attribute.Value{}
	for _, kv := range attrs {
		present[string(kv.Key)] = kv.Value
	}
	var out []string
	for i := range schemaKeys {
		spec := &schemaKeys[i]
		if spec.Marker == "" {
			continue
		}
		if _, here := present[spec.Name]; here {
			continue
		}
		gap, writable := true, false
		for _, w := range ws {
			r := spec.Writers[w]
			if r.Level <= LevelNotEstablished {
				continue
			}
			writable = true
			if !mustWrite(r, present) {
				gap = false
				break
			}
		}
		if gap && writable {
			out = append(out, spec.Marker)
		}
	}
	if targets(present) == 0 {
		out = append(out, schemaTarget.Marker)
	}
	return out
}

// checkValue checks one value against its key's type, enum and format.
func checkValue(spec *KeySpec, v attribute.Value) (Reason, bool) {
	if !hasType(spec.Type, v) {
		return ReasonBadType, true
	}
	if !allValidUTF8(v) {
		return ReasonInvalidUTF8, true
	}
	switch spec.Type {
	case TypeString:
		s := v.AsString()
		if s == "" {
			return ReasonEmpty, true
		}
		if len(spec.Values) > 0 && !slices.Contains(spec.Values, s) {
			return ReasonBadEnum, true
		}
	case TypeBool:
		if len(spec.Values) > 0 && !slices.Contains(spec.Values, strconv.FormatBool(v.AsBool())) {
			return ReasonBadEnum, true
		}
	case TypeStringSlice:
		if len(stringList(v)) == 0 {
			return ReasonEmpty, true
		}
	}
	switch spec.Format {
	case "delegation_link":
		for _, l := range stringList(v) {
			c, sub, ok := strings.Cut(l, ":")
			if !ok || sub == "" || (c != "" && !Class(c).Known()) {
				return ReasonBadFormat, true
			}
		}
	case "marker_list":
		seen := map[string]bool{}
		for _, m := range strings.Split(v.AsString(), ",") {
			if seen[m] || !slices.Contains(schemaMarkers, m) {
				return ReasonBadFormat, true
			}
			seen[m] = true
		}
	}
	return "", false
}

// hasType reports whether v is of type t. A string list is a STRINGSLICE or a
// SLICE of strings: both are an OTLP array of strings on the wire.
func hasType(t ValueType, v attribute.Value) bool {
	switch t {
	case TypeString:
		return v.Type() == attribute.STRING
	case TypeBool:
		return v.Type() == attribute.BOOL
	case TypeInt:
		return v.Type() == attribute.INT64
	case TypeStringSlice:
		if v.Type() == attribute.STRINGSLICE {
			return true
		}
		if v.Type() != attribute.SLICE {
			return false
		}
		for _, e := range v.AsSlice() {
			if e.Type() != attribute.STRING {
				return false
			}
		}
		return true
	}
	return false
}

// stringList returns the strings of a string-list value.
func stringList(v attribute.Value) []string {
	if v.Type() == attribute.STRINGSLICE {
		return v.AsStringSlice()
	}
	var out []string
	for _, e := range v.AsSlice() {
		out = append(out, e.AsString())
	}
	return out
}
