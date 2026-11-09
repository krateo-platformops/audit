package audit

import (
	_ "embed"
	"maps"
	"slices"
)

//go:generate go run ./internal/schemagen -in schema/v1.yaml -out schema_gen.go -doc docs/schema.md

// schemaV1 is THE schema, schema/v1.yaml. The key constants and the checker's
// rules in schema_gen.go are generated from it; a test fails when they are
// stale.
//
//go:embed schema/v1.yaml
var schemaV1 []byte

// SchemaYAML returns a copy of schema/v1.yaml, the schema this package writes
// and checks, for tools that are not written in Go.
func SchemaYAML() []byte { return slices.Clone(schemaV1) }

// Writer is the class of component that records an audit event. The schema
// states, per writer, which keys it must, may or cannot write.
type Writer string

// Class is the class of the principal named in user.name, as its credential
// proves it (krateo.audit.actor_class).
type Class string

// The actor classes. They are authn's `principal` claim values, one to one.
const (
	ClassHuman      Class = "human"
	ClassAgent      Class = "agent"
	ClassController Class = "controller"
	ClassService    Class = "service"
)

// Known reports whether c is one of the four classes.
func (c Class) Known() bool {
	switch c {
	case ClassHuman, ClassAgent, ClassController, ClassService:
		return true
	}
	return false
}

// Level is how strongly a writer must write a key.
type Level uint8

// The requirement levels, weakest first. See schema/v1.yaml.
const (
	LevelNotApplicable  Level = iota // the fact does not exist for this writer
	LevelNotEstablished              // this writer cannot know it; never written
	LevelOptional                    // may be written
	LevelConditional                 // required when Requirement.When holds
	LevelRequired                    // on every record
)

var levelNames = [...]string{"not_applicable", "not_established", "optional", "conditional", "required"}

func (l Level) String() string {
	if int(l) < len(levelNames) {
		return levelNames[l]
	}
	return "Level(?)"
}

// ValueType is the attribute value type of a key.
type ValueType string

// The value types the schema uses.
const (
	TypeString      ValueType = "string"
	TypeStringSlice ValueType = "string[]"
	TypeBool        ValueType = "bool"
	TypeInt         ValueType = "int"
)

// Condition is a condition the checker evaluates on the record itself.
type Condition string

// Requirement is one writer's requirement for one key.
type Requirement struct {
	Level Level
	// When says, for LevelConditional, when the key is required.
	When string
	// Check is the condition the checker evaluates for When, or "" when the
	// condition is not visible on the record.
	Check Condition
	// Markable means a writer that cannot establish the key omits it and names
	// the key's marker in krateo.audit.incomplete.
	Markable bool
}

// KeySpec is one attribute of the schema.
type KeySpec struct {
	Name    string
	Type    ValueType
	Semconv string // stable | development | deprecated | none
	// Values is the closed set of values, when the key is an enum.
	Values []string
	// Format names a structural rule on the value: "delegation_link" or
	// "marker_list".
	Format string
	// Marker is the name the key has in krateo.audit.incomplete.
	Marker string
	// Identity keys carry who someone is, on purpose. They never reach a span
	// or an ordinary log line.
	Identity bool
	// Asserted keys hold a value a client chose: never identity.
	Asserted bool
	// ReplacedBy names the replacement of a v0.3 key written side by side
	// with it during W1 (v0.4.x). Removed in v0.5.0.
	ReplacedBy string
	// DualWrite says Emit adds this v0.3 key beside its replacement. False
	// for a v0.3 key written only where it is written today (enduser.id).
	DualWrite bool
	// OnlyWhen, when set, is the condition the key may be written under, and
	// only under: Check reports the key anywhere else (ReasonUnexpected).
	OnlyWhen    Condition
	Description string
	// Writers holds every writer's requirement.
	Writers map[Writer]Requirement
}

// TargetMode is how many of the target keys a writer's record carries.
type TargetMode string

// The target modes.
const (
	TargetExactlyOne TargetMode = "exactly_one"
	TargetAtLeastOne TargetMode = "at_least_one"
)

// TargetRule is the record-level rule that every record names its target: a
// Kubernetes object (krateo.audit.object_ref.resource) or an external endpoint
// (server.address).
type TargetRule struct {
	Marker  string
	Keys    []string
	Writers map[Writer]TargetMode
}

// Population is where one writer's records land in krateo_audit: the
// instrumentation scope name of the logger it emits on.
type Population struct {
	Scope  string
	Writer Writer
	Who    string
}

// RuleTarget is the Violation.Key of a breach of the target rule.
const RuleTarget = "target"

// Keys returns every key of the schema, in schema order.
func Keys() []KeySpec {
	out := make([]KeySpec, len(schemaKeys))
	for i, k := range schemaKeys {
		out[i] = k.clone()
	}
	return out
}

// LookupKey returns the schema entry of name.
func LookupKey(name string) (KeySpec, bool) {
	i, ok := schemaIndex[name]
	if !ok {
		return KeySpec{}, false
	}
	return schemaKeys[i].clone(), true
}

// Writers returns every writer class, in schema order.
func Writers() []Writer { return slices.Clone(schemaWriters) }

// Markers returns every name krateo.audit.incomplete may list, in the order a
// record lists them.
func Markers() []string { return slices.Clone(schemaMarkers) }

// Target returns the target rule.
func Target() TargetRule {
	t := schemaTarget
	t.Keys = slices.Clone(t.Keys)
	t.Writers = maps.Clone(t.Writers)
	return t
}

// Populations returns where each writer's records land, by scope name.
func Populations() []Population { return slices.Clone(schemaPopulations) }

// LegacyControls returns the scopes of rows written before this schema, the
// positive control of the live conformance query.
func LegacyControls() []Population { return slices.Clone(schemaLegacyControls) }

// LegacyKey returns the v0.3 key Emit writes side by side with key during W1,
// or "" when it writes none (a key with no v0.3 name, or user.name, whose
// v0.3 copy enduser.id is never added).
func LegacyKey(key string) string { return legacyOf[key] }

// Conditions returns every condition the checker evaluates.
func Conditions() []Condition { return slices.Clone(schemaConditions) }

func (k KeySpec) clone() KeySpec {
	k.Values = slices.Clone(k.Values)
	k.Writers = maps.Clone(k.Writers)
	return k
}

var (
	schemaIndex = map[string]int{}
	legacyOf    = map[string]string{}
)

func init() {
	for i, k := range schemaKeys {
		schemaIndex[k.Name] = i
		if k.ReplacedBy != "" && k.DualWrite {
			legacyOf[k.ReplacedBy] = k.Name
		}
	}
}
