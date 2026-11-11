// Command schemagen generates, from schema/v1.yaml, schema_gen.go (the key
// constants and the checker's rule table) and docs/schema.md (the record
// contract, key by key, with the example records it copies from the Go file
// named by -examples). It runs through `go generate` in the module root;
// TestGeneratedFilesAreCurrent fails when a committed file is not what this
// command produces.
//
// It is the only place the module parses YAML, so the audit package itself
// depends on the OpenTelemetry APIs alone.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/format"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"text/template"

	"go.yaml.in/yaml/v3"
)

func main() {
	in := flag.String("in", "schema/v1.yaml", "schema file")
	out := flag.String("out", "schema_gen.go", "generated Go file")
	doc := flag.String("doc", "docs/schema.md", "generated record contract")
	examples := flag.String("examples", "contract_records_test.go", "Go file holding the example records docs/schema.md shows")
	flag.Parse()

	src, md, err := generate(*in, *examples)
	// Both outputs are committed, world-readable source files: they hold no
	// secret, so they get the mode every other source file has.
	if err == nil {
		err = os.WriteFile(*out, src, 0o644) // #nosec G306 -- generated source file, committed to git
	}
	if err == nil {
		err = os.WriteFile(*doc, md, 0o644) // #nosec G306 -- generated documentation, committed to git
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "schemagen:", err)
		os.Exit(1)
	}
}

// generate reads the schema at path and the example records at examples,
// validates them and returns the Go source and the Markdown contract.
func generate(path, examples string) (src, md []byte, err error) {
	raw, err := os.ReadFile(path) // #nosec G304,G703 -- the schema file go generate names with -in is this tool's input
	if err != nil {
		return nil, nil, err
	}
	s, err := parse(raw)
	if err != nil {
		return nil, nil, err
	}
	ex, err := os.ReadFile(examples) // #nosec G304,G703 -- the examples file go generate names with -examples is this tool's input
	if err != nil {
		return nil, nil, err
	}
	regions, err := exampleRegions(ex)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", examples, err)
	}
	if src, err = render(s); err != nil {
		return nil, nil, err
	}
	return src, renderDoc(s, regions), nil
}

type schema struct {
	Updated           string             `yaml:"updated"`
	SchemaVersion     string             `yaml:"schema_version"`
	EventName         string             `yaml:"event_name"`
	Writers           []writer           `yaml:"writers"`
	Conditions        []condition        `yaml:"conditions"`
	Target            target             `yaml:"target"`
	CredentialTargets []credentialTarget `yaml:"credential_targets"`
	// ContentAnnotations are the annotations the content hash counts.
	ContentAnnotations []string     `yaml:"content_annotations"`
	Populations        []population `yaml:"populations"`
	LegacyControls     []population `yaml:"legacy_controls"`
	Keys               []key        `yaml:"keys"`
}

// credentialTarget is a Kubernetes target that carries a credential: a key
// marked credential_free is never written on a record naming it.
type credentialTarget struct {
	APIGroup    string `yaml:"api_group"`
	Resource    string `yaml:"resource"`
	Subresource string `yaml:"subresource"`
}

type writer struct {
	ID          string `yaml:"id"`
	Code        string `yaml:"code"`
	Go          string `yaml:"go"`
	Description string `yaml:"description"`
}

type condition struct {
	ID          string `yaml:"id"`
	Go          string `yaml:"go"`
	Description string `yaml:"description"`
}

type target struct {
	Marker  string            `yaml:"marker"`
	Keys    []string          `yaml:"keys"`
	Writers map[string]string `yaml:"writers"`
}

type population struct {
	Scope  string `yaml:"scope"`
	Writer string `yaml:"writer"`
	Who    string `yaml:"who"`
	// Note is how a reader selects the population's rows, when that is not
	// obvious from the scope; docs/schema.md shows it under the table.
	Note string `yaml:"note"`
}

type key struct {
	Name       string   `yaml:"name"`
	Go         string   `yaml:"go"`
	Type       string   `yaml:"type"`
	Semconv    string   `yaml:"semconv"`
	Values     []string `yaml:"values"`
	Format     string   `yaml:"format"`
	Marker     string   `yaml:"marker"`
	Identity   bool     `yaml:"identity"`
	Asserted   bool     `yaml:"asserted"`
	ReplacedBy string   `yaml:"replaced_by"`
	DualWrite  *bool    `yaml:"dual_write"`
	OnlyWhen   string   `yaml:"only_when"`
	NotWhen    string   `yaml:"not_when"`
	// CredentialFree: never written on a record whose Kubernetes target is a
	// credential target.
	CredentialFree bool `yaml:"credential_free"`
	// Minimum and LessThan bound an int key: from below, and by another int
	// key of the same record.
	Minimum     *int64                 `yaml:"minimum"`
	LessThan    string                 `yaml:"less_than"`
	Description string                 `yaml:"description"`
	Writers     map[string]requirement `yaml:"writers"`
}

// DualWrites reports whether Emit writes k beside its replacement: a replaced
// key is, unless it says dual_write: false.
func (k key) DualWrites() bool { return k.ReplacedBy != "" && (k.DualWrite == nil || *k.DualWrite) }

// requirement is a scalar level ("required") or a mapping
// ({level: conditional, when: ..., check: ..., markable: true, values: [...]}).
type requirement struct {
	Level    string   `yaml:"level"`
	When     string   `yaml:"when"`
	Check    string   `yaml:"check"`
	Markable bool     `yaml:"markable"`
	Values   []string `yaml:"values"`
}

// requirementFields are the fields a requirement mapping may have. Decoding
// the mapping by hand loses the decoder's KnownFields, so UnmarshalYAML checks
// them itself: an unquoted comma in a flow mapping's `when` silently starts a
// new, unknown field ({when: a, b} is when "a" and a field "b").
var requirementFields = []string{"level", "when", "check", "markable", "values"}

func (r *requirement) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		r.Level = n.Value
		return nil
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i < len(n.Content); i += 2 {
			if f := n.Content[i].Value; !slices.Contains(requirementFields, f) {
				return fmt.Errorf("line %d: requirement field %q is not one of %v (a `when` with a comma must be quoted)", n.Content[i].Line, f, requirementFields)
			}
		}
	}
	type plain requirement
	var p plain
	if err := n.Decode(&p); err != nil {
		return err
	}
	*r = requirement(p)
	return nil
}

var (
	levels   = map[string]string{"required": "LevelRequired", "conditional": "LevelConditional", "optional": "LevelOptional", "not_established": "LevelNotEstablished", "not_applicable": "LevelNotApplicable"}
	types    = map[string]string{"string": "TypeString", "string[]": "TypeStringSlice", "bool": "TypeBool", "int": "TypeInt"}
	semconvs = []string{"stable", "development", "deprecated", "none"}
	formats  = []string{"", "delegation_link", "marker_list", "sha256_hex", "content_hash", "uuid", "opaque_id", "rfc3339"}
	// annotationKey is a prefixed Kubernetes annotation key: a DNS subdomain,
	// a slash, a name. Only a prefixed key can be one a component owns.
	annotationKey = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?/[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`)
	// assertedPrefixes are where the asserted keys live, and only they: a
	// header the gateway saw, and the provenance a client sent the writer.
	assertedPrefixes = []string{"krateo.audit.asserted.", "krateo.audit.client."}
	modes            = map[string]string{"exactly_one": "TargetExactlyOne", "at_least_one": "TargetAtLeastOne"}
	goIdent          = regexp.MustCompile(`^[A-Z][A-Za-z0-9]*$`)
	markerName       = regexp.MustCompile(`^[a-z][a-z_]*$`)
	valueName        = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)*$`)
)

func parse(raw []byte) (*schema, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var s schema
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

func (s *schema) validate() error {
	if s.SchemaVersion == "" || s.EventName == "" || s.Updated == "" {
		return fmt.Errorf("updated, schema_version and event_name are required")
	}
	writerIDs := map[string]bool{}
	for _, w := range s.Writers {
		if w.ID == "" || !goIdent.MatchString(w.Go) || w.Description == "" {
			return fmt.Errorf("writer %q: id, go and description are required", w.ID)
		}
		if writerIDs[w.ID] {
			return fmt.Errorf("writer %q: duplicate", w.ID)
		}
		writerIDs[w.ID] = true
	}
	condIDs := map[string]bool{}
	for _, c := range s.Conditions {
		if c.ID == "" || !goIdent.MatchString(c.Go) || c.Description == "" {
			return fmt.Errorf("condition %q: id, go and description are required", c.ID)
		}
		condIDs[c.ID] = true
	}

	names := map[string]*key{}
	goNames := map[string]bool{}
	markers := map[string]bool{}
	for i := range s.Keys {
		k := &s.Keys[i]
		if k.Name == "" || !goIdent.MatchString(k.Go) || k.Description == "" {
			return fmt.Errorf("key %q: name, go and description are required", k.Name)
		}
		if names[k.Name] != nil || goNames[k.Go] {
			return fmt.Errorf("key %q (%s): duplicate", k.Name, k.Go)
		}
		names[k.Name], goNames[k.Go] = k, true
		if _, ok := types[k.Type]; !ok {
			return fmt.Errorf("key %q: unknown type %q", k.Name, k.Type)
		}
		if !slices.Contains(semconvs, k.Semconv) {
			return fmt.Errorf("key %q: semconv %q is not one of %v", k.Name, k.Semconv, semconvs)
		}
		if !slices.Contains(formats, k.Format) {
			return fmt.Errorf("key %q: unknown format %q", k.Name, k.Format)
		}
		if k.Identity && k.Asserted {
			return fmt.Errorf("key %q: an asserted key is never identity", k.Name)
		}
		if k.Asserted != slices.ContainsFunc(assertedPrefixes, func(p string) bool { return strings.HasPrefix(k.Name, p) }) {
			return fmt.Errorf("key %q: asserted keys, and only they, live under the prefixes %v", k.Name, assertedPrefixes)
		}
		if k.Asserted && (k.Marker != "" || slices.Contains(s.Target.Keys, k.Name)) {
			return fmt.Errorf("key %q: an asserted key is never marked and never a target", k.Name)
		}
		if k.Format != "" && k.Format != "delegation_link" && k.Type != "string" {
			return fmt.Errorf("key %q: format %s needs a string key, not %s", k.Name, k.Format, k.Type)
		}
		if (k.Minimum != nil || k.LessThan != "") && k.Type != "int" {
			return fmt.Errorf("key %q: minimum and less_than bound an int key, not %s", k.Name, k.Type)
		}
		if k.NotWhen != "" && !condIDs[k.NotWhen] {
			return fmt.Errorf("key %q: not_when %q is not a declared condition", k.Name, k.NotWhen)
		}
		if k.NotWhen != "" && k.NotWhen == k.OnlyWhen {
			return fmt.Errorf("key %q: only_when and not_when name the same condition, so the key is never allowed", k.Name)
		}
		if k.CredentialFree && len(s.CredentialTargets) == 0 {
			return fmt.Errorf("key %q: credential_free with no credential_targets", k.Name)
		}
		if len(k.Values) > 0 && k.Type != "string" && k.Type != "bool" {
			return fmt.Errorf("key %q: values need a string or bool key", k.Name)
		}
		if k.Marker != "" {
			if !markerName.MatchString(k.Marker) || markers[k.Marker] {
				return fmt.Errorf("key %q: marker %q is malformed or duplicate", k.Name, k.Marker)
			}
			markers[k.Marker] = true
		}
		if k.DualWrite != nil && k.ReplacedBy == "" {
			return fmt.Errorf("key %q: dual_write goes with, and only with, replaced_by", k.Name)
		}
		if k.OnlyWhen != "" && !condIDs[k.OnlyWhen] {
			return fmt.Errorf("key %q: only_when %q is not a declared condition", k.Name, k.OnlyWhen)
		}
		if k.ReplacedBy != "" {
			if len(k.Writers) != 0 {
				return fmt.Errorf("key %q: a replaced key takes its replacement's writer levels; list none", k.Name)
			}
			continue
		}
		if err := k.validateWriterValues(s.Writers); err != nil {
			return err
		}
		for w := range k.Writers {
			if !writerIDs[w] {
				return fmt.Errorf("key %q: unknown writer %q", k.Name, w)
			}
		}
		for _, w := range s.Writers {
			r, ok := k.Writers[w.ID]
			if !ok {
				return fmt.Errorf("key %q: no requirement for writer %q", k.Name, w.ID)
			}
			if _, ok := levels[r.Level]; !ok {
				return fmt.Errorf("key %q, writer %q: unknown level %q", k.Name, w.ID, r.Level)
			}
			if (r.Level == "conditional") != (r.When != "") {
				return fmt.Errorf("key %q, writer %q: `when` goes with, and only with, conditional", k.Name, w.ID)
			}
			if r.Check != "" && (r.Level != "conditional" || !condIDs[r.Check]) {
				return fmt.Errorf("key %q, writer %q: check %q needs a conditional level and a declared condition", k.Name, w.ID, r.Check)
			}
			if r.Markable && k.Marker == "" {
				return fmt.Errorf("key %q, writer %q: markable needs a marker", k.Name, w.ID)
			}
			if r.Markable && r.Level != "required" && r.Level != "conditional" {
				return fmt.Errorf("key %q, writer %q: only a required or conditional key is markable", k.Name, w.ID)
			}
			if k.Asserted && r.Level == "required" {
				return fmt.Errorf("key %q, writer %q: an asserted key is never required (a client may send nothing)", k.Name, w.ID)
			}
		}
	}
	for _, k := range s.Keys {
		if k.LessThan != "" {
			if o := names[k.LessThan]; o == nil || o.Type != "int" || o.Name == k.Name {
				return fmt.Errorf("key %q: less_than %q is not another int key", k.Name, k.LessThan)
			}
		}
		if k.ReplacedBy == "" {
			continue
		}
		r := names[k.ReplacedBy]
		if r == nil || r.ReplacedBy != "" {
			return fmt.Errorf("key %q: replaced_by %q is not a current key", k.Name, k.ReplacedBy)
		}
		if r.Type != k.Type {
			return fmt.Errorf("key %q: type %s differs from its replacement's %s", k.Name, k.Type, r.Type)
		}
	}

	if !markerName.MatchString(s.Target.Marker) || markers[s.Target.Marker] {
		return fmt.Errorf("target: marker %q is malformed or duplicate", s.Target.Marker)
	}
	if len(s.Target.Keys) != 2 {
		return fmt.Errorf("target: want exactly two keys, a Kubernetes object and an endpoint")
	}
	for _, k := range s.Target.Keys {
		if names[k] == nil {
			return fmt.Errorf("target: unknown key %q", k)
		}
	}
	for _, w := range s.Writers {
		if _, ok := modes[s.Target.Writers[w.ID]]; !ok {
			return fmt.Errorf("target: writer %q has no mode", w.ID)
		}
	}
	seenTargets := map[credentialTarget]bool{}
	for _, c := range s.CredentialTargets {
		if c.Resource == "" || seenTargets[c] {
			return fmt.Errorf("credential target %+v: a resource is required, and each target is listed once", c)
		}
		seenTargets[c] = true
	}
	seenAnnotations := map[string]bool{}
	for _, a := range s.ContentAnnotations {
		if !annotationKey.MatchString(a) || seenAnnotations[a] {
			return fmt.Errorf("content annotation %q: a qualified annotation key (prefix/name), listed once", a)
		}
		seenAnnotations[a] = true
	}
	scopes := map[string]bool{}
	for _, p := range append(slices.Clone(s.Populations), s.LegacyControls...) {
		if p.Scope == "" || !writerIDs[p.Writer] || p.Who == "" {
			return fmt.Errorf("population %q: scope, a known writer and who are required", p.Scope)
		}
		// One writer per scope: the live queries select a writer's rows by
		// scope, so a shared scope would judge one writer's rows by another's
		// rules.
		if scopes[p.Scope] {
			return fmt.Errorf("population %q: duplicate scope", p.Scope)
		}
		scopes[p.Scope] = true
	}
	consts := map[string]string{}
	for _, c := range s.valueConsts() {
		if v, dup := consts[c.Name]; dup && v != c.Value {
			return fmt.Errorf("key %q: values %q and %q both make the constant %s", c.Key, v, c.Value, c.Name)
		}
		consts[c.Name] = c.Value
	}
	return nil
}

// validateWriterValues checks the per-writer closed sets of k: a string key
// with no key-level values, declared by every writer that may write the key,
// and by no other.
func (k *key) validateWriterValues(writers []writer) error {
	declared := false
	for _, r := range k.Writers {
		declared = declared || r.Values != nil
	}
	if !declared {
		return nil
	}
	if k.Type != "string" {
		return fmt.Errorf("key %q: per-writer values need a string key, not %s", k.Name, k.Type)
	}
	if len(k.Values) > 0 {
		return fmt.Errorf("key %q: per-writer values and key-level values exclude each other", k.Name)
	}
	for _, w := range writers {
		r := k.Writers[w.ID]
		writes := r.Level != "not_applicable" && r.Level != "not_established"
		if writes != (len(r.Values) > 0) {
			return fmt.Errorf("key %q, writer %q: every writer that may write a key with per-writer values declares its own, and no other writer does", k.Name, w.ID)
		}
		seen := map[string]bool{}
		for _, v := range r.Values {
			if !valueName.MatchString(v) || seen[v] {
				return fmt.Errorf("key %q, writer %q: value %q is malformed (lower_snake_case) or duplicate", k.Name, w.ID, v)
			}
			seen[v] = true
		}
	}
	return nil
}

// valueConst is one generated constant for a per-writer value.
type valueConst struct {
	Name, Value, Key string
	Writers          []string
}

// valueConsts is a constant per value of every key with per-writer values,
// named after the key's Go name and the value (DenialReasonNameReserved), in
// schema order, each listing the writers that may write it.
func (s *schema) valueConsts() []valueConst {
	var out []valueConst
	for _, k := range s.Keys {
		at := map[string]int{}
		for _, w := range s.Writers {
			for _, v := range k.Writers[w.ID].Values {
				if i, ok := at[v]; ok {
					out[i].Writers = append(out[i].Writers, w.ID)
					continue
				}
				at[v] = len(out)
				out = append(out, valueConst{Name: k.Go + camel(v), Value: v, Key: k.Name, Writers: []string{w.ID}})
			}
		}
	}
	return out
}

// camel is a lower_snake_case value in CamelCase: name_reserved is
// NameReserved.
func camel(v string) string {
	var b strings.Builder
	for _, part := range strings.Split(v, "_") {
		if part != "" {
			b.WriteString(strings.ToUpper(part[:1]) + part[1:])
		}
	}
	return b.String()
}

// markers is every marker, keys first in schema order, then the target rule.
func (s *schema) markers() []string {
	var out []string
	for _, k := range s.Keys {
		if k.Marker != "" {
			out = append(out, k.Marker)
		}
	}
	return append(out, s.Target.Marker)
}

func (s *schema) key(name string) key {
	for _, k := range s.Keys {
		if k.Name == name {
			return k
		}
	}
	return key{}
}

// requirementsOf returns k's requirement per writer. A replaced key takes its
// replacement's, as optional where the replacement may be written.
func (s *schema) requirementsOf(k key) map[string]requirement {
	if k.ReplacedBy == "" {
		return k.Writers
	}
	out := map[string]requirement{}
	for w, r := range s.key(k.ReplacedBy).Writers {
		switch r.Level {
		case "not_established", "not_applicable":
			out[w] = requirement{Level: r.Level}
		default:
			out[w] = requirement{Level: "optional", Values: r.Values}
		}
	}
	return out
}

func render(s *schema) ([]byte, error) {
	funcs := template.FuncMap{
		"q":        strconv.Quote,
		"doc":      doc,
		"level":    func(l string) string { return levels[l] },
		"type":     func(t string) string { return types[t] },
		"mode":     func(m string) string { return modes[m] },
		"writerGo": func(id string) string { return s.writerGo(id) },
		"condGo":   func(id string) string { return s.condGo(id) },
		"reqs":     s.requirementsOf,
		"markers":  s.markers,
		"strs":     strs,
		"consts":   s.valueConsts,
		"join":     strings.Join,
		"deref":    func(p *int64) int64 { return *p },
	}
	t, err := template.New("gen").Funcs(funcs).Parse(tmpl)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, s); err != nil {
		return nil, err
	}
	out, err := format.Source(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("gofmt the generated source: %w\n%s", err, buf.Bytes())
	}
	return out, nil
}

func (s *schema) writerGo(id string) string {
	for _, w := range s.Writers {
		if w.ID == id {
			return w.Go
		}
	}
	return ""
}

func (s *schema) condGo(id string) string {
	for _, c := range s.Conditions {
		if c.ID == id {
			return c.Go
		}
	}
	return ""
}

// doc renders text as a // comment block wrapped at 76 columns.
func doc(prefix, text string) string {
	words := strings.Fields(text)
	var lines []string
	line := "// " + prefix
	for _, w := range words {
		if len(line)+1+len(w) > 79 && line != "//" {
			lines = append(lines, line)
			line = "//"
		}
		line += " " + w
	}
	return strings.Join(append(lines, line), "\n")
}

func strs(v []string) string {
	if len(v) == 0 {
		return "nil"
	}
	q := make([]string, len(v))
	for i, s := range v {
		q[i] = strconv.Quote(s)
	}
	return "[]string{" + strings.Join(q, ", ") + "}"
}

const tmpl = `// Code generated by internal/schemagen from schema/v1.yaml. DO NOT EDIT.

package audit

// SchemaVersion is the schema version this package writes
// (krateo.audit.schema_version).
const SchemaVersion = {{q .SchemaVersion}}

// The schema's keys. Spell a key through these constants, never by hand.
const (
{{- range .Keys}}
	{{doc (printf "Key%s is %q." .Go .Name) .Description}}
{{- if .ReplacedBy}}
	//
	// Deprecated: the v0.3 name of {{.ReplacedBy}}, removed when
	// migration window W1 closes. Read {{.ReplacedBy}}.
{{- end}}
	Key{{.Go}} = {{q .Name}}
{{- end}}
)

{{- with consts}}

// The closed values of the keys whose values depend on the writer. Check
// reports any other value, and a value written by a writer it does not list.
const (
{{- range .}}
	{{doc (printf "%s is %q," .Name .Value) (printf "a %s value of writer %s." .Key (join .Writers ", "))}}
	{{.Name}} = {{q .Value}}
{{- end}}
)
{{- end}}

// The writer classes.
const (
{{- range .Writers}}
	{{doc (printf "%s (%s):" .Go .Code) .Description}}
	{{.Go}} Writer = {{q .ID}}
{{- end}}
)

// The conditions the checker evaluates on a record.
const (
{{- range .Conditions}}
	{{doc (printf "%s:" .Go) .Description}}
	{{.Go}} Condition = {{q .ID}}
{{- end}}
)

var schemaWriters = []Writer{ {{- range .Writers}}{{.Go}}, {{end -}} }

var schemaConditions = []Condition{ {{- range .Conditions}}{{.Go}}, {{end -}} }

var schemaMarkers = {{strs markers}}

var schemaTarget = TargetRule{
	Marker: {{q .Target.Marker}},
	Keys:   {{strs .Target.Keys}},
	Writers: map[Writer]TargetMode{
{{- range $.Writers}}
		{{.Go}}: {{mode (index $.Target.Writers .ID)}},
{{- end}}
	},
}

var schemaCredentialTargets = []CredentialTarget{
{{- range .CredentialTargets}}
	{Group: {{q .APIGroup}}, Resource: {{q .Resource}}, Subresource: {{q .Subresource}}},
{{- end}}
}

var schemaContentAnnotations = {{strs .ContentAnnotations}}

var schemaPopulations = []Population{
{{- range .Populations}}
	{Scope: {{q .Scope}}, Writer: {{writerGo .Writer}}, Who: {{q .Who}}},
{{- end}}
}

var schemaLegacyControls = []Population{
{{- range .LegacyControls}}
	{Scope: {{q .Scope}}, Writer: {{writerGo .Writer}}, Who: {{q .Who}}},
{{- end}}
}

var schemaKeys = []KeySpec{
{{- range $k := .Keys}}
	{
		Name:     Key{{.Go}},
		Type:     {{type .Type}},
		Semconv:  {{q .Semconv}},
		Values:   {{strs .Values}},
		Format:   {{q .Format}},
		Marker:   {{q .Marker}},
		Identity: {{.Identity}},
		Asserted: {{.Asserted}},
		ReplacedBy: {{q .ReplacedBy}},
		DualWrite: {{.DualWrites}},
		OnlyWhen: {{if .OnlyWhen}}{{condGo .OnlyWhen}}{{else}}""{{end}},
		NotWhen: {{if .NotWhen}}{{condGo .NotWhen}}{{else}}""{{end}},
		CredentialFree: {{.CredentialFree}},
		Min: {{if .Minimum}}minOf({{deref .Minimum}}){{else}}nil{{end}},
		LessThan: {{q .LessThan}},
		Description: {{q .Description}},
		Writers: map[Writer]Requirement{
{{- $r := reqs $k}}
{{- range $.Writers}}
{{- $w := index $r .ID}}
			{{.Go}}: {Level: {{level $w.Level}}
				{{- if $w.When}}, When: {{q $w.When}}{{end}}
				{{- if $w.Check}}, Check: {{condGo $w.Check}}{{end}}
				{{- if $w.Markable}}, Markable: true{{end}}
				{{- if $w.Values}}, Values: {{strs $w.Values}}{{end}}},
{{- end}}
		},
	},
{{- end}}
}
`
