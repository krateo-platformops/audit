// Command schemagen generates, from schema/v1.yaml, schema_gen.go (the key
// constants and the checker's rule table) and docs/schema.md (the record
// contract, key by key). It runs through `go generate` in the module root;
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
	flag.Parse()

	src, md, err := generate(*in)
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

// generate reads the schema at path, validates it and returns the Go source
// and the Markdown contract.
func generate(path string) (src, md []byte, err error) {
	raw, err := os.ReadFile(path) // #nosec G304,G703 -- the schema file go generate names with -in is this tool's input
	if err != nil {
		return nil, nil, err
	}
	s, err := parse(raw)
	if err != nil {
		return nil, nil, err
	}
	if src, err = render(s); err != nil {
		return nil, nil, err
	}
	return src, renderDoc(s), nil
}

type schema struct {
	Updated        string       `yaml:"updated"`
	SchemaVersion  string       `yaml:"schema_version"`
	EventName      string       `yaml:"event_name"`
	Writers        []writer     `yaml:"writers"`
	Conditions     []condition  `yaml:"conditions"`
	Target         target       `yaml:"target"`
	Populations    []population `yaml:"populations"`
	LegacyControls []population `yaml:"legacy_controls"`
	Keys           []key        `yaml:"keys"`
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
}

type key struct {
	Name        string                 `yaml:"name"`
	Go          string                 `yaml:"go"`
	Type        string                 `yaml:"type"`
	Semconv     string                 `yaml:"semconv"`
	Values      []string               `yaml:"values"`
	Format      string                 `yaml:"format"`
	Marker      string                 `yaml:"marker"`
	Identity    bool                   `yaml:"identity"`
	Asserted    bool                   `yaml:"asserted"`
	ReplacedBy  string                 `yaml:"replaced_by"`
	DualWrite   *bool                  `yaml:"dual_write"`
	OnlyWhen    string                 `yaml:"only_when"`
	Description string                 `yaml:"description"`
	Writers     map[string]requirement `yaml:"writers"`
}

// DualWrites reports whether Emit writes k beside its replacement: a replaced
// key is, unless it says dual_write: false.
func (k key) DualWrites() bool { return k.ReplacedBy != "" && (k.DualWrite == nil || *k.DualWrite) }

// requirement is a scalar level ("required") or a mapping
// ({level: conditional, when: ..., check: ..., markable: true}).
type requirement struct {
	Level    string `yaml:"level"`
	When     string `yaml:"when"`
	Check    string `yaml:"check"`
	Markable bool   `yaml:"markable"`
}

func (r *requirement) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		r.Level = n.Value
		return nil
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
	levels     = map[string]string{"required": "LevelRequired", "conditional": "LevelConditional", "optional": "LevelOptional", "not_established": "LevelNotEstablished", "not_applicable": "LevelNotApplicable"}
	types      = map[string]string{"string": "TypeString", "string[]": "TypeStringSlice", "bool": "TypeBool", "int": "TypeInt"}
	semconvs   = []string{"stable", "development", "deprecated", "none"}
	formats    = []string{"", "delegation_link", "marker_list"}
	modes      = map[string]string{"exactly_one": "TargetExactlyOne", "at_least_one": "TargetAtLeastOne"}
	goIdent    = regexp.MustCompile(`^[A-Z][A-Za-z0-9]*$`)
	markerName = regexp.MustCompile(`^[a-z][a-z_]*$`)
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
		if k.Asserted != strings.HasPrefix(k.Name, "krateo.audit.asserted.") {
			return fmt.Errorf("key %q: asserted keys, and only they, live under the krateo.audit.asserted prefix", k.Name)
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
		}
	}
	for _, k := range s.Keys {
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
	for _, p := range append(slices.Clone(s.Populations), s.LegacyControls...) {
		if p.Scope == "" || !writerIDs[p.Writer] || p.Who == "" {
			return fmt.Errorf("population %q: scope, a known writer and who are required", p.Scope)
		}
	}
	return nil
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
			out[w] = requirement{Level: "optional"}
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
	// Deprecated: the v0.3 name of {{.ReplacedBy}}, removed in v0.5.0. Read
	// {{.ReplacedBy}}.
{{- end}}
	Key{{.Go}} = {{q .Name}}
{{- end}}
)

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
		Description: {{q .Description}},
		Writers: map[Writer]Requirement{
{{- $r := reqs $k}}
{{- range $.Writers}}
{{- $w := index $r .ID}}
			{{.Go}}: {Level: {{level $w.Level}}
				{{- if $w.When}}, When: {{q $w.When}}{{end}}
				{{- if $w.Check}}, Check: {{condGo $w.Check}}{{end}}
				{{- if $w.Markable}}, Markable: true{{end}}},
{{- end}}
		},
	},
{{- end}}
}
`
