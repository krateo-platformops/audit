package audit

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
)

// v0.11.0 (audit#32): the schema's value formats as exported validators,
// generated from schema/v1.yaml's formats, and Check uses exactly them.

// Every format schema/v1.yaml declares has its generated validator and a
// rule, and every key's format is declared.
func TestFormats_EveryDeclaredFormatHasItsValidator(t *testing.T) {
	formats := Formats()
	if len(formats) == 0 {
		t.Fatal("the schema declares no format: the check would test nothing")
	}
	for _, f := range formats {
		if _, ok := formatRule(f); !ok {
			t.Errorf("format %s has no rule: ValidFormat would refuse every value", f)
		}
		if formatValidators[f] == nil {
			t.Errorf("format %s has no generated Valid* function", f)
		}
	}
	if len(formatValidators) != len(formats) {
		t.Errorf("%d generated validators for %d formats", len(formatValidators), len(formats))
	}
	if ValidFormat("no_such_format", "x") {
		t.Error("ValidFormat accepts a value of a format the schema does not declare")
	}
	for _, k := range Keys() {
		if k.Format != "" && !slices.Contains(formats, k.Format) {
			t.Errorf("key %s declares format %q, which the schema does not list", k.Name, k.Format)
		}
	}
}

// formatCases is the shared table: per format, values each validator must
// accept or refuse. A format the schema declares without rows here fails
// TestFormats_CheckAndTheExportsAgree.
var formatCases = map[string][]struct {
	value string
	valid bool
}{
	FormatOpaqueID: {
		{"a", true}, {"A-z_09", true}, {strings.Repeat("a", 128), true},
		{strings.Repeat("a", 129), false}, {"", false},
		{"name@example.com", false},                             // an email
		{"abc\ndef", false}, {"abc\n", false}, {"\nabc", false}, // a newline, inside and at either end
		{"séance", false}, {"日本", false}, // unicode
		{" a", false}, {"a.b", false}, {"a/b", false},
	},
	FormatUUID: {
		{"00000000-0000-4000-8000-0000000000aa", true},
		{"00000000-0000-4000-8000-0000000000AA", false}, {"000000000000400080000000000000aa", false},
		{"00000000-0000-4000-8000-0000000000aa\n", false}, {"00000000-0000-4000-8000-0000000000a", false}, {"", false},
	},
	FormatSHA256Hex: {
		{strings.Repeat("a", 64), true}, {strings.Repeat("0", 64), true},
		{strings.Repeat("a", 63), false}, {strings.Repeat("a", 65), false}, {strings.Repeat("A", 64), false},
		{strings.Repeat("a", 64) + "\n", false}, {"", false},
	},
	FormatContentHash: {
		{"c1:" + strings.Repeat("a", 64), true},
		{"c2:" + strings.Repeat("a", 64), false}, {"c1:" + strings.Repeat("a", 63), false},
		{strings.Repeat("a", 64), false}, {"c1:" + strings.Repeat("a", 64) + "\n", false}, {"", false},
	},
	FormatRFC3339: {
		{"2026-11-11T10:00:00Z", true}, {"2026-11-11T10:00:00.123Z", true}, {"2026-11-11T10:00:00+01:00", true},
		{"2026-11-11", false}, {"2026-11-11T10:00:00", false}, {"2026-11-11T10:00:00Z\n", false}, {"", false},
	},
	FormatMarkerList: {
		{"actor", true}, {"actor,verb", true},
		{"actor,actor", false}, {"not-a-marker", false}, {"actor,", false}, {"", false},
	},
	FormatDelegationLink: {
		{"agent:example-agent", true}, {":example-subject", true},
		{"agent:", false}, {"bogus:example-subject", false}, {"example-subject", false}, {"", false},
	},
}

// Check and the exported validators agree on every row of the table, for
// every key that declares the format, on a writer that may write the key:
// Check reports the key as bad-format (or empty) exactly when ValidFormat,
// the format's Valid* function and ValidValue refuse the value.
func TestFormats_CheckAndTheExportsAgree(t *testing.T) {
	keysOf := map[string][]KeySpec{}
	for _, k := range Keys() {
		if k.Format != "" {
			keysOf[k.Format] = append(keysOf[k.Format], k)
		}
	}
	for _, f := range Formats() {
		rows := formatCases[f]
		if len(rows) == 0 {
			t.Errorf("format %s has no rows in formatCases", f)
			continue
		}
		valid, invalid := 0, 0
		for _, row := range rows {
			if row.valid {
				valid++
			} else {
				invalid++
			}
			if got := ValidFormat(f, row.value); got != row.valid {
				t.Errorf("ValidFormat(%s, %q) = %v, want %v", f, row.value, got, row.valid)
			}
			if got := formatValidators[f](row.value); got != row.valid {
				t.Errorf("Valid* for %s(%q) = %v, want %v", f, row.value, got, row.valid)
			}
			for _, k := range keysOf[f] {
				err := ValidValue(k.Name, row.value)
				var fe *FormatError
				if (err == nil) != row.valid || (err != nil && (!errors.As(err, &fe) || fe.Key != k.Name || fe.Format != f)) {
					t.Errorf("ValidValue(%s, %q) = %v; want valid %v", k.Name, row.value, err, row.valid)
				}
				if err != nil && row.value != "" && strings.Contains(err.Error(), row.value) {
					t.Errorf("ValidValue's error carries the value: %v", err)
				}
				w, ok := writerOf(k)
				if !ok {
					t.Fatalf("no writer may write %s", k.Name)
				}
				v := attribute.StringValue(row.value)
				if k.Type == TypeStringSlice {
					v = attribute.StringSliceValue([]string{row.value})
				}
				reported := slices.ContainsFunc(Check(w, []attribute.KeyValue{{Key: attribute.Key(k.Name), Value: v}}), func(x Violation) bool {
					return x.Key == k.Name && (x.Reason == ReasonBadFormat || x.Reason == ReasonEmpty)
				})
				if reported == row.valid {
					t.Errorf("Check(%s) on %s = %q: reports it %v, but the validators say valid %v", w, k.Name, row.value, reported, row.valid)
				}
			}
		}
		if valid == 0 || invalid == 0 {
			t.Errorf("format %s: %d valid and %d invalid rows; the table needs both", f, valid, invalid)
		}
		if len(keysOf[f]) == 0 {
			t.Errorf("format %s: no key declares it, so Check never applies it", f)
		}
	}
}

// A string-list key's format applies to every element: a list whose first
// element is valid and a later one isn't is reported, and a list of valid
// elements isn't.
func TestFormats_EveryElementOfAListIsChecked(t *testing.T) {
	for _, k := range Keys() {
		if k.Format == "" || k.Type != TypeStringSlice {
			continue
		}
		var good, bad string
		for _, row := range formatCases[k.Format] {
			if row.valid && good == "" {
				good = row.value
			}
			if !row.valid && row.value != "" && bad == "" {
				bad = row.value
			}
		}
		w, _ := writerOf(k)
		for _, tc := range []struct {
			list []string
			want bool
		}{{[]string{good, good}, false}, {[]string{good, bad}, true}, {[]string{bad, good}, true}} {
			got := slices.Contains(Check(w, []attribute.KeyValue{attribute.StringSlice(k.Name, tc.list)}), Violation{Key: k.Name, Reason: ReasonBadFormat})
			if got != tc.want {
				t.Errorf("%s = %q: bad-format %v, want %v", k.Name, tc.list, got, tc.want)
			}
		}
	}
}

// writerOf is a writer class that may write k.
func writerOf(k KeySpec) (Writer, bool) {
	for _, w := range Writers() {
		if k.Writers[w].Level > LevelNotEstablished {
			return w, true
		}
	}
	return "", false
}

// ValidValue on a key with no format accepts any value, and an unknown key
// is ErrUnknownKey.
func TestValidValue(t *testing.T) {
	if err := ValidValue(KeyAction, "anything at all\n"); err != nil {
		t.Errorf("a key with no format: %v", err)
	}
	err := ValidValue("no.such.key", "x")
	if !errors.Is(err, ErrUnknownKey) || !strings.Contains(err.Error(), "no.such.key") {
		t.Errorf("an unknown key: %v", err)
	}
	if err := ValidValue(KeyClientAgentSessionID, "name@example.com"); err == nil || strings.Contains(err.Error(), "name@example.com") {
		t.Errorf("an email as an agent session id: %v", err)
	}
	if !ValidOpaqueID("example-session") || ValidOpaqueID("name@example.com") {
		t.Error("ValidOpaqueID")
	}
}

// No second copy of a format's pattern exists in the module: each lives in
// schema/v1.yaml and in the regexp schema_gen.go compiles from it, and
// nowhere else, so Check and the validators cannot drift apart.
func TestFormats_NoSecondCopyOfAPattern(t *testing.T) {
	var patterns []string
	for _, f := range Formats() {
		if re, ok := formatPatterns[f]; ok {
			patterns = append(patterns, re.String())
		}
	}
	if len(patterns) == 0 {
		t.Fatal("no format has a pattern: the check would test nothing")
	}
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "testdata" || d.Name() == ".git") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || path == "schema_gen.go" {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, p := range patterns {
			if strings.Contains(string(raw), p) {
				t.Errorf("%s holds a copy of the format pattern %s: use the generated validator", path, p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
