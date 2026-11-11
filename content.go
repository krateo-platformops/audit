package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"unicode/utf8"
)

// ErrCredentialTarget is ContentSHA256's refusal of a credential target (a
// Secret): a hash of low-entropy secret data can be guessed offline, so such
// a write carries no content hash.
var ErrCredentialTarget = errors.New("audit: no content hash for a credential target")

// ContentSHA256 returns the lowercase hex SHA-256 of obj's canonical content,
// for krateo.audit.object_ref.content_sha256 (Event.ContentSHA256). group and
// resource are the object's as object_ref names them (group "" for the core
// group). obj is the object the write sends: a typed object, an
// unstructured map, or its JSON (json.RawMessage).
//
// The content, per kind family (docs/schema.md has the rules and a test
// vector):
//   - a ConfigMap (core configmaps): its data and binaryData;
//   - any other object: every top-level field but apiVersion, kind, metadata
//     and status (a custom resource's spec, a RoleBinding's roleRef and
//     subjects).
//
// A field that is absent or null is left out. The canonical form is UTF-8
// JSON with no whitespace, object keys sorted by their bytes, strings with
// only the escapes JSON requires (`\"`, `\\`, and the control characters,
// as \b \f \n \r \t or \u00xx) and every other character raw, and integers
// in decimal. A non-integer number, or obj not being a JSON object, is an
// error: there is no canonical form for it. Bytes that are not valid UTF-8
// become U+FFFD, as encoding/json makes them. A credential target is refused
// with ErrCredentialTarget.
func ContentSHA256(group, resource string, obj any) (string, error) {
	if IsCredentialTarget(group, resource, "") {
		return "", ErrCredentialTarget
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		return "", fmt.Errorf("audit: content hash: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var whole any
	if err := dec.Decode(&whole); err != nil {
		return "", fmt.Errorf("audit: content hash: %w", err)
	}
	fields, ok := whole.(map[string]any)
	if !ok {
		return "", errors.New("audit: content hash: the object is not a JSON object")
	}
	content := map[string]any{}
	for k, v := range fields {
		if v != nil && contentField(group, resource, k) {
			content[k] = v
		}
	}
	var b bytes.Buffer
	if err := canonicalJSON(&b, content); err != nil {
		return "", fmt.Errorf("audit: content hash: %w", err)
	}
	sum := sha256.Sum256(b.Bytes())
	return hex.EncodeToString(sum[:]), nil
}

// contentField reports whether the top-level field k is part of the content
// of an object of (group, resource).
func contentField(group, resource, k string) bool {
	if group == "" && resource == "configmaps" {
		return k == "data" || k == "binaryData"
	}
	return !slices.Contains([]string{"apiVersion", "kind", "metadata", "status"}, k)
}

// integer is a JSON integer in decimal: no sign on zero, no leading zero, no
// fraction, no exponent.
var integer = regexp.MustCompile(`^(0|-?[1-9][0-9]*)$`)

// canonicalJSON writes v, as encoding/json decodes JSON with UseNumber, in
// the canonical form ContentSHA256 hashes.
func canonicalJSON(b *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case json.Number:
		if !integer.MatchString(string(x)) {
			return errors.New("a non-integer number has no canonical form")
		}
		b.WriteString(string(x))
	case string:
		return canonicalString(b, x)
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := canonicalJSON(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		slices.Sort(keys) // by bytes: UTF-8 order
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := canonicalString(b, k); err != nil {
				return err
			}
			b.WriteByte(':')
			if err := canonicalJSON(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("unexpected JSON value %T", v)
	}
	return nil
}

// canonicalString writes s as a JSON string with only the escapes JSON
// requires.
func canonicalString(b *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return errors.New("a string is not valid UTF-8")
	}
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return nil
}
