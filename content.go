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

// ContentFormC1 is the canonical form ContentSHA256 hashes, and the prefix of
// every value it returns ("c1:<hex>"). The form is fixed: any change to it is
// a new form, c2, so a stored hash is always checked with the form that made
// it. docs/schema.md defines c1.
const ContentFormC1 = "c1"

// contentFormC1Annotations is form c1's annotation key set, FROZEN at
// v0.12.0's two authorization annotations. It is deliberately not
// AuthorizationAnnotations: that list grows (v0.13.0 adds
// authn.krateo.io/username), and a form is fixed, so growing it must never
// change a c1 hash. Hashing another key set is a new form, c2.
var contentFormC1Annotations = []string{"authn.krateo.io/strategy", "authn.krateo.io/groups"}

// ContentFormC1Annotations returns form c1's annotation keys: frozen at
// authn.krateo.io/strategy and authn.krateo.io/groups, whatever
// AuthorizationAnnotations declares. A comparator that checks a c1 hash
// against the annotations compares these.
func ContentFormC1Annotations() []string { return slices.Clone(contentFormC1Annotations) }

// ErrCredentialTarget is ContentSHA256's refusal of a credential target (a
// Secret, a token request or review): a hash of low-entropy secret data can be
// guessed offline, so such a write carries no content hash.
var ErrCredentialTarget = errors.New("audit: no content hash for a credential target")

// ContentSHA256 returns "c1:" and the lowercase hex SHA-256 of obj's canonical
// content in form c1, for krateo.audit.object_ref.content_sha256
// (Event.ContentSHA256). group, resource and subresource are the target as
// the record's object_ref names it (group "" for the core group). obj is the
// request body as sent: a typed object, an unstructured map, or its JSON
// (json.RawMessage).
//
// Form c1 (docs/schema.md has the rules and a test vector):
//   - the content, per kind family: a ConfigMap's (core configmaps) data and
//     binaryData; any other object's top-level fields but apiVersion, kind,
//     metadata and status;
//   - plus, for every family, metadata.annotations kept to
//     ContentFormC1Annotations (frozen; not AuthorizationAnnotations), left
//     out when none is set;
//   - an object member whose value is null is left out, at every depth (a
//     null array element stays);
//   - UTF-8 JSON with no whitespace, object keys sorted by their bytes,
//     strings with only the escapes JSON requires (`\"`, `\\`, and the
//     control characters, as \b \f \n \r \t or \u00xx) and every other
//     character raw, integers in decimal.
//
// A non-integer number, or obj not being a JSON object, is an error: there is
// no canonical form for it. Bytes that are not valid UTF-8 become U+FFFD, as
// encoding/json makes them. A credential target (IsCredentialTarget, the
// targets Check refuses the key on) is refused with ErrCredentialTarget.
func ContentSHA256(group, resource, subresource string, obj any) (string, error) {
	if IsCredentialTarget(group, resource, subresource) {
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
		if contentField(group, resource, k) {
			content[k] = v
		}
	}
	if a := formC1Annotations(fields); len(a) > 0 {
		content["metadata"] = map[string]any{"annotations": a}
	}
	var b bytes.Buffer
	if err := canonicalJSON(&b, content); err != nil {
		return "", fmt.Errorf("audit: content hash: %w", err)
	}
	sum := sha256.Sum256(b.Bytes())
	return ContentFormC1 + ":" + hex.EncodeToString(sum[:]), nil
}

// contentField reports whether the top-level field k is part of the content
// of an object of (group, resource).
func contentField(group, resource, k string) bool {
	if group == "" && resource == "configmaps" {
		return k == "data" || k == "binaryData"
	}
	return !slices.Contains([]string{"apiVersion", "kind", "metadata", "status"}, k)
}

// formC1Annotations is the object's metadata.annotations kept to form c1's
// frozen key set, without the null ones.
func formC1Annotations(fields map[string]any) map[string]any {
	meta, _ := fields["metadata"].(map[string]any)
	all, _ := meta["annotations"].(map[string]any)
	out := map[string]any{}
	for _, k := range contentFormC1Annotations {
		if v, ok := all[k]; ok && v != nil {
			out[k] = v
		}
	}
	return out
}

// integer is a JSON integer in decimal: no sign on zero, no leading zero, no
// fraction, no exponent.
var integer = regexp.MustCompile(`^(0|-?[1-9][0-9]*)$`)

// canonicalJSON writes v, as encoding/json decodes JSON with UseNumber, in the
// bytes of form c1. An object member whose value is null is left out, at
// every depth; a null array element is written.
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
		for k, e := range x {
			if e != nil {
				keys = append(keys, k)
			}
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
