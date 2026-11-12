package audit

import (
	"errors"
	"slices"
	"strings"
	"time"
)

// ValidFormat reports whether value is of format, as Check enforces it: one
// of the formats schema/v1.yaml declares (the Format* constants). It is false
// for a format the schema does not declare. For a string-list key's format
// (delegation_link), value is one element.
//
// A writer that takes a key's value from an untrusted source (an inbound
// header, baggage) validates it with this, or with the format's Valid*
// function or ValidValue, before writing it, so it never writes what Check
// would refuse.
func ValidFormat(format, value string) bool {
	rule, ok := formatRule(format)
	return ok && rule(value)
}

// formatRule is format's rule: its schema pattern, or the rule below for a
// format no regular expression states. ok is false for a format the schema
// does not declare, and for a declared format with no rule (a test keeps that
// set empty).
func formatRule(format string) (rule func(string) bool, ok bool) {
	if !slices.Contains(schemaFormats, format) {
		return nil, false
	}
	if re, ok := formatPatterns[format]; ok {
		return re.MatchString, true
	}
	switch format {
	case FormatDelegationLink:
		return func(v string) bool {
			c, sub, ok := strings.Cut(v, ":")
			return ok && sub != "" && (c == "" || Class(c).Known())
		}, true
	case FormatMarkerList:
		return func(v string) bool {
			seen := map[string]bool{}
			for _, m := range strings.Split(v, ",") {
				if seen[m] || !slices.Contains(schemaMarkers, m) {
					return false
				}
				seen[m] = true
			}
			return true
		}, true
	case FormatContentHash:
		// Only the forms this library defines: a form it does not know has no
		// rule to check a stored hash with.
		return func(v string) bool {
			form, sum, ok := strings.Cut(v, ":")
			return ok && form == ContentFormC1 && ValidSHA256Hex(sum)
		}, true
	case FormatEndpointRefName:
		return validEndpointRefName, true
	case FormatRFC3339:
		return func(v string) bool {
			_, err := time.Parse(time.RFC3339, v)
			return err == nil
		}, true
	}
	return nil, false
}

// perUserSecretSuffixes end the names of the per-user credential Secrets
// (plumbing endpoints.SecretName and its step-up form): such a name embeds a
// username, so no endpoint_ref.name is one.
var perUserSecretSuffixes = []string{"-clientconfig", "-clientconfig-stepup"}

// validEndpointRefName is format endpoint_ref_name: 1 to 253 of [a-z0-9.-],
// starting and ending with a letter or digit, and never a per-user
// clientconfig Secret's name.
func validEndpointRefName(v string) bool {
	if len(v) == 0 || len(v) > 253 {
		return false
	}
	alnum := func(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') }
	for i := 0; i < len(v); i++ {
		if c := v[i]; !alnum(c) && c != '-' && c != '.' {
			return false
		}
	}
	if !alnum(v[0]) || !alnum(v[len(v)-1]) {
		return false
	}
	for _, sfx := range perUserSecretSuffixes {
		if strings.HasSuffix(v, sfx) {
			return false
		}
	}
	return true
}

// ErrUnknownKey is the error ValidValue returns for a key the schema does not
// declare.
var ErrUnknownKey = errors.New("audit: the key is not in the schema")

// FormatError is ValidValue's error for a value that is not of its key's
// format. It names the key and the format, never the value: audit values can
// carry identity.
type FormatError struct {
	Key, Format string
}

func (e *FormatError) Error() string {
	return "audit: the value of " + e.Key + " is not of format " + e.Format
}

// ValidValue applies key's declared format to value, as Check does: nil when
// the value is of the key's format or the key declares none, a *FormatError
// when it is not, and an error wrapping ErrUnknownKey for a key the schema
// does not declare. It checks the format only, not the key's type, enum or
// emptiness. For a string-list key (krateo.audit.delegation), value is one
// element.
func ValidValue(key, value string) error {
	i, ok := schemaIndex[key]
	if !ok {
		return &unknownKeyError{key: key}
	}
	spec := &schemaKeys[i]
	if spec.Format == "" || ValidFormat(spec.Format, value) {
		return nil
	}
	return &FormatError{Key: key, Format: spec.Format}
}

type unknownKeyError struct{ key string }

func (e *unknownKeyError) Error() string { return ErrUnknownKey.Error() + ": " + e.key }
func (e *unknownKeyError) Unwrap() error { return ErrUnknownKey }

// Formats returns every value format the schema declares, in schema order.
func Formats() []string { return slices.Clone(schemaFormats) }
