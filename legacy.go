package audit

import "go.opentelemetry.io/otel/attribute"

// WithLegacyKeys returns attrs with, for each attribute that replaced a v0.3
// key, that v0.3 key added beside it with the same value, unless attrs already
// carries it. This is migration window W1's dual-write: outcome,
// k8s.resource.*, k8s.object.* and enduser.id are written next to
// krateo.audit.outcome, krateo.audit.object_ref.* and user.name, so readers of
// the old keys keep working until they move.
//
// Emit calls it on every record during W1 (v0.4.x and v0.5.x). A writer that
// builds its own attributes calls it too. The release that closes W1 removes
// the v0.3 keys, and this function.
func WithLegacyKeys(attrs []attribute.KeyValue) []attribute.KeyValue {
	have := make(map[attribute.Key]bool, len(attrs))
	for _, kv := range attrs {
		have[kv.Key] = true
	}
	out := attrs[:len(attrs):len(attrs)] // append copies: the caller's array is never written
	for _, kv := range attrs {
		old := attribute.Key(legacyOf[string(kv.Key)])
		if old == "" || have[old] {
			continue
		}
		out = append(out, attribute.KeyValue{Key: old, Value: kv.Value})
		have[old] = true
	}
	return out
}
