package audit

import (
	"time"

	"go.opentelemetry.io/otel/attribute"
)

// The krateo.audit.client.source values.
const (
	// ClientSourcePortal: the portal (frontend) sent the provenance header.
	ClientSourcePortal = "portal"
)

// The krateo.audit.client.rejected values: why the writer rejected a
// client's provenance header (snowplow#1333).
const (
	ClientRejectedOversize = "oversize" // longer than the header's bound
	ClientRejectedEncoding = "encoding" // not base64url JSON
	ClientRejectedVersion  = "version"  // a version the writer does not read
	ClientRejectedSchema   = "schema"   // an unknown key, a wrong type, a value out of its rule
)

// ClientProvenance is what a client asserted about a write, after the writer
// validated it (Event.Client) -> krateo.audit.client.*. Every value is the
// client's assertion: none is identity, the actor's class, the agent's
// identity, the outcome or the target, which the writer establishes itself.
// The zero value asserts nothing; an unset field is omitted.
type ClientProvenance struct {
	// Rejected is why the writer rejected the client's header (one of the
	// ClientRejected* values) -> krateo.audit.client.rejected. When it is
	// set, Emit writes it alone: a rejected header asserts nothing, so no
	// other field reaches the record.
	Rejected string

	Source         string        // krateo.audit.client.source: ClientSourcePortal
	AgentSessionID string        // krateo.audit.client.agent_session_id: an agent-initiated write's session
	ConfirmationID string        // krateo.audit.client.confirmation_id: one press of the confirm gate, a lowercase UUID
	ConfirmedSet   *ConfirmedSet // krateo.audit.client.confirmed_set.*; nil: none
	// RequestedAt is when the client says the person confirmed, by its own
	// clock -> krateo.audit.client.requested_at, RFC 3339 in UTC with
	// milliseconds. Never the event time. Zero: omitted.
	RequestedAt time.Time
}

// ConfirmedSet is the blast radius a person confirmed with one press of the
// confirm gate, and this write's place in it
// (krateo.audit.client.confirmed_set.*). All four keys are written together.
type ConfirmedSet struct {
	Count        int64  // count: how many writes the set holds, at least 1
	Irreversible bool   // irreversible: any write of the set is irreversible
	SHA256       string // sha256: lowercase hex SHA-256 of the canonical set (snowplow#1333)
	Op           int64  // op: this write's index in the set, from 0, below Count
}

// requestedAtLayout is RFC 3339 with milliseconds, as the header carries it.
const requestedAtLayout = "2006-01-02T15:04:05.000Z07:00"

// attributes are the client keys of c: krateo.audit.client.rejected alone
// when the header was rejected, the asserted fields otherwise.
func (c ClientProvenance) attributes() []attribute.KeyValue {
	if c.Rejected != "" {
		return []attribute.KeyValue{attribute.String(KeyClientRejected, c.Rejected)}
	}
	var out []attribute.KeyValue
	add := func(k, v string) {
		if v != "" {
			out = append(out, attribute.String(k, v))
		}
	}
	add(KeyClientSource, c.Source)
	add(KeyClientAgentSessionID, c.AgentSessionID)
	add(KeyClientConfirmationID, c.ConfirmationID)
	if s := c.ConfirmedSet; s != nil {
		out = append(out,
			attribute.Int64(KeyClientConfirmedSetCount, s.Count),
			attribute.Bool(KeyClientConfirmedSetIrreversible, s.Irreversible),
			attribute.String(KeyClientConfirmedSetSHA256, s.SHA256),
			attribute.Int64(KeyClientConfirmedSetOp, s.Op))
	}
	if !c.RequestedAt.IsZero() {
		add(KeyClientRequestedAt, c.RequestedAt.UTC().Format(requestedAtLayout))
	}
	return out
}
