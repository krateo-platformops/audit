// Package audit emits the canonical Krateo AuditEvent as an OTLP LogRecord on
// the shared OTel Collector -> ClickHouse plane, and checks records against
// the one audit schema, schema/v1.yaml (krateo-platformops/installer#716). The
// collector routes event.name="audit" records to the krateo_audit table.
//
// It is the one emitter shared by every Krateo component that audits what it
// does, whichever runtime it is built on (provider-runtime or
// unstructured-runtime): it depends only on the OTel APIs.
//
// Correlation, two keys:
//   - trace_id: the Logs SDK stamps TraceId/SpanId from the span on ctx, joining
//     the audit row to the traces/logs the action caused.
//   - the written object's identity: ObjectUID + ObjectGeneration (and
//     ObjectResourceVersion where known). snowplow records the same three for the
//     write that created or changed an object, so a controller's audit row for
//     the reconcile that acted on that generation joins back to the user's
//     request — and to its session.id — on (uid, generation), without mutating
//     the object.
//
// session.id is read from W3C baggage when present (request-path components);
// a reconcile has no inbound baggage, which is why the object identity exists.
//
// Audit attributes carry identity on purpose. Nothing in this package logs
// them; a Violation names a key and a reason, never a value.
package audit

import (
	"context"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// EventName is the discriminator stamped on every audit record: the LogRecord
// EventName and the event.name attribute. The collector and every query filter
// on LogAttributes['event.name'] = 'audit'.
const EventName = "audit"

// BaggageSessionKey is the W3C baggage member carrying the business/session
// correlation id (minted by snowplow, never a bespoke header).
const BaggageSessionKey = "session.id"

// Outcome values (krateo.audit.outcome). Anything other than OutcomeSuccess is
// emitted at ERROR.
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
	OutcomeDenied  = "denied"
)

// Preview says whether the target is in the preview sandbox
// (krateo.audit.preview). The zero value is "not determined".
type Preview uint8

// The preview states.
const (
	// PreviewUnknown: not determined. For a Kubernetes target, namespaced or
	// cluster-scoped, the record is marked krateo.audit.incomplete=preview.
	PreviewUnknown Preview = iota
	// PreviewFalse: the target is not in a namespace labelled
	// krateo.io/purpose=preview-sandbox, or is cluster-scoped.
	PreviewFalse
	// PreviewTrue: the target's Namespace carries the label
	// krateo.io/purpose=preview-sandbox, as read from apiserver state.
	PreviewTrue
)

// PreviewOf returns PreviewTrue or PreviewFalse.
func PreviewOf(sandbox bool) Preview {
	if sandbox {
		return PreviewTrue
	}
	return PreviewFalse
}

// Link is one link of a signed delegation (RFC 8693 act) chain.
type Link struct {
	// Class is the link's principal class. "" when the token did not say; the
	// link is then written ":<subject>".
	Class   Class
	Subject string
}

// Event is the caller-facing input. Every field is optional; an unset field is
// omitted from the record, never written empty. The record a field becomes is
// in the comment after it; docs/api.md has the whole contract.
//
// Never put a credential in any field. In particular Message must not echo an
// upstream response body, and ServerAddress names an endpoint by host[:port]
// only: a path, query or userinfo can carry a secret. Emit enforces the latter by
// reducing ServerAddress to host[:port], so passing the request URL is safe, but
// that is defence in depth, not permission to put a secret in any other field.
// Never put identity in Message either: the affected user goes in AffectedUser.
type Event struct {
	Message string // LogRecord body

	// The actor: who performs the action. When UserName is empty and the
	// Emitter has a WithActor principal, that principal is the actor and
	// UserRoles and ActorClass are ignored, so one record never mixes two
	// principals. With neither, the record is still emitted, as these fields
	// give it, marked krateo.audit.incomplete=actor: a record is never
	// dropped.
	UserName   string   // user.name
	UserRoles  []string // user.roles
	ActorClass Class    // krateo.audit.actor_class; omitted (and marked) unless Known

	// Deprecated: enduser.id is deprecated in semconv and is removed in
	// v0.5.0. Emit writes it only when it is set here, as v0.3 did, and never
	// adds it; a value that differs from user.name is a Check violation.
	EndUserID string

	OnBehalfOf string // krateo.audit.on_behalf_of.user.name: a delegated token's sub
	Delegation []Link // krateo.audit.delegation: the act chain, outermost first, ending with the subject

	ImpersonatedUser  string   // krateo.audit.impersonated_user.name
	ImpersonatedRoles []string // krateo.audit.impersonated_user.roles

	// AffectedUser is the user the action was done TO, when that is not the
	// actor (a revoked grant's subject, a deactivated account) ->
	// krateo.audit.affected_user.name.
	AffectedUser string

	Action     string // krateo.action (the emit site's literal, e.g. "call", "rest.write")
	Verb       string // krateo.audit.verb (create, update, ..., or the lowercase method)
	HTTPMethod string // http.request.method; a method semconv does not name becomes _OTHER
	StatusCode int    // http.response.status_code (0 => omitted)
	Outcome    string // krateo.audit.outcome: OutcomeSuccess | OutcomeFailure | OutcomeDenied
	Preview    Preview
	// DryRun marks a write the authority was asked to validate and not
	// persist (Kubernetes dryRun=All) -> krateo.audit.dry_run=true. A request
	// or action writer (WithWriter) gets dry_run=false on every other write
	// record; a read never carries the key. The action literal is the
	// caller's either way (snowplow writes call.dryRun).
	DryRun bool

	// The Kubernetes object acted on. During W1 each is also written under its
	// v0.3 key (k8s.resource.*, k8s.object.*).
	Namespace   string // k8s.namespace.name
	Group       string // krateo.audit.object_ref.api_group (omit for the core group)
	Version     string // krateo.audit.object_ref.api_version
	Resource    string // krateo.audit.object_ref.resource: the plural, always set for a Kubernetes object
	Subresource string // krateo.audit.object_ref.subresource
	Kind        string // krateo.audit.object_ref.kind (optional; never instead of Resource)
	ObjectName  string // krateo.audit.object_ref.name

	// Identity of the object written or acted on — the Option-B join key.
	ObjectUID             string // krateo.audit.object_ref.uid
	ObjectGeneration      int64  // krateo.audit.object_ref.generation (0 => omitted)
	ObjectResourceVersion string // krateo.audit.object_ref.resource_version

	// server.address — host[:port] of an external endpoint. A URL is accepted:
	// Emit drops its scheme, userinfo, path, query and fragment. A value with no
	// parseable host is omitted, never written raw.
	ServerAddress string

	// What the writer received, for a writer that serves requests.
	RequestURI   string    // krateo.request.uri: path and query only
	SourceIPs    []string  // krateo.request.source_ips: forwarded entries, then the peer
	UserAgent    string    // user_agent.original, cut at 1024 bytes as the apiserver does
	ReceivedTime time.Time // krateo.request.received_time_unix_nano (zero => omitted)

	// The RESTAction stage that performed the action.
	RESTActionNamespace string // krateo.restaction.namespace
	RESTActionName      string // krateo.restaction.name
	RESTActionStage     string // krateo.restaction.stage
}

// Emitter wraps one OTel Logs API Logger. Build it once from the process
// LoggerProvider and inject it. A nil Emitter (or one with a nil logger) is a
// no-op, so a component with OTLP logs disabled never panics and needs no
// nil-guard at each call site.
type Emitter struct {
	logger log.Logger
	actor  *principal
	writer Writer

	incomplete metric.Int64Counter
	unattached metric.Int64Counter
}

type principal struct {
	name  string
	roles []string
	class Class
}

// Option configures an Emitter.
type Option func(*options)

type options struct {
	actor  *principal
	writer Writer
	meters metric.MeterProvider
}

// WithActor makes username, of class class, the actor of every record whose
// Event names none: a controller or tool executor reporting its own principal.
// For a controller, username is system:serviceaccount:<namespace>:<name> and
// class is ClassController.
func WithActor(username string, class Class) Option {
	return func(o *options) { o.actor = &principal{name: username, class: class} }
}

// WithWriter declares the writer class the Emitter records for, so Emit marks
// every gap that class must mark. Without it, Emit marks a gap only when every
// writer class that can write the key would have to.
func WithWriter(w Writer) Option { return func(o *options) { o.writer = w } }

// WithMeterProvider sets where the Emitter counts incomplete records. The
// default is the global MeterProvider (otel.GetMeterProvider).
func WithMeterProvider(mp metric.MeterProvider) Option {
	return func(o *options) { o.meters = mp }
}

// MetricIncomplete counts the records Emit emitted marked
// krateo.audit.incomplete, one point per marker: {marker="actor"} is a record
// emitted with no actor. The attribute names a marker, never a value of the
// record.
const MetricIncomplete = "krateo.audit.records.incomplete"

// MetricRecordedMarkerUnattached counts the records Emit emitted whose
// krateo.audit.recorded marker reached no trace: no WithRecordedMarker holder
// on ctx, and no recording span. {reason="no_span"}: no span at all;
// {reason="not_recording"}: the span on ctx had ended or does not record. The
// record itself was emitted. No identity in the attribute.
const MetricRecordedMarkerUnattached = "krateo.audit.recorded_marker.unattached"

const meterName = "github.com/krateo-platformops/audit"

// New returns an Emitter bound to logger, typically
// provider.Logger("<your module>/audit").
func New(logger log.Logger, opts ...Option) *Emitter {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	if o.meters == nil {
		o.meters = otel.GetMeterProvider()
	}
	m := o.meters.Meter(meterName)
	incomplete, _ := m.Int64Counter(MetricIncomplete, metric.WithUnit("{record}"),
		metric.WithDescription("Audit records emitted marked krateo.audit.incomplete, by marker. actor: the record named no actor."))
	unattached, _ := m.Int64Counter(MetricRecordedMarkerUnattached, metric.WithUnit("{record}"),
		metric.WithDescription("Audit records emitted whose krateo.audit.recorded marker reached no trace: no WithRecordedMarker holder, and no recording span on ctx. by reason: no_span, not_recording."))
	return &Emitter{logger: logger, actor: o.actor, writer: o.writer, incomplete: incomplete, unattached: unattached}
}

// Emit writes one canonical AuditEvent. ctx should carry the active span (so the
// SDK stamps TraceId/SpanId) and, on a request path, the W3C baggage (so
// session.id is captured).
//
// Emit is the one writer, and it never drops a record:
//   - a record missing a key its writer must write, the actor included (no
//     Event.UserName and no WithActor), is emitted without it and marked
//     krateo.audit.incomplete=<markers>, and each marker is counted under
//     MetricIncomplete;
//   - it rejects nothing: a key outside the schema is a Check finding in the
//     writer's tests, never a reason not to emit;
//   - it sets the LogRecord EventName and the event.name attribute, stamps
//     krateo.audit.schema_version, writes the v0.3 keys beside their
//     replacements (W1, v0.4.x), and makes every string valid UTF-8 (Sanitize);
//   - once the logger has taken the record (it reports itself enabled for
//     it), it marks the request recorded: on ctx's WithRecordedMarker holder
//     when one is installed, else SpanKeyRecorded=true on the span active on
//     ctx while that span records. With neither, the marker reaches no trace:
//     that is counted under MetricRecordedMarkerUnattached and logged once
//     per process at WARN, and the record stays emitted. A nil Emitter or
//     logger, or a disabled logger, marks and counts nothing.
func (e *Emitter) Emit(ctx context.Context, ev Event) {
	if e == nil || e.logger == nil {
		return
	}
	attrs := attributes(ctx, ev, e.actorOf(ev))
	if dry, ok := e.dryRun(ev, attrs); ok {
		attrs = append(attrs, attribute.Bool(KeyDryRun, dry))
	}
	attrs = WithLegacyKeys(attrs)
	if markers := missingMarkers(e.markingWriters(), attrs); len(markers) > 0 {
		attrs = append(attrs, attribute.String(KeyIncomplete, strings.Join(markers, ",")))
		for _, m := range markers {
			e.incomplete.Add(ctx, 1, metric.WithAttributes(attribute.String("marker", m)))
		}
	}
	for i, kv := range attrs {
		attrs[i] = Sanitize(kv)
	}

	var rec log.Record
	now := time.Now()
	rec.SetTimestamp(now)
	rec.SetObservedTimestamp(now)
	rec.SetEventName(EventName)
	rec.SetBody(SanitizeValue(attribute.StringValue(ev.Message)))
	if ev.Outcome == OutcomeSuccess || ev.Outcome == "" {
		rec.SetSeverity(log.SeverityInfo)
		rec.SetSeverityText("INFO")
	} else {
		rec.SetSeverity(log.SeverityError)
		rec.SetSeverityText("ERROR")
	}
	rec.AddAttributes(attrs...)

	// Emit always hands the record over (a record is never dropped here), and
	// marks the request recorded only when the logger says it processes the
	// record: a disabled logger drops it, and a dropped record must not keep a
	// trace on its behalf. A marker with no target is never silent: it is
	// counted, and logged once per process.
	handed := e.logger.Enabled(ctx, log.EnabledParameters{Severity: rec.Severity(), EventName: EventName})
	e.logger.Emit(ctx, rec)
	if !handed {
		return
	}
	if reason := markRecorded(ctx); reason != "" {
		e.unattached.Add(ctx, 1, metric.WithAttributes(attribute.String("reason", reason)))
		warnUnattached(reason)
	}
}

// dryRun is the krateo.audit.dry_run value Emit writes, if any: true whenever
// the Event says the write was a dry run; false only on a record the declared
// writer class must carry the key on (a request or action writer's write). A
// v0.3 caller declares no writer and sets no DryRun, so its records gain no
// key.
func (e *Emitter) dryRun(ev Event, attrs []attribute.KeyValue) (value, write bool) {
	if ev.DryRun {
		return true, true
	}
	if e.writer == "" {
		return false, false
	}
	present := make(map[string]attribute.Value, len(attrs))
	for _, kv := range attrs {
		present[string(kv.Key)] = kv.Value
	}
	return false, mustWrite(schemaKeys[schemaIndex[KeyDryRun]].Writers[e.writer], present)
}

// actorOf is the record's actor: the Event's when it names one, else the
// Emitter's WithActor principal, else the Event's fields as given (a record
// with no user.name, which Emit marks actor).
func (e *Emitter) actorOf(ev Event) principal {
	if ev.UserName == "" && e.actor != nil && e.actor.name != "" {
		return *e.actor
	}
	return principal{name: ev.UserName, roles: ev.UserRoles, class: ev.ActorClass}
}

// markingWriters is the writer classes whose gaps Emit marks: the declared
// one, or every class (missingMarkers then keeps the gaps all of them share).
func (e *Emitter) markingWriters() []Writer {
	if e.writer != "" {
		return []Writer{e.writer}
	}
	return schemaWriters
}

// attributes builds the record's schema-v1 attributes from ev (no v0.3 keys,
// no markers, not yet sanitised).
func attributes(ctx context.Context, ev Event, actor principal) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, 40)
	add := func(k, v string) {
		if v != "" {
			attrs = append(attrs, attribute.String(k, v))
		}
	}
	strs := func(k string, v []string) {
		if len(v) > 0 {
			attrs = append(attrs, attribute.StringSlice(k, slices.Clone(v)))
		}
	}
	num := func(k string, v int64) {
		if v != 0 {
			attrs = append(attrs, attribute.Int64(k, v))
		}
	}

	add(KeyEventName, EventName)
	add(KeySchemaVersion, SchemaVersion)

	add(KeyUserName, actor.name)
	strs(KeyUserRoles, actor.roles)
	if actor.class.Known() {
		add(KeyActorClass, string(actor.class))
	}
	add(KeyLegacyEndUserID, ev.EndUserID)
	add(KeyOnBehalfOf, ev.OnBehalfOf)
	strs(KeyDelegation, delegation(ev.Delegation))
	add(KeyImpersonatedUser, ev.ImpersonatedUser)
	strs(KeyImpersonatedRoles, ev.ImpersonatedRoles)
	add(KeyAffectedUser, ev.AffectedUser)

	add(KeyAction, ev.Action)
	add(KeyVerb, ev.Verb)
	method, original := httpMethod(ev.HTTPMethod)
	add(KeyHTTPMethod, method)
	add(KeyHTTPMethodOriginal, original)
	num(KeyHTTPStatusCode, int64(ev.StatusCode))
	add(KeyOutcome, ev.Outcome)
	if ev.Preview != PreviewUnknown {
		attrs = append(attrs, attribute.Bool(KeyPreview, ev.Preview == PreviewTrue))
	}

	add(KeyNamespace, ev.Namespace)
	add(KeyObjectAPIGroup, ev.Group)
	add(KeyObjectAPIVersion, ev.Version)
	add(KeyObjectResource, ev.Resource)
	add(KeyObjectSubresource, ev.Subresource)
	add(KeyObjectKind, ev.Kind)
	add(KeyObjectName, ev.ObjectName)
	add(KeyObjectUID, ev.ObjectUID)
	num(KeyObjectGeneration, ev.ObjectGeneration)
	add(KeyObjectResourceVersion, ev.ObjectResourceVersion)
	add(KeyServerAddress, hostPort(ev.ServerAddress))

	add(KeyRequestURI, ev.RequestURI)
	strs(KeySourceIPs, ev.SourceIPs)
	add(KeyUserAgent, truncateUserAgent(ev.UserAgent))
	if !ev.ReceivedTime.IsZero() {
		num(KeyRequestReceivedTime, ev.ReceivedTime.UnixNano())
	}
	if m := baggage.FromContext(ctx).Member(BaggageSessionKey); m.Key() != "" {
		add(KeySessionID, m.Value())
	}
	add(KeyRESTActionNamespace, ev.RESTActionNamespace)
	add(KeyRESTActionName, ev.RESTActionName)
	add(KeyRESTActionStage, ev.RESTActionStage)

	// TraceId/SpanId are LogRecord fields the SDK stamps from ctx, not
	// attributes. Flag a record emitted with no trace context so it is findable.
	if sc := trace.SpanContextFromContext(ctx); !sc.IsValid() {
		attrs = append(attrs, attribute.Bool(KeyNoTraceContext, true))
	}
	return attrs
}

// delegation renders a chain as krateo.audit.delegation entries,
// <class>:<subject>. An unknown class is written as "".
func delegation(chain []Link) []string {
	if len(chain) == 0 {
		return nil
	}
	out := make([]string, len(chain))
	for i, l := range chain {
		c := l.Class
		if !c.Known() {
			c = ""
		}
		out[i] = string(c) + ":" + l.Subject
	}
	return out
}

// httpMethod is method as semconv records it: a method it names stays, and
// any other (lowercase included) becomes _OTHER, with the method as given
// returned as original for http.request.method_original. original is ""
// when nothing was rewritten.
func httpMethod(method string) (recorded, original string) {
	if method == "" {
		return "", ""
	}
	if k := schemaKeys[schemaIndex[KeyHTTPMethod]]; slices.Contains(k.Values, method) {
		return method, ""
	}
	return "_OTHER", method
}

// The apiserver's User-Agent bound and marker (k8s.io/apiserver
// pkg/audit/request.go maxUserAgentLength, userAgentTruncateSuffix).
const (
	maxUserAgentLength      = 1024
	userAgentTruncateSuffix = "...TRUNCATED"
)

// truncateUserAgent is the apiserver's maybeTruncateUserAgent, on characters:
// a User-Agent longer than maxUserAgentLength bytes keeps at most that many
// bytes and gets userAgentTruncateSuffix. The cut steps back to the start of
// the character it would split, and invalid bytes are replaced first, so the
// result is valid UTF-8 within the bound.
func truncateUserAgent(ua string) string {
	ua = validUTF8(ua)
	if len(ua) <= maxUserAgentLength {
		return ua
	}
	cut := maxUserAgentLength
	for cut > 0 && !utf8.RuneStart(ua[cut]) {
		cut--
	}
	return ua[:cut] + userAgentTruncateSuffix
}

// hostPort reduces addr to the host[:port] it names, as url.URL.Host spells it
// (an IPv6 literal keeps its brackets). It drops any scheme, userinfo, path,
// query and fragment. It returns "" when addr has no parseable host, so Emit
// omits server.address rather than write the raw value: the raw value is exactly
// what may carry a secret.
func hostPort(addr string) string {
	if addr == "" {
		return ""
	}
	// A value with no scheme ("host:port", "host/path") is read as an authority.
	// "://" counts as a scheme separator only before any path, query or fragment,
	// so a URL embedded in a query ("host/cb?next=https://...") does not.
	if i := strings.Index(addr, "://"); i < 0 || strings.ContainsAny(addr[:i], "/?#") {
		addr = "//" + addr
	}
	u, err := url.Parse(addr)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return strings.TrimSuffix(u.Host, ":") // "host:" has an empty port
}
