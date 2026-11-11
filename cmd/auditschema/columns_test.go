package main

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/krateo-platformops/audit"
	"go.opentelemetry.io/otel/attribute"
)

// fixtureValue is a valid value for every current schema key, written by
// hand. A key the schema gains without a value here fails the column test,
// so no new rule is left out of it. The denial reason is per writer
// (fixtureDenialReason); krateo.audit.incomplete is set per row.
var fixtureValue = map[string]attribute.Value{
	audit.KeyEventName:             attribute.StringValue("audit"),
	audit.KeySchemaVersion:         attribute.StringValue("1"),
	audit.KeyUserName:              attribute.StringValue("example-user"),
	audit.KeyUserRoles:             attribute.StringSliceValue([]string{"example-group"}),
	audit.KeyActorClass:            attribute.StringValue("human"),
	audit.KeyOnBehalfOf:            attribute.StringValue("example-subject"),
	audit.KeyDelegation:            attribute.StringSliceValue([]string{"agent:example-user", "human:example-subject"}),
	audit.KeyImpersonatedUser:      attribute.StringValue("example-impersonated"),
	audit.KeyImpersonatedRoles:     attribute.StringSliceValue([]string{"example-group"}),
	audit.KeyAffectedUser:          attribute.StringValue("example-affected"),
	audit.KeyAction:                attribute.StringValue("example.action"),
	audit.KeyVerb:                  attribute.StringValue("create"), // a write
	audit.KeyHTTPMethod:            attribute.StringValue("_OTHER"), // method_other holds
	audit.KeyHTTPMethodOriginal:    attribute.StringValue("purge"),
	audit.KeyDryRun:                attribute.BoolValue(false),
	audit.KeyOutcome:               attribute.StringValue("denied"), // denied holds
	audit.KeyHTTPStatusCode:        attribute.Int64Value(403),
	audit.KeyPreview:               attribute.BoolValue(false),
	audit.KeyObjectAPIGroup:        attribute.StringValue("apps"),
	audit.KeyObjectAPIVersion:      attribute.StringValue("v1"),
	audit.KeyObjectResource:        attribute.StringValue("deployments"),
	audit.KeyObjectSubresource:     attribute.StringValue("status"),
	audit.KeyObjectName:            attribute.StringValue("example-worker"),
	audit.KeyNamespace:             attribute.StringValue("example-ns"),
	audit.KeyObjectKind:            attribute.StringValue("Deployment"),
	audit.KeyObjectUID:             attribute.StringValue("uid-o"),
	audit.KeyObjectResourceVersion: attribute.StringValue("42"),
	audit.KeyObjectGeneration:      attribute.Int64Value(2),
	audit.KeyCauseAPIGroup:         attribute.StringValue("composition.krateo.io"),
	audit.KeyCauseAPIVersion:       attribute.StringValue("v1-2-0"),
	audit.KeyCauseResource:         attribute.StringValue("exampleapps"),
	audit.KeyCauseNamespace:        attribute.StringValue("example-ns"),
	audit.KeyCauseName:             attribute.StringValue("example-composition"),
	audit.KeyCauseUID:              attribute.StringValue("uid-c"),
	audit.KeyCauseGeneration:       attribute.Int64Value(4),
	audit.KeyServerAddress:         attribute.StringValue("api.example.com"),
	audit.KeyRequestURI:            attribute.StringValue("/call"),
	audit.KeySourceIPs:             attribute.StringSliceValue([]string{"192.0.2.10"}),
	audit.KeyUserAgent:             attribute.StringValue("example-portal/1.0"),
	audit.KeyRequestReceivedTime:   attribute.Int64Value(1),
	audit.KeySessionID:             attribute.StringValue("example-session"),
	audit.KeyRESTActionNamespace:   attribute.StringValue("example-ns"),
	audit.KeyRESTActionName:        attribute.StringValue("example-restaction"),
	audit.KeyRESTActionStage:       attribute.StringValue("example-stage"),
	audit.KeyNoTraceContext:        attribute.BoolValue(true),
	audit.KeyGatewayRoute:          attribute.StringValue("example/route"),
	audit.KeyGatewayMCPTool:        attribute.StringValue("example_tool"),
	audit.KeyAssertedAgentHost:     attribute.StringValue("example-agent-host"),
}

// fixtureDenialReason is one value of each writer's own closed set.
var fixtureDenialReason = map[audit.Writer]string{
	audit.WriterRequest:    audit.DenialReasonGroupNotAllowed,
	audit.WriterController: audit.DenialReasonKeptResourcePolicy,
}

type fixtureRow struct {
	name  string
	attrs []attribute.KeyValue
}

// richRow is a row of writer w carrying every key w may write (bar the
// marker list), with every checked condition holding: a write, an _OTHER
// method, a delegation, an impersonation, a Kubernetes target, a cause (for
// a controller) and a denied outcome. v0.3 keys carry their replacement's
// value.
func richRow(t *testing.T, w audit.Writer) []attribute.KeyValue {
	t.Helper()
	cur := map[string]attribute.Value{}
	for _, k := range audit.Keys() {
		if k.ReplacedBy != "" || k.Name == audit.KeyIncomplete || k.Writers[w].Level <= audit.LevelNotEstablished {
			continue
		}
		v, ok := fixtureValue[k.Name]
		if k.Name == audit.KeyDenialReason {
			var r string
			r, ok = fixtureDenialReason[w]
			v = attribute.StringValue(r)
		}
		if !ok {
			t.Fatalf("no fixture value for %s (writer %s): add one to fixtureValue", k.Name, w)
		}
		cur[k.Name] = v
	}
	var out []attribute.KeyValue
	for _, k := range audit.Keys() { // schema order, v0.3 keys after their replacements' values are known
		if v, ok := cur[k.Name]; ok {
			out = append(out, attribute.KeyValue{Key: attribute.Key(k.Name), Value: v})
		} else if v, ok := cur[k.ReplacedBy]; ok && k.ReplacedBy != "" && k.Writers[w].Level > audit.LevelNotEstablished {
			out = append(out, attribute.KeyValue{Key: attribute.Key(k.Name), Value: v})
		}
	}
	return out
}

func dropKeys(attrs []attribute.KeyValue, drop func(string) bool) []attribute.KeyValue {
	return slices.DeleteFunc(slices.Clone(attrs), func(kv attribute.KeyValue) bool { return drop(string(kv.Key)) })
}

func setKey(attrs []attribute.KeyValue, kvs ...attribute.KeyValue) []attribute.KeyValue {
	out := slices.Clone(attrs)
	for _, kv := range kvs {
		out = dropKeys(out, func(k string) bool { return k == string(kv.Key) })
		out = append(out, kv)
	}
	return out
}

// fixtureRows is the rich row and its variations: each key removed (and,
// for a markable key, removed and marked), each closed-set value replaced by
// one outside the set, and each checked condition turned false.
func fixtureRows(t *testing.T, w audit.Writer) []fixtureRow {
	rich := richRow(t, w)
	rows := []fixtureRow{{"rich", rich}}
	for _, kv := range rich {
		k := string(kv.Key)
		spec, _ := audit.LookupKey(k)
		rows = append(rows, fixtureRow{"without " + k, dropKeys(rich, func(x string) bool { return x == k })})
		if spec.Marker != "" {
			rows = append(rows, fixtureRow{"without " + k + ", marked", setKey(dropKeys(rich, func(x string) bool { return x == k }),
				attribute.String(audit.KeyIncomplete, spec.Marker))})
		}
		if len(spec.Values)+len(spec.Writers[w].Values) > 0 {
			bad := attribute.StringValue("outside-the-closed-set")
			if kv.Value.Type() == attribute.BOOL {
				bad = attribute.BoolValue(!kv.Value.AsBool())
			}
			rows = append(rows, fixtureRow{k + " outside its set", setKey(rich, attribute.KeyValue{Key: kv.Key, Value: bad})})
		}
	}
	has := func(prefix string) func(string) bool {
		return func(k string) bool { return strings.HasPrefix(k, prefix) }
	}
	rows = append(rows,
		fixtureRow{"not denied: success", setKey(rich, attribute.String(audit.KeyOutcome, "success"), attribute.String(audit.KeyLegacyOutcome, "success"))},
		fixtureRow{"not denied: failure", setKey(rich, attribute.String(audit.KeyOutcome, "failure"), attribute.String(audit.KeyLegacyOutcome, "failure"))},
		fixtureRow{"a read", setKey(rich, attribute.String(audit.KeyVerb, "get"))},
		fixtureRow{"a method semconv names", setKey(rich, attribute.String(audit.KeyHTTPMethod, "POST"))},
		fixtureRow{"no delegation", dropKeys(rich, func(k string) bool { return k == audit.KeyDelegation || k == audit.KeyOnBehalfOf })},
		fixtureRow{"no impersonation", dropKeys(rich, has("krateo.audit.impersonated_user."))},
		fixtureRow{"no Kubernetes target", dropKeys(rich, func(k string) bool {
			spec, _ := audit.LookupKey(k)
			return k == audit.KeyNamespace || strings.HasPrefix(k, "krateo.audit.object_ref.") || strings.HasPrefix(spec.ReplacedBy, "krateo.audit.object_ref.")
		})},
	)
	return rows
}

// columnRe finds a rules query's per-key columns.
var columnRe = regexp.MustCompile(`\) AS ((unmet|unexpected|bad)_[a-z0-9_]+)\b`)

// rulesQuery returns writer w's rules query.
func rulesQuery(t *testing.T, sql string, w audit.Writer) string {
	t.Helper()
	head := "-- Conditional keys, enums, closed set, target rule and W1 pairs, writer " + string(w) + "."
	i := strings.Index(sql, head)
	if i < 0 {
		t.Fatalf("no rules query for %s", w)
	}
	q := sql[i:]
	return q[:strings.Index(q, ";")]
}

// columnKey maps a column alias to its key and the violation Check reports
// for the same fact.
func columnKey(t *testing.T, col string) (string, audit.Reason) {
	t.Helper()
	for prefix, reason := range map[string]audit.Reason{"unmet": audit.ReasonMissing, "unexpected": audit.ReasonUnexpected, "bad": audit.ReasonBadEnum} {
		for _, k := range audit.Keys() {
			if alias(prefix, k.Name) == col {
				return k.Name, reason
			}
		}
	}
	t.Fatalf("column %s names no key", col)
	return "", ""
}

// Every per-key column of every writer's live rules query, executed on the
// fixture rows, counts a row exactly when Check reports the same fact on it:
// unmet_ = missing (a marked gap is not counted), unexpected_ = unexpected,
// bad_ = bad-enum. Each column is counted on some row and not on another,
// so no column passes by never firing.
func TestSQL_EveryColumnCountsWhatCheckReports(t *testing.T) {
	_, sql, _ := runIt(t, "", "sql")
	columns := 0
	for _, w := range audit.Writers() {
		if len(scopesOf(w, false)) == 0 {
			continue
		}
		q := rulesQuery(t, sql, w)
		rows := fixtureRows(t, w)
		for _, m := range columnRe.FindAllStringSubmatch(q, -1) {
			col := m[1]
			key, reason := columnKey(t, col)
			pred := countIfOf(t, q, col)
			columns++
			counted, notCounted := 0, 0
			for _, r := range rows {
				got, err := evalSQL(pred, rowOf(r.attrs))
				if err != nil {
					t.Fatalf("%s %s: %v\n%s", w, col, err, pred)
				}
				want := slices.Contains(audit.Check(w, r.attrs), audit.Violation{Key: key, Reason: reason})
				if got != want {
					t.Errorf("%s %s on row %q: SQL counts %v, Check reports %s %v", w, col, r.name, got, reason, want)
				}
				if got {
					counted++
				} else {
					notCounted++
				}
			}
			if counted == 0 || notCounted == 0 {
				t.Errorf("%s %s: counted on %d rows, not counted on %d; the arm needs both", w, col, counted, notCounted)
			}
		}
	}
	if columns < 20 {
		t.Errorf("only %d per-key columns found: the column pattern no longer matches the queries", columns)
	}
}

// The cause_ref detector, by hand: what the controller's live query counts
// for no cause, a full cause, a cause with only its name, and a full cause
// without its uid.
func TestSQL_CauseRefColumnsByHand(t *testing.T) {
	_, sql, _ := runIt(t, "", "sql")
	q := rulesQuery(t, sql, audit.WriterController)
	rich := richRow(t, audit.WriterController)
	isCause := func(k string) bool { return strings.HasPrefix(k, "krateo.audit.cause_ref.") }
	noCause := dropKeys(rich, isCause)
	required := []string{audit.KeyCauseAPIVersion, audit.KeyCauseResource, audit.KeyCauseName, audit.KeyCauseUID}
	for _, tc := range []struct {
		name  string
		attrs []attribute.KeyValue
		unmet []string // the unmet_ cause_ref columns that count the row
	}{
		{"no cause", noCause, nil},
		{"a full cause", rich, nil},
		{"a cause with only its name", setKey(noCause, attribute.String(audit.KeyCauseName, "example-composition")),
			[]string{audit.KeyCauseAPIVersion, audit.KeyCauseResource, audit.KeyCauseUID}},
		{"a full cause without its uid", dropKeys(rich, func(k string) bool { return k == audit.KeyCauseUID }), []string{audit.KeyCauseUID}},
	} {
		for _, k := range required {
			got, err := evalSQL(countIfOf(t, q, alias("unmet", k)), rowOf(tc.attrs))
			if err != nil {
				t.Fatal(err)
			}
			if want := slices.Contains(tc.unmet, k); got != want {
				t.Errorf("%s: unmet_%s counts %v, want %v", tc.name, k, got, want)
			}
		}
	}
}
