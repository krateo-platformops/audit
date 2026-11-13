package main

import (
	"maps"
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
	// v0.6.0: the content hash, and the client-asserted provenance (with its
	// rejection: the rich row breaks the "rejected alone" rule on purpose,
	// so every unexpected_ client column fires on it).
	audit.KeyObjectContentSHA256:            attribute.StringValue("c1:2bbf0a0f3ccc266c6ee429376afbd9a20714a80d5b03a753bbb29ec8c1fee232"),
	audit.KeyClientSource:                   attribute.StringValue("portal"),
	audit.KeyClientAgentSessionID:           attribute.StringValue("example-agent-session"),
	audit.KeyClientConfirmationID:           attribute.StringValue("00000000-0000-4000-8000-0000000000aa"),
	audit.KeyClientConfirmedSetCount:        attribute.Int64Value(3),
	audit.KeyClientConfirmedSetIrreversible: attribute.BoolValue(true),
	audit.KeyClientConfirmedSetSHA256:       attribute.StringValue("0a08bb91090b111f15a045b6061bccc4d0b8488d85f99ba57d8632e17061c277"),
	audit.KeyClientConfirmedSetOp:           attribute.Int64Value(1),
	audit.KeyClientRequestedAt:              attribute.StringValue("2026-11-11T10:00:00.000Z"),
	audit.KeyClientRejected:                 attribute.StringValue("schema"),
	// v0.9.0: the check result is per action; richRow takes the first value
	// of the first action that declares a set, and sets krateo.action to it.
	audit.KeyCheckResult: attribute.StringValue("per-action"),
	// v0.12.0: the non-resource path target and the endpointRef.
	audit.KeyURLPath:              attribute.StringValue("/debug/shadow-parity"),
	audit.KeyEndpointRefNamespace: attribute.StringValue("example-ns"),
	audit.KeyEndpointRefName:      attribute.StringValue("example-endpoint"),
	// v0.14.0: the authorization key a controller kept, beside
	// kept_existing_value (fixtureDenialReason).
	audit.KeyAuthorizationKey: attribute.StringValue("annotation:authn.krateo.io/username"),
	// v0.15.0: the verified identity's claim, and a /delegate token's
	// audience (unexpected on the rich row, whose outcome is denied for
	// another reason).
	audit.KeyIdentityClaim: attribute.StringValue(`["oidc","https://idp.example.com/realms/krateo","00000000-0000-4000-8000-000000000001"]`),
	audit.KeyTokenAudience: attribute.StringValue("agentiko"),
}

// firstActionValue is the first action, in sorted order, that declares a set
// for key on writer w, and that set's first value; ok is false when the key's
// values do not depend on the action.
func firstActionValue(key string, w audit.Writer) (action, value string, ok bool) {
	spec, _ := audit.LookupKey(key)
	sets := spec.Writers[w].ActionValues
	if len(sets) == 0 {
		return "", "", false
	}
	action = slices.Sorted(maps.Keys(sets))[0]
	return action, sets[action][0], true
}

// fixtureDenialReason is one value of each writer's own closed set. The
// controller's is kept_existing_value (v0.14.0), so the rich row holds its
// condition and may carry krateo.audit.authorization_key.
var fixtureDenialReason = map[audit.Writer]string{
	audit.WriterRequest:    audit.DenialReasonGroupNotAllowed,
	audit.WriterController: audit.DenialReasonKeptExistingValue,
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
	for _, k := range audit.Keys() { // a per-action key: a value of an action that declares it, on that action
		if a, v, ok := firstActionValue(k.Name, w); ok {
			cur[k.Name], cur[audit.KeyAction] = attribute.StringValue(v), attribute.StringValue(a)
		}
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

// closedSet is the values writer w may write for key: the key's enum, or w's
// own set. A bool enum's values are spelled "true" / "false".
func closedSet(key string, w audit.Writer) []string {
	spec, _ := audit.LookupKey(key)
	return append(slices.Clone(spec.Values), spec.Writers[w].Values...)
}

// withValue sets key to the closed-set value v, typed as the key is, and its
// v0.3 twin, if the row carries one, to the same value.
func withValue(attrs []attribute.KeyValue, key, v string) []attribute.KeyValue {
	spec, _ := audit.LookupKey(key)
	val := attribute.StringValue(v)
	if spec.Type == audit.TypeBool {
		val = attribute.BoolValue(v == "true")
	}
	out := setKey(attrs, attribute.KeyValue{Key: attribute.Key(key), Value: val})
	if old := audit.LegacyKey(key); old != "" && slices.ContainsFunc(attrs, func(kv attribute.KeyValue) bool { return string(kv.Key) == old }) {
		out = setKey(out, attribute.KeyValue{Key: attribute.Key(old), Value: val})
	}
	return out
}

// withoutKeys drops keys and the v0.3 twins of every dropped key.
func withoutKeys(attrs []attribute.KeyValue, keys map[string]bool) []attribute.KeyValue {
	return dropKeys(attrs, func(k string) bool {
		spec, _ := audit.LookupKey(k)
		return keys[k] || keys[spec.ReplacedBy]
	})
}

// falsified returns rich with condition c made false, derived from the
// schema and audit.Holds rather than written per condition: the keys c reads
// are those a one-key row makes it hold on. Each such key with a closed set
// takes the first value of its set that leaves c false (verb get, method
// CONNECT, outcome success); every other one is dropped (a delegation, a
// cause, an object). ok is false when no such row exists.
func falsified(w audit.Writer, rich []attribute.KeyValue, c audit.Condition) (row []attribute.KeyValue, ok bool) {
	row = slices.Clone(rich)
	for _, kv := range rich {
		k := string(kv.Key)
		if !audit.Holds(c, []attribute.KeyValue{kv}) {
			continue
		}
		replaced := false
		for _, v := range closedSet(k, w) {
			one := withValue([]attribute.KeyValue{kv}, k, v) // the key alone, with v
			if !audit.Holds(c, one) {
				row, replaced = withValue(row, k, v), true
				break
			}
		}
		if !replaced {
			row = withoutKeys(row, map[string]bool{k: true})
		}
	}
	return row, !audit.Holds(c, row)
}

// fixtureRows is the rich row and its variations, every one derived from the
// schema:
//   - each key removed, and a markable key removed and marked;
//   - each closed-set key once per value of its set (every verb, every
//     outcome, each of the writer's denial reasons, ...), and once outside it;
//   - each checked condition made false, once with the keys that depend on it
//     kept (an only_when key is then unexpected) and once correct: without
//     every key conditional on it and every key written only under it (a read
//     without dry_run);
//   - the rich row's object replaced by each credential target.
func fixtureRows(t *testing.T, w audit.Writer) []fixtureRow {
	rich := richRow(t, w)
	rows := []fixtureRow{{"rich", rich}}
	for _, c := range audit.CredentialTargets() {
		row := withoutKeys(rich, map[string]bool{audit.KeyObjectAPIGroup: true, audit.KeyObjectSubresource: true})
		row = withValue(row, audit.KeyObjectResource, c.Resource)
		if c.Group != "" {
			row = withValue(row, audit.KeyObjectAPIGroup, c.Group)
		}
		if c.Subresource != "" {
			row = withValue(row, audit.KeyObjectSubresource, c.Subresource)
		}
		rows = append(rows, fixtureRow{"object " + c.Group + "/" + c.Resource + "/" + c.Subresource, row})
	}
	for _, kv := range rich {
		k := string(kv.Key)
		spec, _ := audit.LookupKey(k)
		rows = append(rows, fixtureRow{"without " + k, dropKeys(rich, func(x string) bool { return x == k })})
		if spec.Marker != "" {
			rows = append(rows, fixtureRow{"without " + k + ", marked", setKey(dropKeys(rich, func(x string) bool { return x == k }),
				attribute.String(audit.KeyIncomplete, spec.Marker))})
		}
		set := closedSet(k, w)
		if spec.ReplacedBy == "" { // a v0.3 twin gets each value beside its replacement (withValue)
			for _, v := range set {
				rows = append(rows, fixtureRow{k + " = " + v, withValue(rich, k, v)})
			}
		}
		if sets := spec.Writers[w].ActionValues; len(sets) > 0 {
			for _, a := range slices.Sorted(maps.Keys(sets)) {
				on := setKey(rich, attribute.String(audit.KeyAction, a))
				for _, v := range sets[a] {
					rows = append(rows, fixtureRow{k + " = " + v + " on " + a, withValue(on, k, v)})
				}
				rows = append(rows, fixtureRow{k + " outside the set of " + a, withValue(on, k, "outside-the-closed-set")})
			}
			rows = append(rows,
				fixtureRow{k + " on an action that declares no set", setKey(rich, attribute.String(audit.KeyAction, "example.action"))},
				fixtureRow{k + " on a record with no action", dropKeys(rich, func(x string) bool { return x == audit.KeyAction })})
		}
		if len(set) > 0 {
			bad := attribute.StringValue("outside-the-closed-set")
			if kv.Value.Type() == attribute.BOOL {
				bad = attribute.BoolValue(!kv.Value.AsBool())
			}
			rows = append(rows, fixtureRow{k + " outside its set", setKey(rich, attribute.KeyValue{Key: kv.Key, Value: bad})})
		}
	}
	// A condition this writer's own values never meet can still hold on its
	// rows through another writer's value (v0.14.0: kept_existing_value, a
	// controller reason, on a request row). Its not_when keys are then
	// unexpected, so each such condition is made true once, from the first
	// closed-set value of any writer that makes it hold alone.
	for _, c := range audit.Conditions() {
		if audit.Holds(c, rich) {
			continue
		}
	made:
		for _, spec := range audit.Keys() { // a key the writer may not write at all included (the gateway's denial reason)
			k := spec.Name
			if spec.Type != audit.TypeString {
				continue
			}
			values := slices.Clone(spec.Values)
			for _, other := range audit.Writers() {
				values = append(values, spec.Writers[other].Values...)
			}
			for _, v := range values {
				if audit.Holds(c, []attribute.KeyValue{attribute.String(k, v)}) {
					rows = append(rows, fixtureRow{"made " + string(c) + " by " + k + " = " + v, withValue(rich, k, v)})
					break made
				}
			}
		}
	}
	for _, c := range audit.Conditions() {
		if !audit.Holds(c, rich) {
			continue // a condition this writer's rows never meet (caused, off the controller)
		}
		f, ok := falsified(w, rich, c)
		if !ok {
			t.Fatalf("%s: no row derived from the schema makes condition %s false", w, c)
		}
		rows = append(rows, fixtureRow{"not " + string(c) + ", dependent keys kept", f})
		dependent := map[string]bool{}
		for _, k := range audit.Keys() {
			if k.Writers[w].Check == c || k.OnlyWhen == c {
				dependent[k.Name] = true
			}
		}
		rows = append(rows, fixtureRow{"not " + string(c) + ", correct", withoutKeys(f, dependent)})
	}
	return rows
}

// columnRe finds a rules query's per-key columns.
var columnRe = regexp.MustCompile(`\) AS ((unmet|unexpected|bad|not_for_target|not_for_action)_[a-z0-9_]+)\b`)

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
	for prefix, reason := range map[string]audit.Reason{"unmet": audit.ReasonMissing, "unexpected": audit.ReasonUnexpected, "bad": audit.ReasonBadEnum, "not_for_target": audit.ReasonNotForTarget, "not_for_action": audit.ReasonNotForAction} {
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
