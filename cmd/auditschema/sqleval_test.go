package main

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/krateo-platformops/audit"
	"go.opentelemetry.io/otel/attribute"
)

// A tiny evaluator for the SQL the live queries put in a condition or a
// countIf: comparisons of LogAttributes['k'] with literals (=, !=, IN),
// arrayExists(k -> startsWith(k, '<prefix>'), mapKeys(LogAttributes)), AND,
// OR, NOT and parentheses, on one row (LogAttributes as a string map, a
// missing key reading ''). It is written apart from sql.go, so a test can
// execute the generated predicates on fixture rows and compare them with
// what audit.Holds and audit.Check decide, instead of matching their text.

type sqlEval struct {
	toks []string
	pos  int
}

func tokenizeSQL(s string) ([]string, error) {
	var out []string
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\n' || c == '\t':
			i++
		case strings.HasPrefix(s[i:], "!=") || strings.HasPrefix(s[i:], "->"):
			out = append(out, s[i:i+2])
			i += 2
		case strings.ContainsRune("()[],=", rune(c)):
			out = append(out, string(c))
			i++
		case c == '\'':
			var b strings.Builder
			j := i + 1
			for ; j < len(s) && s[j] != '\''; j++ {
				if s[j] == '\\' && j+1 < len(s) {
					j++
				}
				b.WriteByte(s[j])
			}
			if j >= len(s) {
				return nil, fmt.Errorf("unterminated literal at %d", i)
			}
			out = append(out, "'"+b.String()) // a leading quote marks a literal
			i = j + 1
		default:
			j := i
			for j < len(s) && (s[j] == '_' || s[j] == '.' || s[j] >= 'a' && s[j] <= 'z' || s[j] >= 'A' && s[j] <= 'Z' || s[j] >= '0' && s[j] <= '9') {
				j++
			}
			if j == i {
				return nil, fmt.Errorf("unexpected %q at %d", c, i)
			}
			out = append(out, s[i:j])
			i = j
		}
	}
	return out, nil
}

// evalSQL evaluates the boolean predicate pred on row.
func evalSQL(pred string, row map[string]string) (bool, error) {
	toks, err := tokenizeSQL(pred)
	if err != nil {
		return false, err
	}
	e := &sqlEval{toks: toks}
	v, err := e.or(row)
	if err == nil && e.pos != len(toks) {
		err = fmt.Errorf("trailing %v", toks[e.pos:])
	}
	return v, err
}

func (e *sqlEval) peek() string {
	if e.pos < len(e.toks) {
		return e.toks[e.pos]
	}
	return ""
}

func (e *sqlEval) eat(want string) error {
	if e.peek() != want {
		return fmt.Errorf("want %q, got %q at token %d", want, e.peek(), e.pos)
	}
	e.pos++
	return nil
}

func (e *sqlEval) or(row map[string]string) (bool, error) {
	v, err := e.and(row)
	for err == nil && e.peek() == "OR" {
		e.pos++
		var r bool
		r, err = e.and(row)
		v = v || r
	}
	return v, err
}

func (e *sqlEval) and(row map[string]string) (bool, error) {
	v, err := e.unary(row)
	for err == nil && e.peek() == "AND" {
		e.pos++
		var r bool
		r, err = e.unary(row)
		v = v && r
	}
	return v, err
}

func (e *sqlEval) unary(row map[string]string) (bool, error) {
	switch e.peek() {
	case "NOT":
		e.pos++
		v, err := e.unary(row)
		return !v, err
	case "(":
		e.pos++
		v, err := e.or(row)
		if err == nil {
			err = e.eat(")")
		}
		return v, err
	case "arrayExists":
		// arrayExists(k -> startsWith(k, '<prefix>'), mapKeys(LogAttributes))
		for _, t := range []string{"arrayExists", "(", "k", "->", "startsWith", "(", "k", ","} {
			if err := e.eat(t); err != nil {
				return false, err
			}
		}
		prefix := e.peek()
		if !strings.HasPrefix(prefix, "'") {
			return false, fmt.Errorf("want a prefix literal, got %q", prefix)
		}
		e.pos++
		for _, t := range []string{")", ",", "mapKeys", "(", "LogAttributes", ")", ")"} {
			if err := e.eat(t); err != nil {
				return false, err
			}
		}
		for k := range row {
			if strings.HasPrefix(k, prefix[1:]) {
				return true, nil
			}
		}
		return false, nil
	}
	left, err := e.term(row)
	if err != nil {
		return false, err
	}
	switch op := e.peek(); op {
	case "=", "!=":
		e.pos++
		right, err := e.term(row)
		return (left == right) == (op == "="), err
	case "IN":
		e.pos++
		if err := e.eat("("); err != nil {
			return false, err
		}
		var set []string
		for {
			v, err := e.term(row)
			if err != nil {
				return false, err
			}
			set = append(set, v)
			if e.peek() != "," {
				break
			}
			e.pos++
		}
		return slices.Contains(set, left), e.eat(")")
	}
	return false, fmt.Errorf("want a comparison, got %q at token %d", e.peek(), e.pos)
}

// term is a string: a literal, or LogAttributes['k'] (” when absent).
func (e *sqlEval) term(row map[string]string) (string, error) {
	t := e.peek()
	if strings.HasPrefix(t, "'") {
		e.pos++
		return t[1:], nil
	}
	for _, w := range []string{"LogAttributes", "["} {
		if err := e.eat(w); err != nil {
			return "", err
		}
	}
	k := e.peek()
	if !strings.HasPrefix(k, "'") {
		return "", fmt.Errorf("want a key literal, got %q", k)
	}
	e.pos++
	return row[k[1:]], e.eat("]")
}

// countIfOf returns the predicate of the countIf column named alias in query.
func countIfOf(t *testing.T, query, alias string) string {
	t.Helper()
	end := strings.Index(query, ") AS "+alias+",")
	if end < 0 {
		end = strings.Index(query, ") AS "+alias+"\n")
	}
	if end < 0 {
		t.Fatalf("no column %s", alias)
	}
	start := strings.LastIndex(query[:end], "countIf(")
	if start < 0 {
		t.Fatalf("column %s is not a countIf", alias)
	}
	return query[start+len("countIf(") : end]
}

// rowOf is a record's attributes as krateo_audit stores them: a string map.
func rowOf(attrs []attribute.KeyValue) map[string]string {
	row := map[string]string{}
	for _, kv := range attrs {
		row[string(kv.Key)] = kv.Value.Emit()
	}
	return row
}

// The evaluator itself reads the operators it claims to (positive and
// negative controls), so a green arm below is not an evaluator that says yes.
func TestSQLEval_Controls(t *testing.T) {
	row := map[string]string{"a": "x", "p.q": "1"}
	for pred, want := range map[string]bool{
		"LogAttributes['a'] = 'x'":                                      true,
		"LogAttributes['a'] = 'y'":                                      false,
		"LogAttributes['a'] != 'x'":                                     false,
		"LogAttributes['b'] = ''":                                       true,
		"LogAttributes['a'] IN ('y', 'x')":                              true,
		"LogAttributes['a'] IN ('y', 'z')":                              false,
		"NOT (LogAttributes['a'] = 'x')":                                false,
		"LogAttributes['a'] = 'x' AND LogAttributes['b'] != ''":         false,
		"LogAttributes['a'] = 'y' OR LogAttributes['b'] = ''":           true,
		"arrayExists(k -> startsWith(k, 'p.'), mapKeys(LogAttributes))": true,
		"arrayExists(k -> startsWith(k, 'z.'), mapKeys(LogAttributes))": false,
		`LogAttributes['a'] = 'it\'s'`:                                  false,
	} {
		got, err := evalSQL(pred, row)
		if err != nil || got != want {
			t.Errorf("%s = %v, %v; want %v", pred, got, err, want)
		}
	}
	if _, err := evalSQL("has(splitByChar(',', 'x'), 'y')", row); err == nil {
		t.Errorf("the evaluator accepted SQL it does not implement")
	}
}

// Every condition's SQL means what audit.Holds means: executed on fixture
// rows that make each condition true and false, it decides as Holds does.
func TestConditionSQL_MeansWhatHoldsMeans(t *testing.T) {
	s := attribute.String
	rows := [][]attribute.KeyValue{
		{s(audit.KeyOutcome, audit.OutcomeDenied)},
		{s(audit.KeyOutcome, audit.OutcomeSuccess)},
		{s(audit.KeyOutcome, audit.OutcomeFailure)},
		{s(audit.KeyLegacyOutcome, audit.OutcomeDenied)}, // the v0.3 key alone is not krateo.audit.outcome
		{s(audit.KeyVerb, "delete")},
		{s(audit.KeyVerb, "get")},
		{s(audit.KeyVerb, "post")},
		{s(audit.KeyHTTPMethod, "_OTHER")},
		{s(audit.KeyHTTPMethod, "POST")},
		{s(audit.KeyNamespace, "example-ns")},
		{s(audit.KeyObjectResource, "pods")},
		{s(audit.KeyServerAddress, "api.example.com")},
		{s(audit.KeyCauseUID, "uid-c")},
		{s(audit.KeyCauseName, "example-composition"), s(audit.KeyOutcome, audit.OutcomeDenied)},
		{s(audit.KeyOnBehalfOf, "example-user")},
		{attribute.StringSlice(audit.KeyDelegation, []string{"agent:example-agent"})},
		{s(audit.KeyImpersonatedUser, "example-user")},
		{attribute.StringSlice(audit.KeyImpersonatedRoles, []string{"example-group"})},
		{},
	}
	// Every verb the schema names, and every method: the write and
	// method_other conditions decide on each value.
	for _, k := range []string{audit.KeyVerb, audit.KeyHTTPMethod, audit.KeyOutcome} {
		spec, _ := audit.LookupKey(k)
		for _, v := range spec.Values {
			rows = append(rows, []attribute.KeyValue{s(k, v)})
		}
	}
	for _, c := range audit.Conditions() {
		pred := conditionSQL[c]
		trues, falses := 0, 0
		for _, attrs := range rows {
			got, err := evalSQL(pred, rowOf(attrs))
			if err != nil {
				t.Fatalf("condition %s: %v\n%s", c, err, pred)
			}
			if want := audit.Holds(c, attrs); got != want {
				t.Errorf("condition %s on %v: SQL says %v, Holds says %v\n%s", c, rowOf(attrs), got, want, pred)
			}
			if got {
				trues++
			} else {
				falses++
			}
		}
		if trues == 0 || falses == 0 {
			t.Errorf("condition %s: the rows make it %d times true and %d times false; the arm needs both", c, trues, falses)
		}
	}
}

// The live detector for a denial reason outside a denied record, executed:
// a kept deletion and an authn refusal are not counted; a reason on a
// success or a failure is, as Check reports it.
func TestSQL_UnexpectedDenialReasonCountsWhatCheckReports(t *testing.T) {
	_, sql, _ := runIt(t, "", "sql")
	s := attribute.String
	for _, tc := range []struct {
		w      audit.Writer
		reason string
	}{
		{audit.WriterController, audit.DenialReasonKeptResourcePolicy},
		{audit.WriterRequest, audit.DenialReasonNameClaimed},
	} {
		head := "-- Conditional keys, enums, closed set, target rule and W1 pairs, writer " + string(tc.w) + "."
		q := sql[strings.Index(sql, head):]
		q = q[:strings.Index(q, ";")]
		pred := countIfOf(t, q, alias("unexpected", audit.KeyDenialReason))
		for _, outcome := range []string{audit.OutcomeDenied, audit.OutcomeSuccess, audit.OutcomeFailure, ""} {
			for _, withReason := range []bool{true, false} {
				var attrs []attribute.KeyValue
				if outcome != "" {
					attrs = append(attrs, s(audit.KeyOutcome, outcome))
				}
				if withReason {
					attrs = append(attrs, s(audit.KeyDenialReason, tc.reason))
				}
				counted, err := evalSQL(pred, rowOf(attrs))
				if err != nil {
					t.Fatalf("%s: %v\n%s", tc.w, err, pred)
				}
				reported := slices.Contains(audit.Check(tc.w, attrs), audit.Violation{Key: audit.KeyDenialReason, Reason: audit.ReasonUnexpected})
				if want := withReason && outcome != audit.OutcomeDenied; counted != want || reported != want {
					t.Errorf("%s, outcome %q, reason %v: SQL counts %v, Check reports %v; want %v", tc.w, outcome, withReason, counted, reported, want)
				}
			}
		}
	}
}
