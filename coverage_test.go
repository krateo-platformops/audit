package audit

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

// coverageRow is one emit site of docs/coverage.md.
type coverageRow struct {
	line                          int
	table                         Writer // the "## <writer>" section it is in
	owner, scope, writer, action  string
	target, verb, outcomes, state string
}

var (
	coverageSection = regexp.MustCompile(`^## (\w+) \([A-Z]\)$`)
	coverageHeader  = "| owner | scope | writer | krateo.action | target | verb | outcomes | state |"
	coverageState   = regexp.MustCompile(`^(done|pending) \(\[[^\]]+\]\(https://github\.com/krateo-platformops/[a-z0-9-]+/(pull|issues)/[0-9]+\)\)$`)
)

// coverageRows parses the tables of docs/coverage.md. It fails on a table
// that is not the documented shape, so a malformed row cannot hide from
// coverageProblems.
func coverageRows(t *testing.T, doc string) []coverageRow {
	t.Helper()
	var rows []coverageRow
	var section Writer
	inTable := false
	for i, l := range strings.Split(doc, "\n") {
		if m := coverageSection.FindStringSubmatch(l); m != nil {
			section, inTable = Writer(m[1]), false
			continue
		}
		switch {
		case l == coverageHeader:
			if section == "" {
				t.Fatalf("docs/coverage.md:%d: a table outside a writer section", i+1)
			}
			inTable = true
		case strings.HasPrefix(l, "|---"):
		case inTable && strings.HasPrefix(l, "|"):
			cells := strings.Split(strings.Trim(l, "|"), " | ")
			if len(cells) != 8 {
				t.Fatalf("docs/coverage.md:%d: %d cells, want 8", i+1, len(cells))
			}
			for j := range cells {
				cells[j] = strings.TrimSpace(cells[j])
			}
			rows = append(rows, coverageRow{line: i + 1, table: section,
				owner: cells[0], scope: strings.Trim(cells[1], "`"), writer: cells[2], action: cells[3],
				target: cells[4], verb: cells[5], outcomes: cells[6], state: cells[7]})
		case strings.HasPrefix(l, "|"):
			t.Fatalf("docs/coverage.md:%d: a table that is not the coverage table", i+1)
		default:
			inTable = false
		}
	}
	return rows
}

// coverageProblems is every way rows break the inventory's rules. Each row
// names a krateo.action and sits in its writer's section. Its scope must be
// a population of that same writer in schema/v1.yaml, so the live queries
// judge its rows by that writer's rules. Its state must be done or pending,
// linked to the PR or issue it comes from.
func coverageProblems(rows []coverageRow) []string {
	scopes := map[string]Writer{}
	for _, p := range Populations() {
		scopes[p.Scope] = p.Writer
	}
	var out []string
	add := func(r coverageRow, f string, a ...any) {
		out = append(out, fmt.Sprintf("docs/coverage.md:%d: ", r.line)+fmt.Sprintf(f, a...))
	}
	for _, r := range rows {
		if r.owner == "" || len(r.action) < 3 || !strings.HasPrefix(r.action, "`") {
			add(r, "no owner, or no krateo.action spelled `...`")
		}
		switch w, ok := scopes[r.scope]; {
		case !ok:
			add(r, "%s's scope %q is not a population in schema/v1.yaml", r.action, r.scope)
		case w != Writer(r.writer):
			add(r, "scope %q is writer %s's population, the row says %s", r.scope, w, r.writer)
		}
		if Writer(r.writer) != r.table {
			add(r, "a %s row in the %s section", r.writer, r.table)
		}
		if !coverageState.MatchString(r.state) {
			add(r, "state %q is not done or pending with its PR or issue link", r.state)
		}
	}
	return out
}

// Every krateo.action docs/coverage.md lists is on a population scope of its
// own writer in schema/v1.yaml, with its state and the PR it comes from.
func TestCoverage_EveryRowHasItsPopulation(t *testing.T) {
	raw, err := os.ReadFile("docs/coverage.md")
	if err != nil {
		t.Fatal(err)
	}
	rows := coverageRows(t, string(raw))
	if len(rows) == 0 {
		t.Fatal("docs/coverage.md has no row: the check would test nothing")
	}
	for _, p := range coverageProblems(rows) {
		t.Error(p)
	}
}

// The check can fail. A row with an unlisted scope, another writer's scope,
// the wrong section, no action, or a state that names no PR is reported. The
// good row is not.
func TestCoverage_TheCheckCanFail(t *testing.T) {
	good := "## request (H)\n\n" + coverageHeader + "\n|---|---|---|---|---|---|---|---|\n" +
		"| snowplow | `github.com/krateo-platformops/snowplow/audit` | request | `call` | an object | create | success | done ([snowplow#1](https://github.com/krateo-platformops/snowplow/pull/1)) |\n"
	rows := coverageRows(t, good)
	if len(rows) != 1 || rows[0].scope != "github.com/krateo-platformops/snowplow/audit" || rows[0].table != WriterRequest {
		t.Fatalf("parse of a good row: %+v", rows)
	}
	if p := coverageProblems(rows); len(p) != 0 {
		t.Fatalf("the good row is reported: %v", p)
	}
	for name, bad := range map[string]func(r *coverageRow){
		"unlisted scope":       func(r *coverageRow) { r.scope = "github.com/krateo-platformops/nowhere/audit" },
		"another writer scope": func(r *coverageRow) { r.scope = "github.com/krateo-platformops/authn/audit/controller" },
		"another section":      func(r *coverageRow) { r.table = WriterController },
		"no action":            func(r *coverageRow) { r.action = "" },
		"state without a PR":   func(r *coverageRow) { r.state = "done" },
		"state not done": func(r *coverageRow) {
			r.state = "audited ([snowplow#1](https://github.com/krateo-platformops/snowplow/pull/1))"
		},
	} {
		r := rows[0]
		bad(&r)
		if len(coverageProblems([]coverageRow{r})) == 0 {
			t.Errorf("%s: the row is not reported", name)
		}
	}
}
