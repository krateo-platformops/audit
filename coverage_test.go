package audit

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

// coverageRow is one row of an inventory table in docs/coverage.md.
type coverageRow struct {
	line                                      int
	component, path, writer, identity, status string
	owner                                     string
}

const coverageHeader = "| component | path (what changes) | writer class | identity source | status | owner issue |"

var (
	// An issue reference, written as a reference-style link: [repo#123].
	coverageRef = regexp.MustCompile(`\[([a-z0-9-]+#[0-9]+)\]`)
	// The definition of one: [repo#123]: https://github.com/<org>/repo/(issues|pull)/123
	coverageDef = regexp.MustCompile(`^\[([a-z0-9-]+)#([0-9]+)\]: https://github\.com/(krateo-platformops|krateo-agentiko)/([a-z0-9-]+)/(issues|pull)/([0-9]+)$`)
	// A placeholder such as <user> or <ns>: the page holds no identity, not even a stand-in for one.
	coveragePlaceholder = regexp.MustCompile(`<[A-Za-z][^<>\n]*>`)
	coverageOutOfScope  = regexp.MustCompile(`^out of scope \(.+\)$`)
)

// coverageRows parses the inventory tables of docs/coverage.md. A table with
// the inventory's header must have six cells per row; any other table is
// left alone (the page has a column legend).
func coverageRows(t *testing.T, doc string) []coverageRow {
	t.Helper()
	var rows []coverageRow
	inTable := false
	for i, l := range strings.Split(doc, "\n") {
		switch {
		case l == coverageHeader:
			inTable = true
		case inTable && strings.HasPrefix(l, "|---"):
		case inTable && strings.HasPrefix(l, "|"):
			cells := strings.Split(strings.Trim(l, "|"), " | ")
			if len(cells) != 6 {
				t.Fatalf("docs/coverage.md:%d: %d cells, want 6", i+1, len(cells))
			}
			for j := range cells {
				cells[j] = strings.TrimSpace(cells[j])
			}
			rows = append(rows, coverageRow{line: i + 1, component: cells[0], path: cells[1],
				writer: cells[2], identity: cells[3], status: cells[4], owner: cells[5]})
		default:
			inTable = false
		}
	}
	return rows
}

// coverageProblems is every way the rows break audit#9's acceptance. A row
// names a component and a path, a writer class of schema v1 (or "—" when no
// writer emits, which only an out-of-scope row may say), a status from the
// closed set, and an owner issue that the page defines as a link. An
// out-of-scope row says why.
func coverageProblems(rows []coverageRow, defined map[string]bool) []string {
	writers := map[string]bool{}
	for _, w := range Writers() {
		writers[string(w)] = true
	}
	var out []string
	add := func(r coverageRow, f string, a ...any) {
		out = append(out, fmt.Sprintf("docs/coverage.md:%d: ", r.line)+fmt.Sprintf(f, a...))
	}
	for _, r := range rows {
		if r.component == "" || r.path == "" || r.identity == "" {
			add(r, "no component, path or identity source")
		}
		outOfScope := coverageOutOfScope.MatchString(r.status)
		switch r.status {
		case "audited", "not audited":
		default:
			if !outOfScope && !strings.HasPrefix(r.status, "audited, non-conformant") {
				add(r, "status %q is not audited, audited, non-conformant, not audited or out of scope (reason)", r.status)
			}
		}
		switch {
		case writers[r.writer]:
		case r.writer == "—" && outOfScope:
		case r.writer == "—":
			add(r, "no writer class, but the status %q is not out of scope", r.status)
		default:
			add(r, "writer class %q is not one of schema v1's writers", r.writer)
		}
		refs := coverageRef.FindAllStringSubmatch(r.owner, -1)
		if len(refs) == 0 {
			add(r, "no owner issue")
		}
		for _, m := range refs {
			if !defined[m[1]] {
				add(r, "owner issue [%s] has no link definition", m[1])
			}
		}
	}
	return out
}

// coverageDefinitions is the set of issue references the page defines, and
// a problem for each definition whose link text and URL disagree.
func coverageDefinitions(doc string) (map[string]bool, []string) {
	defined := map[string]bool{}
	var bad []string
	for i, l := range strings.Split(doc, "\n") {
		if !strings.HasPrefix(l, "[") || !strings.Contains(l, "]: ") {
			continue
		}
		m := coverageDef.FindStringSubmatch(l)
		if m == nil || m[1] != m[4] || m[2] != m[6] {
			bad = append(bad, fmt.Sprintf("docs/coverage.md:%d: link definition %q is not [repo#n]: its issue or pull URL", i+1, l))
			continue
		}
		defined[m[1]+"#"+m[2]] = true
	}
	return defined, bad
}

// docs/coverage.md meets audit#9's acceptance: every row names an owner
// issue or an out-of-scope reason, uses a writer class and a status from
// the closed sets, and the page holds no identity placeholder.
func TestCoverage_EveryRowMeetsTheAcceptance(t *testing.T) {
	raw, err := os.ReadFile("docs/coverage.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	rows := coverageRows(t, doc)
	if len(rows) == 0 {
		t.Fatal("docs/coverage.md has no inventory row: the check would test nothing")
	}
	defined, bad := coverageDefinitions(doc)
	for _, p := range bad {
		t.Error(p)
	}
	for _, p := range coverageProblems(rows, defined) {
		t.Error(p)
	}
	if m := coveragePlaceholder.FindString(doc); m != "" {
		t.Errorf("docs/coverage.md holds the placeholder %q: the page names no identity, not even a stand-in", m)
	}
}

// The check can fail: each broken row below is reported, and the good row
// is not. The rows go through the same parser as the real page.
func TestCoverage_TheCheckCanFail(t *testing.T) {
	good := coverageHeader + "\n|---|---|---|---|---|---|\n" +
		"| snowplow | `POST /call`: an object | request | the caller's JWT | audited | [snowplow#1] |\n" +
		"\n[snowplow#1]: https://github.com/krateo-platformops/snowplow/issues/1\n"
	rows := coverageRows(t, good)
	defined, bad := coverageDefinitions(good)
	if len(rows) != 1 || len(bad) != 0 || !defined["snowplow#1"] {
		t.Fatalf("parse of the good page: rows %+v, bad definitions %v, defined %v", rows, bad, defined)
	}
	if p := coverageProblems(rows, defined); len(p) != 0 {
		t.Fatalf("the good row is reported: %v", p)
	}
	for name, breakIt := range map[string]func(r *coverageRow){
		"no owner issue":          func(r *coverageRow) { r.owner = "snowplow" },
		"undefined owner issue":   func(r *coverageRow) { r.owner = "[snowplow#2]" },
		"status outside the set":  func(r *coverageRow) { r.status = "done" },
		"out of scope, no reason": func(r *coverageRow) { r.status = "out of scope" },
		"unknown writer class":    func(r *coverageRow) { r.writer = "issuer" },
		"no writer, but audited":  func(r *coverageRow) { r.writer = "—" },
		"no path":                 func(r *coverageRow) { r.path = "" },
		"no identity source":      func(r *coverageRow) { r.identity = "" },
	} {
		r := rows[0]
		breakIt(&r)
		if len(coverageProblems([]coverageRow{r}, defined)) == 0 {
			t.Errorf("%s: the row is not reported", name)
		}
	}
	// An out-of-scope row with a reason and no writer is fine.
	r := rows[0]
	r.writer, r.status = "—", "out of scope (not mounted)"
	if p := coverageProblems([]coverageRow{r}, defined); len(p) != 0 {
		t.Errorf("an out-of-scope row with its reason is reported: %v", p)
	}
	// A definition whose text and URL name different issues is reported.
	if _, bad := coverageDefinitions("[snowplow#1]: https://github.com/krateo-platformops/snowplow/issues/2\n"); len(bad) == 0 {
		t.Error("a definition whose number disagrees with its URL is not reported")
	}
	if _, bad := coverageDefinitions("[snowplow#1]: https://github.com/krateo-platformops/authn/issues/1\n"); len(bad) == 0 {
		t.Error("a definition whose repository disagrees with its URL is not reported")
	}
	// A placeholder is found.
	if coveragePlaceholder.FindString("the <user>-clientconfig Secret") == "" {
		t.Error("a <user> placeholder is not found")
	}
}
