package audit

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

// coverageRow is one mutating path in docs/coverage.md.
type coverageRow struct {
	line  int
	table Writer // the "## <writer> (X)" section it is in; "—" for "## no writer"

	component, path, writer, identity, status, owner string // audit#9's columns
	scope, action, verb, outcomes                    string // the schema columns, blank when not known yet
}

// noWriter is the writer-class cell, and the section, of a path no writer records.
const noWriter Writer = "—"

var (
	coverageSection  = regexp.MustCompile(`^## (\w+) \([A-Z]\)$`)
	coverageNoWriter = "## no writer"
	coverageHeader   = "| component | path (what changes) | writer class | identity source | status | owner issue | scope | krateo.action | verb | outcomes |"

	// An issue or PR reference, written as a reference-style link: [repo#123].
	coverageRef = regexp.MustCompile(`\[([a-z0-9-]+#[0-9]+)\]`)
	// Its definition: [repo#123]: https://github.com/<org>/repo/(issues|pull)/123.
	coverageDef = regexp.MustCompile(`^\[([a-z0-9-]+)#([0-9]+)\]: https://github\.com/(krateo-platformops|krateo-agentiko)/([a-z0-9-]+)/(issues|pull)/([0-9]+)$`)
	// The identity shapes the page must not hold. A person's name has no
	// shape a pattern can tell from a word, so names are a review rule, not
	// a check here.
	//
	// A placeholder such as <user>: not even a stand-in for an identity.
	coveragePlaceholder = regexp.MustCompile(`<[A-Za-z][^<>\n]*>`)
	// An email address.
	coverageEmail = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)
	// A clientconfig Secret spelled by its name, which embeds the user's
	// (name-clientconfig, name-clientconfig-stepup): describe it in words.
	coverageUserSecret = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9._-]*-clientconfig`)
	coverageOutOfScope = regexp.MustCompile(`^out of scope \(.+\)$`)
)

// coverageRows parses the inventory tables of docs/coverage.md. It fails on
// an inventory table outside a writer section, on a table that looks like
// the inventory but has another header, and on a row with the wrong number
// of cells, so a malformed row cannot hide from coverageProblems. Other
// tables (the column legend) are left alone.
func coverageRows(t *testing.T, doc string) []coverageRow {
	t.Helper()
	var rows []coverageRow
	var section Writer
	inTable := false
	for i, l := range strings.Split(doc, "\n") {
		if strings.HasPrefix(l, "## ") {
			section, inTable = "", false
			if m := coverageSection.FindStringSubmatch(l); m != nil {
				section = Writer(m[1])
			} else if l == coverageNoWriter {
				section = noWriter
			}
			continue
		}
		switch {
		case l == coverageHeader:
			if section == "" {
				t.Fatalf("docs/coverage.md:%d: an inventory table outside a writer section", i+1)
			}
			inTable = true
		case !inTable && strings.HasPrefix(l, "| component | path"):
			t.Fatalf("docs/coverage.md:%d: an inventory table whose header is not %q", i+1, coverageHeader)
		case inTable && strings.HasPrefix(l, "|---"):
		case inTable && strings.HasPrefix(l, "|"):
			cells := strings.Split(strings.TrimSuffix(strings.TrimPrefix(l, "|"), "|"), "|")
			if len(cells) != 10 {
				t.Fatalf("docs/coverage.md:%d: %d cells, want 10", i+1, len(cells))
			}
			for j := range cells {
				cells[j] = strings.TrimSpace(cells[j])
			}
			rows = append(rows, coverageRow{line: i + 1, table: section,
				component: cells[0], path: cells[1], writer: cells[2], identity: cells[3], status: cells[4], owner: cells[5],
				scope: strings.Trim(cells[6], "`"), action: cells[7], verb: cells[8], outcomes: cells[9]})
		default:
			inTable = false
		}
	}
	return rows
}

// coverageProblems is every way rows break the inventory's rules.
//
// audit#9's acceptance: a row names a component, a path and an identity
// source; a writer class of schema v1, or "—" on an out-of-scope row only; a
// status from the closed set, with the reason when it is out of scope; and
// an owner issue the page defines as a link.
//
// Conformance: a row sits in its writer's section. A scope, when given, is a
// population of that same writer in schema/v1.yaml, so the live queries
// judge its rows by that writer's rules, and an audited path always names
// its scope. A krateo.action, when given, is spelled `...`.
func coverageProblems(rows []coverageRow, defined map[string]bool) []string {
	writers := map[Writer]bool{}
	for _, w := range Writers() {
		writers[w] = true
	}
	scopes := map[string]Writer{}
	for _, p := range Populations() {
		scopes[p.Scope] = p.Writer
	}
	var out []string
	add := func(r coverageRow, f string, a ...any) {
		out = append(out, fmt.Sprintf("docs/coverage.md:%d: ", r.line)+fmt.Sprintf(f, a...))
	}
	for _, r := range rows {
		w := Writer(r.writer)
		if r.component == "" || r.path == "" || r.identity == "" {
			add(r, "no component, path or identity source")
		}

		outOfScope := coverageOutOfScope.MatchString(r.status)
		audited := r.status == "audited" || strings.HasPrefix(r.status, "audited, non-conformant")
		if !audited && !outOfScope && r.status != "not audited" {
			add(r, "status %q is not audited, audited, non-conformant, not audited or out of scope (reason)", r.status)
		}

		switch {
		case writers[w]:
		case w == noWriter && outOfScope:
		case w == noWriter:
			add(r, "no writer class, but the status %q is not out of scope", r.status)
		default:
			add(r, "writer class %q is not one of schema v1's writers", r.writer)
		}
		if w != r.table {
			add(r, "a %s row in the %s section", r.writer, r.table)
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

		switch sw, ok := scopes[r.scope]; {
		case r.scope == "" && audited:
			add(r, "an audited path names no scope")
		case r.scope == "":
		case !ok:
			add(r, "scope %q is not a population in schema/v1.yaml", r.scope)
		case sw != w:
			add(r, "scope %q is writer %s's population, the row says %s", r.scope, sw, r.writer)
		}
		if r.action != "" && (len(r.action) < 3 || !strings.HasPrefix(r.action, "`") || !strings.HasSuffix(r.action, "`")) {
			add(r, "krateo.action %q is not spelled `...`", r.action)
		}
	}
	return out
}

// coverageDefinitions is the set of references the page defines, and a
// problem for each definition whose link text and URL disagree.
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

// coverageIdentityProblems is every identity shape the page holds: a
// placeholder, an email address, or a clientconfig Secret spelled by its
// user-named name.
func coverageIdentityProblems(doc string) []string {
	var out []string
	for i, l := range strings.Split(doc, "\n") {
		for _, c := range []struct {
			re   *regexp.Regexp
			what string
		}{
			{coveragePlaceholder, "a placeholder: not even a stand-in for an identity"},
			{coverageEmail, "an email address"},
			{coverageUserSecret, "a clientconfig Secret spelled by its user-named name: describe it in words"},
		} {
			if m := c.re.FindString(l); m != "" {
				out = append(out, fmt.Sprintf("docs/coverage.md:%d: %q is %s", i+1, m, c.what))
			}
		}
	}
	return out
}

// docs/coverage.md meets audit#9's acceptance, and every scope it names is a
// population of its own writer in schema/v1.yaml.
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
	for _, p := range coverageIdentityProblems(doc) {
		t.Error(p)
	}
}

// The check can fail: each broken row below is reported, and the good row
// is not. The rows go through the same parser as the real page.
func TestCoverage_TheCheckCanFail(t *testing.T) {
	good := "## request (H)\n\n" + coverageHeader + "\n|---|---|---|---|---|---|---|---|---|---|\n" +
		"| snowplow | `POST /call`: an object | request | the caller's JWT | audited | [snowplow#1] | `github.com/krateo-platformops/snowplow/audit` | `call` | create | success, failure |\n" +
		"\n[snowplow#1]: https://github.com/krateo-platformops/snowplow/issues/1\n"
	rows := coverageRows(t, good)
	defined, bad := coverageDefinitions(good)
	if len(rows) != 1 || rows[0].table != WriterRequest || rows[0].scope != "github.com/krateo-platformops/snowplow/audit" ||
		len(bad) != 0 || !defined["snowplow#1"] {
		t.Fatalf("parse of the good page: rows %+v, bad definitions %v, defined %v", rows, bad, defined)
	}
	if p := coverageProblems(rows, defined); len(p) != 0 {
		t.Fatalf("the good row is reported: %v", p)
	}
	for name, breakIt := range map[string]func(r *coverageRow){
		"unlisted scope":          func(r *coverageRow) { r.scope = "github.com/krateo-platformops/nowhere/audit" },
		"another writer's scope":  func(r *coverageRow) { r.scope = "github.com/krateo-platformops/authn/audit/controller" },
		"audited, no scope":       func(r *coverageRow) { r.scope = "" },
		"another section":         func(r *coverageRow) { r.table = WriterController },
		"action not spelled":      func(r *coverageRow) { r.action = "call" },
		"no owner issue":          func(r *coverageRow) { r.owner = "snowplow" },
		"undefined owner issue":   func(r *coverageRow) { r.owner = "[snowplow#2]" },
		"status outside the set":  func(r *coverageRow) { r.status = "done" },
		"out of scope, no reason": func(r *coverageRow) { r.status = "out of scope" },
		"unknown writer class":    func(r *coverageRow) { r.writer = "issuer" },
		"no writer, but audited":  func(r *coverageRow) { r.writer, r.table = "—", noWriter },
		"no path":                 func(r *coverageRow) { r.path = "" },
		"no identity source":      func(r *coverageRow) { r.identity = "" },
	} {
		r := rows[0]
		breakIt(&r)
		if len(coverageProblems([]coverageRow{r}, defined)) == 0 {
			t.Errorf("%s: the row is not reported", name)
		}
	}

	// Rows that are fine: a path not audited yet with its schema columns
	// blank, and an out-of-scope row with its reason and no writer.
	notYet := rows[0]
	notYet.status, notYet.scope, notYet.action, notYet.verb, notYet.outcomes = "not audited", "", "", "", ""
	none := notYet
	none.writer, none.table, none.status = "—", noWriter, "out of scope (not mounted)"
	if p := coverageProblems([]coverageRow{notYet, none}, defined); len(p) != 0 {
		t.Errorf("a blank-schema not-audited row or an out-of-scope row with its reason is reported: %v", p)
	}

	// A definition whose text and URL name different issues is reported.
	for _, d := range []string{
		"[snowplow#1]: https://github.com/krateo-platformops/snowplow/issues/2\n",
		"[snowplow#1]: https://github.com/krateo-platformops/authn/issues/1\n",
	} {
		if _, bad := coverageDefinitions(d); len(bad) == 0 {
			t.Errorf("the definition %q is not reported", d)
		}
	}

	// Each identity shape is found; the words the page uses instead are not.
	for _, bad := range []string{
		"the <user>-clientconfig Secret",
		"contact first.last@example.com",
		"the Secret `jdoe-clientconfig`",
		"the Secret jdoe-clientconfig-stepup",
	} {
		if len(coverageIdentityProblems(bad)) == 0 {
			t.Errorf("%q is not reported", bad)
		}
	}
	for _, fine := range []string{
		"creates or updates the user's clientconfig Secret",
		"the user's step-up clientconfig Secret",
		"`auditschema check` pinned with a tool directive",
	} {
		if p := coverageIdentityProblems(fine); len(p) != 0 {
			t.Errorf("%q is reported: %v", fine, p)
		}
	}
}
