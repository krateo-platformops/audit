// Command auditschema checks audit records against schema/v1.yaml for writers
// that are not written in Go, and prints the live conformance queries.
//
//	auditschema check -writer gateway [record.json ...]
//	    validates OTLP/JSON log records (an ExportLogsServiceRequest, one
//	    LogRecord, or a JSON array of LogRecords; stdin when no file) with
//	    the same audit.CheckRecord a Go writer's tests use. It prints one line
//	    per violation, naming a key and a reason, never a value. Exit 1 when a
//	    record breaks the schema, 2 on a usage or input error.
//
//	auditschema sql
//	    prints the ClickHouse queries that check default.krateo_audit, built
//	    from the same schema, so the live check and the unit check cannot
//	    drift: required keys per writer population (with an impossible-key
//	    control and the legacy gateway rows as a positive control), the
//	    conditional, enum, closed-set and W1 rules, and the identity leak
//	    detector.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/krateo-platformops/audit"
)

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: auditschema check -writer <writer> [file ...] | auditschema sql")
		return 2
	}
	switch args[0] {
	case "check":
		return runCheck(args[1:], stdin, stdout, stderr)
	case "sql":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "usage: auditschema sql")
			return 2
		}
		fmt.Fprint(stdout, conformanceSQL())
		return 0
	default:
		fmt.Fprintf(stderr, "auditschema: unknown command %q\n", args[0])
		return 2
	}
}

func runCheck(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	writer := fs.String("writer", "", fmt.Sprintf("writer class, one of %v", audit.Writers()))
	if err := fs.Parse(args); err != nil {
		return 2
	}
	w := audit.Writer(*writer)
	if !isWriter(w) {
		fmt.Fprintf(stderr, "auditschema: -writer must be one of %v\n", audit.Writers())
		return 2
	}

	type input struct {
		name string
		r    io.Reader
	}
	var inputs []input
	if fs.NArg() == 0 {
		inputs = append(inputs, input{"stdin", stdin})
	}
	for _, p := range fs.Args() {
		f, err := os.Open(p)
		if err != nil {
			fmt.Fprintln(stderr, "auditschema:", err)
			return 2
		}
		defer f.Close()
		inputs = append(inputs, input{p, f})
	}

	bad, total := 0, 0
	for _, in := range inputs {
		recs, err := decodeRecords(in.r)
		if err != nil {
			fmt.Fprintf(stderr, "auditschema: %s: %v\n", in.name, err)
			return 2
		}
		for i, r := range recs {
			total++
			vs := audit.CheckRecord(w, r.eventName, r.attrs)
			if len(vs) > 0 {
				bad++
			}
			for _, v := range vs {
				fmt.Fprintf(stdout, "%s: record %d: %s\n", in.name, i, v)
			}
		}
	}
	if total == 0 {
		fmt.Fprintln(stderr, "auditschema: no record in the input: nothing was checked")
		return 2
	}
	fmt.Fprintf(stdout, "%d of %d record(s) break schema %s for writer %s\n", bad, total, audit.SchemaVersion, w)
	if bad > 0 {
		return 1
	}
	return 0
}

func isWriter(w audit.Writer) bool {
	for _, x := range audit.Writers() {
		if x == w {
			return true
		}
	}
	return false
}
