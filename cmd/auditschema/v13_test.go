package main

import "testing"

// A v0.12.0 record stays valid under v0.13.0: the records audit v0.12.0's
// own Emit wrote (testdata/v0.12.0/gen) get exactly the report v0.12.0's
// auditschema gave them, and the same exit code (the one record refused
// before resolution is marked target, and reported so).
func TestCheck_V0120RecordsStayValid(t *testing.T) { recordsStayValid(t, "v0.12.0") }
