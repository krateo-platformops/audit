package main

import "testing"

// A v0.10.0 record stays valid under v0.11.0's Check, which now applies the
// formats through the exported validators: the records audit v0.10.0's own
// Emit wrote (testdata/v0.10.0/gen: every format a record carries, the
// username checks, invalid_request and name_not_issued, and the v0.6.0 to
// v0.9.1 shapes) get exactly the report v0.10.0's auditschema gave them, and
// the same exit code.
func TestCheck_V0100RecordsStayValid(t *testing.T) { recordsStayValid(t, "v0.10.0") }
