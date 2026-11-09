package otlpwire

// Gap c (installer#716, snowplow#1261): a record holding a string that is not
// valid UTF-8 makes the OTLP log exporter refuse the WHOLE batch it is in, so
// one request could lose other people's records.
//
//   X  through the real otlploghttp exporter and a BatchProcessor, one bad
//      record from Emit among good ones: every record arrives, the bad one's
//      values carrying U+FFFD.
//   W  one record per attribute kind, each holding invalid UTF-8 wherever the
//      kind can hold a string, sanitised and sent in ONE batch: every record
//      arrives.
//   N  the control: the same kinds NOT sanitised lose the batch, so X and W
//      would fail if the sanitiser did nothing.

import (
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/krateo-platformops/audit"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/protobuf/proto"
)

// collector is an OTLP/HTTP logs endpoint that decodes what it receives.
type collector struct {
	mu      sync.Mutex
	records []map[string]string // attribute key -> string value
	bodies  []string
}

func (c *collector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var rd io.Reader = r.Body
	if r.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		rd = gz
	}
	raw, _ := io.ReadAll(rd)
	var req collogs.ExportLogsServiceRequest
	if err := proto.Unmarshal(raw, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, rl := range req.GetResourceLogs() {
		for _, sl := range rl.GetScopeLogs() {
			for _, lr := range sl.GetLogRecords() {
				m := map[string]string{}
				for _, kv := range lr.GetAttributes() {
					m[kv.GetKey()] = kv.GetValue().GetStringValue()
				}
				c.records = append(c.records, m)
				c.bodies = append(c.bodies, lr.GetBody().GetStringValue())
			}
		}
	}
	w.Header().Set("Content-Type", "application/x-protobuf")
	out, _ := proto.Marshal(&collogs.ExportLogsServiceResponse{})
	_, _ = w.Write(out)
}

func pipeline(t *testing.T) (*collector, *sdklog.LoggerProvider) {
	t.Helper()
	col := &collector{}
	srv := httptest.NewServer(col)
	t.Cleanup(srv.Close)
	exp, err := otlploghttp.New(context.Background(), otlploghttp.WithEndpointURL(srv.URL+"/v1/logs"))
	if err != nil {
		t.Fatal(err)
	}
	return col, sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewBatchProcessor(exp)))
}

func TestX_OneBadRecordDoesNotLoseTheBatch(t *testing.T) {
	col, lp := pipeline(t)
	e := audit.New(lp.Logger("test-716"), audit.WithActor("system:serviceaccount:ns:rdc", audit.ClassController))
	good := func(name string) {
		e.Emit(context.Background(), audit.Event{Action: "rest.write", Verb: "post", ObjectName: name, ServerAddress: "api.example.com", Outcome: audit.OutcomeSuccess})
	}
	good("ok-1")
	e.Emit(context.Background(), audit.Event{
		Action: "rest.write", Verb: "post", ObjectName: "cm-\xff", ServerAddress: "api.example.com",
		Message: "external write failed: upstream said \xfe\xff", AffectedUser: "bob-\xff", UserAgent: "ua-\xff",
		Outcome: audit.OutcomeFailure,
	})
	good("ok-2")
	if err := lp.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown (flush): %v", err)
	}
	col.mu.Lock()
	defer col.mu.Unlock()
	if len(col.records) != 3 {
		t.Fatalf("the collector received %d of 3 records: one invalid string cost the batch", len(col.records))
	}
	bad := col.records[1]
	for _, k := range []string{audit.KeyObjectName, audit.LegacyKey(audit.KeyObjectName), audit.KeyAffectedUser, audit.KeyUserAgent} {
		if v := bad[k]; !utf8.ValidString(v) || !strings.Contains(v, "�") {
			t.Errorf("%s = %q, want valid UTF-8 with U+FFFD", k, v)
		}
	}
	if b := col.bodies[1]; !utf8.ValidString(b) || !strings.Contains(b, "�") {
		t.Errorf("body = %q, want valid UTF-8 with U+FFFD", b)
	}
}

// kinds is one value of each attribute kind, holding invalid UTF-8 wherever
// the kind can hold a string.
func kinds() map[string]attribute.Value {
	return map[string]attribute.Value{
		"empty": {}, "bool": attribute.BoolValue(true), "int64": attribute.Int64Value(7), "float64": attribute.Float64Value(1.5),
		"string":      attribute.StringValue("s-\xff"),
		"boolslice":   attribute.BoolSliceValue([]bool{true}),
		"int64slice":  attribute.Int64SliceValue([]int64{1}),
		"floatslice":  attribute.Float64SliceValue([]float64{1}),
		"stringslice": attribute.StringSliceValue([]string{"ok", "ss-\xff"}),
		"byteslice":   attribute.ByteSliceValue([]byte{0xff, 0xfe}),
		"slice":       attribute.SliceValue(attribute.StringValue("n-\xff"), attribute.MapValue(attribute.String("k", "nm-\xff"))),
		"map":         attribute.MapValue(attribute.String("key-\xff", "v-\xff"), attribute.Slice("list", attribute.StringValue("l-\xff"))),
	}
}

func emitKinds(t *testing.T, sanitize bool) int {
	t.Helper()
	col, lp := pipeline(t)
	logger := lp.Logger("test-716-kinds")
	ks := kinds()
	for name, v := range ks {
		kv := attribute.KeyValue{Key: "value-\xff", Value: v}
		body := v
		if sanitize {
			kv, body = audit.Sanitize(kv), audit.SanitizeValue(v)
		}
		var rec otellog.Record
		rec.SetBody(body)
		rec.AddAttributes(attribute.String("kind", name), kv)
		logger.Emit(context.Background(), rec)
	}
	_ = lp.Shutdown(context.Background()) // the unsanitised control's export fails by design
	col.mu.Lock()
	defer col.mu.Unlock()
	if sanitize && len(col.records) != len(ks) {
		t.Fatalf("the collector received %d of %d records (one per kind)", len(col.records), len(ks))
	}
	return len(col.records)
}

func TestW_EveryKindSurvivesTheRealExporterInOneBatch(t *testing.T) { emitKinds(t, true) }

func TestN_UnsanitisedKindsLoseTheBatch(t *testing.T) {
	if got := emitKinds(t, false); got != 0 {
		t.Fatalf("without the sanitiser the collector still received %d records: this arm cannot tell the sanitiser works", got)
	}
}
