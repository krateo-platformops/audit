// Command emit-to-stdout emits one canonical Krateo AuditEvent through a real
// OTel Logs SDK pipeline that prints to stdout, with a span on the context so
// TraceId/SpanId are stamped, then checks the record against the schema. Use it
// to see the exact record shape without a collector.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/krateo-platformops/audit"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutlog"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// checker checks each record it is handed against the schema for a
// controller, and prints the violations (keys and reasons, never values).
type checker struct{}

func (checker) OnEmit(_ context.Context, r *sdklog.Record) error {
	var attrs []attribute.KeyValue
	r.WalkAttributes(func(kv attribute.KeyValue) bool { attrs = append(attrs, kv); return true })
	vs := audit.CheckRecord(audit.WriterController, r.EventName(), attrs)
	fmt.Fprintf(os.Stderr, "schema %s, writer %s: %d violation(s) %v\n", audit.SchemaVersion, audit.WriterController, len(vs), vs)
	return nil
}
func (checker) Enabled(context.Context, sdklog.EnabledParameters) bool { return true }
func (checker) Shutdown(context.Context) error                         { return nil }
func (checker) ForceFlush(context.Context) error                       { return nil }

func main() {
	ctx := context.Background()

	exp, err := stdoutlog.New(stdoutlog.WithPrettyPrint())
	if err != nil {
		log.Fatal(err)
	}
	lp := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(checker{}),
		sdklog.WithProcessor(sdklog.NewSimpleProcessor(exp)),
	)
	defer func() { _ = lp.Shutdown(ctx) }()

	tp := sdktrace.NewTracerProvider()
	defer func() { _ = tp.Shutdown(ctx) }()
	ctx, span := tp.Tracer("emit-to-stdout").Start(ctx, "reconcile")
	defer span.End()

	// A controller reports its own ServiceAccount as the actor.
	emitter := audit.New(lp.Logger("emit-to-stdout/audit"),
		audit.WithActor("system:serviceaccount:krateo-system:github-provider", audit.ClassController))
	emitter.Emit(ctx, audit.Event{
		Message:          "created repository",
		Namespace:        "tenant-a",
		Group:            "github.krateo.io",
		Version:          "v1alpha1",
		Resource:         "repoes",
		Kind:             "Repo",
		ObjectName:       "demo",
		ObjectUID:        "0b6c1f4e-9a1c-4c51-8d0a-1f2e3d4c5b6a",
		ObjectGeneration: 3,
		Preview:          audit.PreviewFalse, // tenant-a is not the preview sandbox
		ServerAddress:    "api.github.com",
		Action:           "rest.write",
		Verb:             "post",
		HTTPMethod:       "POST",
		StatusCode:       201,
		Outcome:          audit.OutcomeSuccess,
	})
}
