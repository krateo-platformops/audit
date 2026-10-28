// Command emit-to-stdout emits one canonical Krateo AuditEvent through a real
// OTel Logs SDK pipeline that prints to stdout, with a span on the context so
// TraceId/SpanId are stamped. Use it to see the exact record shape without a
// collector.
package main

import (
	"context"
	"log"

	"github.com/krateo-platformops/audit"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutlog"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func main() {
	ctx := context.Background()

	exp, err := stdoutlog.New(stdoutlog.WithPrettyPrint())
	if err != nil {
		log.Fatal(err)
	}
	lp := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(exp)))
	defer func() { _ = lp.Shutdown(ctx) }()

	tp := sdktrace.NewTracerProvider()
	defer func() { _ = tp.Shutdown(ctx) }()
	ctx, span := tp.Tracer("emit-to-stdout").Start(ctx, "reconcile")
	defer span.End()

	emitter := audit.New(lp.Logger("emit-to-stdout/audit"))
	emitter.Emit(ctx, audit.Event{
		Message:          "created repository demo",
		UserName:         "mario.rossi",
		Namespace:        "tenant-a",
		Group:            "github.krateo.io",
		Version:          "v1alpha1",
		Resource:         "repoes",
		Kind:             "Repo",
		ObjectName:       "demo",
		ObjectUID:        "0b6c1f4e-9a1c-4c51-8d0a-1f2e3d4c5b6a",
		ObjectGeneration: 3,
		ServerAddress:    "api.github.com",
		Action:           "rest.write",
		HTTPMethod:       "POST",
		StatusCode:       201,
		Outcome:          audit.OutcomeSuccess,
	})
}
