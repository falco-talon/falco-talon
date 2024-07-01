package tracing

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/falco-talon/falco-talon/configuration"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/trace"
)

var tracer oteltrace.Tracer

func SetupOTelSDK(ctx context.Context) (shutdown func(context.Context) error, oerr error) {
	var err error
	var shutdownFuncs []func(context.Context) error
	shutdown = func(ctx context.Context) error {
		for _, fn := range shutdownFuncs {
			err = errors.Join(err, fn(ctx))
		}
		shutdownFuncs = nil
		return err
	}

	handleErr := func(inErr error) {
		err = errors.Join(inErr, shutdown(ctx))
	}

	prop := newPropagator()
	otel.SetTextMapPropagator(prop)

	tracerProvider, err := newTraceProvider()
	if err != nil {
		handleErr(err)
		return
	}
	shutdownFuncs = append(shutdownFuncs, tracerProvider.Shutdown)
	otel.SetTracerProvider(tracerProvider)

	tracer = tracerProvider.Tracer("falco-talon")

	return
}

func newPropagator() propagation.TextMapPropagator {
	return propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)
}

func newTraceProvider() (*trace.TracerProvider, error) {
	traceExporter, err := newOtlpGrpcExporter(context.Background())
	if err != nil {
		return nil, err
	}

	traceProvider := trace.NewTracerProvider(
		trace.WithBatcher(traceExporter,
			trace.WithBatchTimeout(time.Second*5),
		),
		trace.WithResource(newResource()),
	)

	return traceProvider, nil
}

func newOtlpGrpcExporter(ctx context.Context) (trace.SpanExporter, error) {
	endpoint := fmt.Sprintf("%s:%s", configuration.GetConfiguration().Otel.CollectorEndpoint, configuration.GetConfiguration().Otel.CollectorPort)
	insecure := configuration.GetConfiguration().Otel.CollectorUseInsecureGrpc

	opts := []otlptracegrpc.Option{
		otlptracegrpc.WithInsecure(),
		otlptracegrpc.WithEndpoint(endpoint),
	}

	if insecure {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}

	exporter, err := otlptracegrpc.New(ctx, opts...)
	if err != nil {
		return nil, err
	}

	return exporter, nil
}

func newResource() *resource.Resource {
	res, err := resource.New(
		context.Background(),
		resource.WithAttributes(
			semconv.ServiceNameKey.String("falco-talon"),
		),
	)
	if err != nil {
		log.Fatalf("failed to create resource: %v", err)
	}
	return res
}

func GetTracer() oteltrace.Tracer {
	return tracer
}
