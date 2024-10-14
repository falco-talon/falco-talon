package traces

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/falcosecurity/falco-talon/utils"

	"github.com/falcosecurity/falco-talon/configuration"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/trace"
)

var tracer oteltrace.Tracer

//nolint:nakedret
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
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
		utils.PrintLog("error", utils.LogLine{Error: err.Error(), Message: "otel"})
	}))
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
	config := configuration.GetConfiguration()

	if !config.Otel.TracesEnabled {
		return trace.NewTracerProvider(), nil
	}

	traceExporter, err := newOtlpGrpcExporter(context.Background())
	if err != nil {
		return nil, err
	}

	traceProvidersOpts := []trace.TracerProviderOption{}
	res := newResource()
	if res != nil {
		traceProvidersOpts = append(traceProvidersOpts, trace.WithResource(res))
	}

	traceProvidersOpts = append(traceProvidersOpts, trace.WithBatcher(traceExporter,
		trace.WithBatchTimeout(time.Second*5),
		trace.WithExportTimeout(time.Second*30),
	))

	traceProvider := trace.NewTracerProvider(traceProvidersOpts...)

	return traceProvider, nil
}

func newOtlpGrpcExporter(ctx context.Context) (trace.SpanExporter, error) {
	config := configuration.GetConfiguration()
	endpoint := fmt.Sprintf("%s:%s", config.Otel.CollectorEndpoint, configuration.GetConfiguration().Otel.CollectorPort)
	insecure := configuration.GetConfiguration().Otel.CollectorUseInsecureGrpc

	opts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(endpoint),
		otlptracegrpc.WithTimeout(time.Duration(config.Otel.Timeout) * time.Second),
		otlptracegrpc.WithRetry(otlptracegrpc.RetryConfig{
			Enabled:        true,
			MaxInterval:    2 * time.Second,
			MaxElapsedTime: 10 * time.Second,
		}),
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
	hostname, _ := os.Hostname()
	res, err := resource.New(
		context.Background(),
		resource.WithAttributes(
			semconv.ServiceNameKey.String("falco-talon"),
			semconv.ServiceVersionKey.String(configuration.GetInfo().GitVersion),
			semconv.ServiceInstanceID(hostname),
		),
	)
	if err != nil {
		return nil
	}
	return res
}

func GetTracer() oteltrace.Tracer {
	return tracer
}
