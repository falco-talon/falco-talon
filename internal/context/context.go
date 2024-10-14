package context

import (
	"context"
	"fmt"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/falcosecurity/falco-talon/internal/context/aws"
	"github.com/falcosecurity/falco-talon/internal/otlp/traces"

	"github.com/falcosecurity/falco-talon/internal/context/kubernetes"
	"github.com/falcosecurity/falco-talon/internal/events"
)

func GetContext(actx context.Context, source string, event *events.Event) (map[string]any, error) {
	tracer := traces.GetTracer()

	_, span := tracer.Start(actx, "context",
		oteltrace.WithAttributes(attribute.String("context.source", source)),
	)
	defer span.End()

	context := make(map[string]any)
	var err error

	switch source {
	case "aws":
		context, err = aws.GetAwsContext(event)
	case "k8snode":
		context, err = kubernetes.GetNodeContext(event)
	default:
		err = fmt.Errorf("unknown context '%v'", source)
	}

	if err != nil {
		span.SetStatus(codes.Error, "failed to add context")
		span.RecordError(err)
		return nil, err
	}

	for k, v := range context {
		span.SetAttributes(attribute.String(strings.ToLower(k), fmt.Sprintf("%v", v)))
	}

	return context, nil
}
