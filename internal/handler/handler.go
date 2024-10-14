package handler

import (
	"crypto/md5" //nolint:gosec
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/falcosecurity/falco-talon/configuration"
	"github.com/falcosecurity/falco-talon/internal/events"
	"github.com/falcosecurity/falco-talon/internal/nats"
	"github.com/falcosecurity/falco-talon/internal/otlp/metrics"
	"github.com/falcosecurity/falco-talon/internal/otlp/traces"
	"github.com/falcosecurity/falco-talon/utils"
)

func MainHandler(w http.ResponseWriter, r *http.Request) {
	config := configuration.GetConfiguration()
	if r.Method != http.MethodPost {
		http.Error(w, "Please send with POST http method", http.StatusBadRequest)
		return
	}

	if r.Body == nil {
		http.Error(w, "Please send a valid request body", http.StatusBadRequest)
		return
	}

	event, err := events.DecodeEvent(r.Body)
	if err != nil {
		http.Error(w, "Please send a valid request body", http.StatusBadRequest)
		return
	}

	rctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))

	tags := []string{}

	for _, i := range event.Tags {
		tags = append(tags, fmt.Sprintf("%v", i))
	}

	tracer := traces.GetTracer()
	ctx, span := tracer.Start(rctx, "event",
		trace.WithAttributes(attribute.String("event.rule", event.Rule)),
		trace.WithAttributes(attribute.String("event.source", event.Source)),
		trace.WithAttributes(attribute.String("event.priority", event.Priority)),
		trace.WithAttributes(attribute.String("event.output", event.Output)),
		trace.WithAttributes(attribute.String("event.tags", strings.ReplaceAll(strings.Trim(fmt.Sprint(event.Tags), "[]"), " ", ", "))),
		trace.WithAttributes(attribute.StringSlice("event.tags", tags)),
	)
	for i, j := range event.OutputFields {
		span.SetAttributes(attribute.String("event.output_fields[\""+i+"\"]", fmt.Sprintf("%v", j)))
	}
	defer span.End()
	event.TraceID = span.SpanContext().TraceID().String()
	span.AddEvent(event.String(), trace.EventOption(trace.WithTimestamp(event.Time)))
	span.SetAttributes(attribute.String("event.traceid", event.TraceID))
	span.SetStatus(codes.Ok, "event received")

	log := utils.LogLine{
		Message:  "event",
		Event:    event.Rule,
		Priority: event.Priority,
		Output:   event.Output,
		Source:   event.Source,
		TraceID:  event.TraceID,
	}

	if config.PrintAllEvents {
		utils.PrintLog("info", log)
	}

	metrics.IncreaseCounter(log)

	hasher := md5.New() //nolint:gosec
	hasher.Write([]byte(event.Output))

	err = nats.GetPublisher().PublishMsg(ctx, hex.EncodeToString(hasher.Sum(nil)), event.String())
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// HealthHandler is a simple handler to test if daemon is UP.
func HealthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status": "ok"}`))
}
