package handler

import (
	"crypto/md5" //nolint:gosec
	"encoding/hex"
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/falco-talon/falco-talon/tracing"

	"github.com/jinzhu/copier"
	"gopkg.in/yaml.v2"

	"github.com/falco-talon/falco-talon/configuration"
	"github.com/falco-talon/falco-talon/internal/events"
	"github.com/falco-talon/falco-talon/internal/nats"
	"github.com/falco-talon/falco-talon/internal/rules"
	"github.com/falco-talon/falco-talon/metrics"
	"github.com/falco-talon/falco-talon/utils"
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

	requestContext := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))

	tracer := tracing.GetTracer()
	ctx, span := tracer.Start(requestContext, "event",
		trace.WithAttributes(attribute.String("event.rule", event.Rule)),
		trace.WithAttributes(attribute.String("event.traceid", event.TraceID)),
		trace.WithAttributes(attribute.String("event.source", event.Source)),
	)
	defer span.End()

	event.TraceID = span.SpanContext().TraceID().String()

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

// Download the rule files
func RulesHandler(w http.ResponseWriter, _ *http.Request) {
	r := rules.GetRules()
	type yamlFile struct {
		Name        string   `yaml:"rule,omitempty"`
		Description string   `yaml:"description,omitempty"`
		Continue    string   `yaml:"continue,omitempty"`
		DryRun      string   `yaml:"dry_run,omitempty"`
		Notifiers   []string `yaml:"notifiers"`
		Actions     []struct {
			Name         string                 `yaml:"action,omitempty"`
			Description  string                 `yaml:"description,omitempty"`
			Actionner    string                 `yaml:"actionner,omitempty"`
			Parameters   map[string]interface{} `yaml:"parameters,omitempty"`
			Continue     string                 `yaml:"continue,omitempty"`
			IgnoreErrors string                 `yaml:"ignore_errors,omitempty"`
		} `yaml:"actions"`
		Match struct {
			OutputFields []string `yaml:"output_fields"`
			Priority     string   `yaml:"priority,omitempty"`
			Source       string   `yaml:"source,omitempty"`
			Rules        []string `yaml:"rules"`
			Tags         []string `yaml:"tags"`
		} `yaml:"match"`
	}

	var q []yamlFile
	if err := copier.Copy(&q, &r); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}

	w.Header().Add("Content-Type", "text/yaml")
	b, _ := yaml.Marshal(q)
	_, _ = w.Write(b)
}
