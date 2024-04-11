package metrics

import (
	"context"
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdk "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"

	"github.com/falco-talon/falco-talon/configuration"
	"github.com/falco-talon/falco-talon/utils"
)

const meterName = "github.com/falco-talon/falco-talon"

var (
	eventCounter        metric.Int64Counter
	matchCounter        metric.Int64Counter
	actionCounter       metric.Int64Counter
	notificationCounter metric.Int64Counter
)
var ctx context.Context

func init() {
	ctx = context.Background()
	exporter, err := prometheus.New()
	if err != nil {
		utils.PrintLog("fatal", utils.LogLine{Error: err.Error(), Message: "init"})
		log.Fatal(err)
	}
	resources := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceNameKey.String("falco-talon"),
		semconv.ServiceVersionKey.String(configuration.GetInfo().GitVersion),
	)
	provider := sdk.NewMeterProvider(
		sdk.WithReader(exporter),
		sdk.WithResource(resources),
	)
	meter := provider.Meter(
		meterName,
		metric.WithInstrumentationVersion(configuration.GetInfo().GitVersion),
	)

	eventCounter, _ = meter.Int64Counter("event", metric.WithDescription("number of received events"))
	matchCounter, _ = meter.Int64Counter("match", metric.WithDescription("number of matched events"))
	actionCounter, _ = meter.Int64Counter("action", metric.WithDescription("number of actions"))
	notificationCounter, _ = meter.Int64Counter("notification", metric.WithDescription("number of notifications"))
}

func IncreaseCounter(log utils.LogLine) {
	opts := getMeasurementOption(log)
	switch log.Message {
	case "event":
		eventCounter.Add(ctx, 1, opts)
	case "match":
		matchCounter.Add(ctx, 1, opts)
	case "action":
		actionCounter.Add(ctx, 1, opts)
	case "notification":
		notificationCounter.Add(ctx, 1, opts)
	}
}

func getMeasurementOption(log utils.LogLine) metric.MeasurementOption {
	attrs := []attribute.KeyValue{}
	if log.Rule != "" {
		attrs = append(attrs, attribute.Key("rule").String(log.Rule))
	}
	if log.Event != "" {
		attrs = append(attrs, attribute.Key("event").String(log.Event))
	}
	if log.Priority != "" {
		attrs = append(attrs, attribute.Key("priority").String(log.Priority))
	}
	if log.Source != "" {
		attrs = append(attrs, attribute.Key("source").String(log.Source))
	}
	if log.Notifier != "" {
		attrs = append(attrs, attribute.Key("notifier").String(log.Notifier))
	}
	if log.Actionner != "" {
		attrs = append(attrs, attribute.Key("actionner").String(log.Actionner))
	}
	if log.ActionnerCategory != "" {
		attrs = append(attrs, attribute.Key("actionner_category").String(log.ActionnerCategory))
	}
	if log.Action != "" {
		attrs = append(attrs, attribute.Key("action").String(log.Action))
	}
	if log.Status != "" {
		attrs = append(attrs, attribute.Key("status").String(log.Status))
	}
	if len(log.Objects) > 0 {
		for i, j := range log.Objects {
			attrs = append(attrs, attribute.Key(i).String(j))
		}
	}

	opts := metric.WithAttributes(attrs...)
	return opts
}

func Handler() http.Handler {
	return promhttp.Handler()
}
