package notifiers

import (
	"context"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/falcosecurity/falco-talon/configuration"
	"github.com/falcosecurity/falco-talon/internal/events"
	"github.com/falcosecurity/falco-talon/internal/models"
	"github.com/falcosecurity/falco-talon/internal/otlp/metrics"
	"github.com/falcosecurity/falco-talon/internal/otlp/traces"
	"github.com/falcosecurity/falco-talon/internal/rules"
	"github.com/falcosecurity/falco-talon/notifiers/elasticsearch"
	"github.com/falcosecurity/falco-talon/notifiers/k8sevents"
	"github.com/falcosecurity/falco-talon/notifiers/loki"
	"github.com/falcosecurity/falco-talon/notifiers/slack"
	"github.com/falcosecurity/falco-talon/notifiers/smtp"
	"github.com/falcosecurity/falco-talon/notifiers/webhook"
	"github.com/falcosecurity/falco-talon/utils"
)

type Notifier interface {
	Init(fields map[string]any) error
	Run(log utils.LogLine) error
	Information() models.Information
	Parameters() models.Parameters
}

type Notifiers []Notifier

var defaultNotifiers *Notifiers
var enabledNotifiers *Notifiers

func init() {
	defaultNotifiers = new(Notifiers)
	defaultNotifiers = ListDefaultNotifiers()
	enabledNotifiers = new(Notifiers)
}

func ListDefaultNotifiers() *Notifiers {
	if len(*defaultNotifiers) == 0 {
		defaultNotifiers.Add(
			k8sevents.Register(),
			slack.Register(),
			smtp.Register(),
			webhook.Register(),
			loki.Register(),
			elasticsearch.Register(),
		)
	}
	return defaultNotifiers
}

func (notifiers *Notifiers) Add(notifier ...Notifier) {
	for _, i := range notifier {
		*notifiers = append(*notifiers, i)
	}
}

func GetNotifiers() *Notifiers {
	return enabledNotifiers
}

func (notifiers *Notifiers) FindNotifier(name string) Notifier {
	if notifiers == nil {
		return nil
	}

	for _, i := range *notifiers {
		if i.Information().Name == name {
			return i
		}
	}
	return nil
}

func Init() {
	config := configuration.GetConfiguration()

	specifiedNotifiers := map[string]bool{}

	for _, i := range config.ListDefaultNotifiers() {
		specifiedNotifiers[i] = true
	}
	rules := rules.GetRules()
	for _, i := range *rules {
		for _, j := range i.ListNotifiers() {
			specifiedNotifiers[j] = true
		}
	}

	for i := range specifiedNotifiers {
		for _, j := range *defaultNotifiers {
			if strings.ToLower(i) == j.Information().Name {
				if err := j.Init(config.Notifiers[i]); err != nil {
					utils.PrintLog("error", utils.LogLine{Message: "init", Error: err.Error(), Category: j.Information().Name, Status: utils.FailureStr})
					continue
				}
				enabledNotifiers.Add(j)
			}
		}
	}
}

func Notify(actx context.Context, rule *rules.Rule, action *rules.Action, event *events.Event, log utils.LogLine) {
	config := configuration.GetConfiguration()

	if len(rule.Notifiers) == 0 && len(config.DefaultNotifiers) == 0 {
		return
	}

	enabledNotifiers := map[string]bool{}

	for _, i := range config.DefaultNotifiers {
		enabledNotifiers[i] = true
	}
	for _, i := range rule.Notifiers {
		enabledNotifiers[i] = true
	}

	logN := utils.LogLine{
		Message:   "notification",
		Rule:      rule.GetName(),
		Action:    action.GetName(),
		Actionner: action.GetActionner(),
		TraceID:   event.TraceID,
	}

	logN.Stage = "action"
	if log.OutputTarget != "" {
		logN.OutputTarget = log.OutputTarget
		logN.Stage = "output"
	}

	obj := make(map[string]string, len(log.Objects))
	for i, j := range log.Objects {
		obj[cases.Title(language.Und, cases.NoLower).String(strings.ToLower(i))] = j
	}
	log.Objects = obj

	for i := range enabledNotifiers {
		if n := ListDefaultNotifiers().FindNotifier(i); n != nil {
			logN.Notifier = i
			tracer := traces.GetTracer()
			_, span := tracer.Start(actx, "notification",
				trace.WithAttributes(attribute.String("notifier.name", n.Information().Name)),
			)

			if err := n.Run(log); err != nil {
				span.SetStatus(codes.Error, err.Error())
				span.RecordError(err)
				logN.Status = utils.FailureStr
				logN.Error = err.Error()
				utils.PrintLog("error", logN)
				metrics.IncreaseCounter(log)
			} else {
				span.SetStatus(codes.Ok, "notification successfully sent")
				logN.Status = utils.SuccessStr
				utils.PrintLog("info", logN)
				metrics.IncreaseCounter(log)
			}
			span.End()
		}
	}
}
