package actionners

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"runtime"
	"strconv"
	"strings"

	"go.opentelemetry.io/otel/codes"

	"github.com/falco-talon/falco-talon/internal/otlp/traces"

	lambdaInvoke "github.com/falco-talon/falco-talon/actionners/aws/lambda"
	"github.com/falco-talon/falco-talon/actionners/webhook"
	"github.com/falco-talon/falco-talon/internal/http"
	"github.com/falco-talon/falco-talon/outputs"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	calicoNetworkpolicy "github.com/falco-talon/falco-talon/actionners/calico/networkpolicy"
	ciliumNetworkPolicy "github.com/falco-talon/falco-talon/actionners/cilium/networkpolicy"
	k8sCordon "github.com/falco-talon/falco-talon/actionners/kubernetes/cordon"
	k8sDelete "github.com/falco-talon/falco-talon/actionners/kubernetes/delete"
	k8sDownload "github.com/falco-talon/falco-talon/actionners/kubernetes/download"
	k8sDrain "github.com/falco-talon/falco-talon/actionners/kubernetes/drain"
	k8sExec "github.com/falco-talon/falco-talon/actionners/kubernetes/exec"
	k8sLabel "github.com/falco-talon/falco-talon/actionners/kubernetes/label"
	k8sLog "github.com/falco-talon/falco-talon/actionners/kubernetes/log"
	k8sNetworkpolicy "github.com/falco-talon/falco-talon/actionners/kubernetes/networkpolicy"
	k8sScript "github.com/falco-talon/falco-talon/actionners/kubernetes/script"
	k8sTcpdump "github.com/falco-talon/falco-talon/actionners/kubernetes/tcpdump"
	k8sTerminate "github.com/falco-talon/falco-talon/actionners/kubernetes/terminate"
	"github.com/falco-talon/falco-talon/configuration"
	awsChecks "github.com/falco-talon/falco-talon/internal/aws/checks"
	aws "github.com/falco-talon/falco-talon/internal/aws/client"
	calico "github.com/falco-talon/falco-talon/internal/calico/client"
	cilium "github.com/falco-talon/falco-talon/internal/cilium/client"
	talonContext "github.com/falco-talon/falco-talon/internal/context"
	"github.com/falco-talon/falco-talon/internal/events"
	k8sChecks "github.com/falco-talon/falco-talon/internal/kubernetes/checks"
	k8s "github.com/falco-talon/falco-talon/internal/kubernetes/client"
	"github.com/falco-talon/falco-talon/internal/nats"
	"github.com/falco-talon/falco-talon/internal/otlp/metrics"
	"github.com/falco-talon/falco-talon/internal/rules"
	"github.com/falco-talon/falco-talon/notifiers"
	"github.com/falco-talon/falco-talon/outputs/model"
	"github.com/falco-talon/falco-talon/utils"
)

type Actionner struct {
	Name                    string
	Category                string
	Action                  func(action *rules.Action, event *events.Event) (utils.LogLine, *model.Data, error)
	CheckParameters         func(action *rules.Action) error
	Init                    func() error
	Checks                  []checkActionner
	DefaultContinue         bool
	AllowAdditionalContexts bool
	AllowOutput             bool
	RequireOutput           bool
}

// type checkActionner func(event *events.Event, actions ...rules.Action) error
type checkActionner func(event *events.Event, action *rules.Action) error

type Actionners []*Actionner

var availableActionners *Actionners
var enabledActionners *Actionners

const (
	trueStr  string = "true"
	falseStr string = "false"
)

func init() {
	availableActionners = new(Actionners)
	availableActionners = GetDefaultActionners()
	enabledActionners = new(Actionners)
}

func GetDefaultActionners() *Actionners {
	if len(*availableActionners) == 0 {
		availableActionners.Add(
			&Actionner{
				Category:        "kubernetes",
				Name:            "terminate",
				DefaultContinue: false,
				Init:            k8s.Init,
				Checks: []checkActionner{
					k8sChecks.CheckPodExist,
				},
				CheckParameters: k8sTerminate.CheckParameters,
				Action:          k8sTerminate.Action,
			},
			&Actionner{
				Category:        "kubernetes",
				Name:            "label",
				DefaultContinue: true,
				Init:            k8s.Init,
				Checks:          []checkActionner{k8sChecks.CheckPodExist},
				CheckParameters: k8sLabel.CheckParameters,
				Action:          k8sLabel.Action,
			},
			&Actionner{
				Category:        "kubernetes",
				Name:            "networkpolicy",
				DefaultContinue: true,
				Init:            k8s.Init,
				Checks: []checkActionner{
					k8sChecks.CheckPodExist,
				},
				CheckParameters: k8sNetworkpolicy.CheckParameters,
				Action:          k8sNetworkpolicy.Action,
			},
			&Actionner{
				Category:        "kubernetes",
				Name:            "exec",
				DefaultContinue: true,
				Init:            k8s.Init,
				Checks: []checkActionner{
					k8sChecks.CheckPodExist,
				},
				CheckParameters:         k8sExec.CheckParameters,
				Action:                  k8sExec.Action,
				AllowAdditionalContexts: true,
			},
			&Actionner{
				Category:        "kubernetes",
				Name:            "script",
				DefaultContinue: true,
				Init:            k8s.Init,
				Checks: []checkActionner{
					k8sChecks.CheckPodExist,
				},
				CheckParameters:         k8sScript.CheckParameters,
				Action:                  k8sScript.Action,
				AllowAdditionalContexts: true,
			},
			&Actionner{
				Category:        "kubernetes",
				Name:            "log",
				DefaultContinue: true,
				Init:            k8s.Init,
				Checks: []checkActionner{
					k8sChecks.CheckPodExist,
				},
				CheckParameters: k8sLog.CheckParameters,
				Action:          k8sLog.Action,
				AllowOutput:     true,
			},
			&Actionner{
				Category:        "kubernetes",
				Name:            "delete",
				DefaultContinue: false,
				Init:            k8s.Init,
				Checks: []checkActionner{
					k8sChecks.CheckTargetExist,
				},
				CheckParameters: nil,
				Action:          k8sDelete.Action,
			},
			&Actionner{
				Category:        "kubernetes",
				Name:            "cordon",
				DefaultContinue: true,
				Init:            k8s.Init,
				Checks: []checkActionner{
					k8sChecks.CheckPodExist,
				},
				CheckParameters: nil,
				Action:          k8sCordon.Action,
			},
			&Actionner{
				Category:        "kubernetes",
				Name:            "drain",
				DefaultContinue: true,
				Init:            k8s.Init,
				Checks: []checkActionner{
					k8sChecks.CheckPodExist,
				},
				CheckParameters: k8sDrain.CheckParameters,
				Action:          k8sDrain.Action,
			},
			&Actionner{
				Category:        "kubernetes",
				Name:            "download",
				DefaultContinue: true,
				Init:            k8s.Init,
				Checks: []checkActionner{
					k8sChecks.CheckPodExist,
				},
				CheckParameters:         k8sDownload.CheckParameters,
				Action:                  k8sDownload.Action,
				AllowAdditionalContexts: true,
				RequireOutput:           true,
			},
			&Actionner{
				Category:        "kubernetes",
				Name:            "tcpdump",
				DefaultContinue: true,
				Init:            k8s.Init,
				Checks: []checkActionner{
					k8sChecks.CheckPodExist,
				},
				AllowAdditionalContexts: true,
				CheckParameters:         k8sTcpdump.CheckParameters,
				Action:                  k8sTcpdump.Action,
				RequireOutput:           true,
			},
			&Actionner{
				Category:        "webhook",
				Name:            "call",
				DefaultContinue: true,
				Init:            http.Init,
				Checks:          []checkActionner{},
				CheckParameters: webhook.CheckParameters,
				Action:          webhook.Action,
			},
			&Actionner{
				Category:        "aws",
				Name:            "lambda",
				DefaultContinue: false,
				Init:            aws.Init,
				Checks: []checkActionner{
					awsChecks.CheckLambdaExist,
				},
				CheckParameters:         lambdaInvoke.CheckParameters,
				Action:                  lambdaInvoke.Action,
				AllowAdditionalContexts: true,
			},
			&Actionner{
				Category:        "calico",
				Name:            "networkpolicy",
				DefaultContinue: true,
				Init:            calico.Init,
				Checks: []checkActionner{
					k8sChecks.CheckPodExist,
					k8sChecks.CheckRemoteIP,
				},
				CheckParameters: calicoNetworkpolicy.CheckParameters,
				Action:          calicoNetworkpolicy.Action,
			},
			&Actionner{
				Category:        "cilium",
				Name:            "networkpolicy",
				DefaultContinue: true,
				Init:            cilium.Init,
				Checks: []checkActionner{
					k8sChecks.CheckPodExist,
					k8sChecks.CheckRemoteIP,
				},
				CheckParameters: ciliumNetworkPolicy.CheckParameters,
				Action:          ciliumNetworkPolicy.Action,
			},
		)
	}

	return availableActionners
}

func Init() error {
	rules := rules.GetRules()

	categories := map[string]bool{}
	enabledCategories := map[string]bool{}

	// list actionner categories to init
	for _, i := range *rules {
		for _, j := range i.Actions {
			categories[j.GetActionnerCategory()] = true
		}
	}

	for category := range categories {
		utils.PrintLog("info", utils.LogLine{Message: "init", ActionnerCategory: category})
		for _, actionner := range *availableActionners {
			if category == actionner.Category {
				if actionner.Init != nil {
					if err := actionner.Init(); err != nil {
						utils.PrintLog("error", utils.LogLine{Message: "init", Error: err.Error(), ActionnerCategory: actionner.Category})
						return err
					}
				}
				enabledCategories[category] = true
			}
		}
	}

	for i := range enabledCategories {
		for _, j := range *availableActionners {
			if i == j.Category {
				enabledActionners.Add(j)
			}
		}
	}

	return nil
}

func (actionners *Actionners) Add(actionner ...*Actionner) {
	*actionners = append(*actionners, actionner...)
}

func GetActionners() *Actionners {
	return enabledActionners
}

func (actionners *Actionners) FindActionner(fullname string) *Actionner {
	if actionners == nil {
		return nil
	}

	for _, i := range *actionners {
		if i == nil {
			continue
		}
		if fullname == fmt.Sprintf("%v:%v", i.Category, i.Name) {
			return i
		}
	}
	return nil
}

func (actionner *Actionner) GetFullName() string {
	return actionner.Category + ":" + actionner.Name
}

func (actionner *Actionner) GetName() string {
	return actionner.Name
}

func (actionner *Actionner) GetCategory() string {
	return actionner.Category
}

func (actionner *Actionner) MustDefaultContinue() bool {
	return actionner.DefaultContinue
}

func (actionner *Actionner) IsOutputRequired() bool {
	return actionner.RequireOutput
}

func (actionner *Actionner) IsOutputAllowed() bool {
	return actionner.AllowOutput
}

func (actionner *Actionner) AllowAdditionalContext() bool {
	return actionner.AllowAdditionalContexts
}

func runAction(mctx context.Context, rule *rules.Rule, action *rules.Action, event *events.Event) (err error) {
	tracer := traces.GetTracer()

	actionners := GetActionners()
	if actionners == nil {
		return nil
	}

	log := utils.LogLine{
		Message:   "action",
		Rule:      rule.GetName(),
		Event:     event.Output,
		Action:    action.GetName(),
		Actionner: action.GetActionner(),
		TraceID:   event.TraceID,
	}

	if rule.DryRun == trueStr {
		log.Output = "no action, dry-run is enabled"
		utils.PrintLog("info", log)
		return err
	}

	actionner := actionners.FindActionner(action.GetActionner())
	if actionner == nil {
		log.Status = utils.FailureStr
		log.Error = fmt.Sprintf("unknown actionner '%v'", action.GetActionner())
		utils.PrintLog("error", log)
		return fmt.Errorf("unknown actionner '%v'", action.GetActionner())
	}

	if checks := actionner.Checks; len(checks) != 0 {
		for _, i := range checks {
			_, span := tracer.Start(mctx, "checks",
				trace.WithAttributes(attribute.String("check.name", runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name())))
			if err = i(event, action); err != nil {
				log.Status = utils.FailureStr
				log.Error = err.Error()
				utils.PrintLog("error", log)
				span.SetStatus(codes.Error, err.Error())
				span.RecordError(err)
				span.End()
				return err
			}
			span.SetStatus(codes.Ok, "all checks passed")
			span.AddEvent("all checks passed")
			span.End()
		}
	}

	var cont bool
	if action.Continue != "" {
		cont, _ = strconv.ParseBool(action.Continue) // can't trigger an error, cause the value is validated before
	} else {
		cont = GetDefaultActionners().FindActionner(action.GetActionner()).MustDefaultContinue()
	}
	var ignoreErr bool
	if action.IgnoreErrors != "" {
		cont, _ = strconv.ParseBool(action.IgnoreErrors) // can't trigger an error, cause the value is validated before
	}

	actx, span := tracer.Start(mctx, "action",
		trace.WithAttributes(attribute.String("action.name", action.GetName())),
		trace.WithAttributes(attribute.String("action.actionner", action.GetActionner())),
		trace.WithAttributes(attribute.String("action.description", action.GetDescription())),
		trace.WithAttributes(attribute.Bool("action.continue", cont)),
		trace.WithAttributes(attribute.Bool("action.ignore_errors", ignoreErr)),
		trace.WithAttributes(attribute.String("actionner.category", action.GetActionnerCategory())),
		trace.WithAttributes(attribute.String("actionner.name", action.GetActionnerName())),
	)
	defer span.End()
	result, data, err := actionner.Action(action, event)
	span.SetAttributes(attribute.String("action.result", result.Status))
	span.SetAttributes(attribute.String("action.output", result.Output))

	log.Status = result.Status
	if len(result.Objects) != 0 {
		log.Objects = result.Objects
		for i, j := range result.Objects {
			span.SetAttributes(attribute.String("object."+strings.ToLower(i), j))
		}
	}
	if result.Error != "" {
		log.Status = utils.FailureStr
		log.Error = result.Error
	}

	if result.Output != "" {
		log.Output = result.Output
	}

	output := action.GetOutput()
	if output == nil && data != nil {
		log.Output = string(data.Bytes)
	}

	metrics.IncreaseCounter(log)

	if err != nil {
		log.Status = utils.FailureStr
		log.Error = err.Error()
		span.SetStatus(codes.Error, err.Error())
		span.RecordError(err)
		utils.PrintLog("error", log)
		go notifiers.Notify(actx, rule, action, event, log)
		return err
	}
	log.Status = utils.SuccessStr
	span.AddEvent(result.Output)
	span.SetStatus(codes.Ok, "action successfully completed")

	utils.PrintLog("info", log)
	go notifiers.Notify(actx, rule, action, event, log)

	if actionner.IsOutputRequired() {
		octx, span := tracer.Start(actx, "output")

		log = utils.LogLine{
			Message: "output",
			Action:  action.GetName(),
			TraceID: event.TraceID,
		}

		if output == nil {
			err = fmt.Errorf("an output is required")
			log.Status = utils.FailureStr
			log.Error = err.Error()
			log.OutputTarget = "n/a"
			utils.PrintLog("error", log)
			metrics.IncreaseCounter(log)
			span.SetStatus(codes.Error, err.Error())
			span.RecordError(err)
			go notifiers.Notify(octx, rule, action, event, log)
			span.End()
			return err
		}

		if data == nil || len(data.Bytes) == 0 {
			err = fmt.Errorf("empty output")
			log.Status = utils.FailureStr
			log.Error = err.Error()
			utils.PrintLog("error", log)
			metrics.IncreaseCounter(log)
			span.SetStatus(codes.Error, err.Error())
			span.RecordError(err)
			go notifiers.Notify(octx, rule, action, event, log)
			span.End()
			return err
		}

		target := output.GetTarget()
		o := outputs.GetDefaultOutputs().FindOutput(target)
		if o == nil {
			err = fmt.Errorf("unknown output target '%v'", target)
			log.Status = utils.FailureStr
			log.OutputTarget = target
			log.Error = err.Error()
			utils.PrintLog("error", log)
			metrics.IncreaseCounter(log)
			span.SetAttributes(attribute.String("output.target", target))
			span.SetStatus(codes.Error, err.Error())
			span.RecordError(err)
			go notifiers.Notify(octx, rule, action, event, log)
			span.End()
			return err
		}

		log.OutputCategory = o.GetCategory()
		log.OutputTarget = target

		span.SetAttributes(attribute.String("output.name", o.GetName()))
		span.SetAttributes(attribute.String("output.category", o.GetCategory()))
		span.SetAttributes(attribute.String("output.target", target))

		if checks := o.Checks; len(checks) != 0 {
			for _, i := range checks {
				if err2 := i(output, event); err2 != nil {
					log.Status = utils.FailureStr
					log.Error = err2.Error()
					utils.PrintLog("error", log)
					metrics.IncreaseCounter(log)
					span.SetStatus(codes.Error, err2.Error())
					span.RecordError(err2)
					go notifiers.Notify(octx, rule, action, event, log)
					span.End()
					return err
				}
			}
		}

		result, err = o.Output(output, data)
		log.Status = result.Status
		log.Objects = result.Objects
		if result.Output != "" {
			log.Output = result.Output
		}
		if result.Error != "" {
			log.Error = result.Error
		}

		span.SetAttributes(attribute.String("output.status", result.Status))
		span.SetAttributes(attribute.String("output.message", result.Output))

		metrics.IncreaseCounter(log)

		if err != nil {
			log.Error = err.Error()
			utils.PrintLog("error", log)
			span.SetStatus(codes.Error, err.Error())
			span.RecordError(err)
			go notifiers.Notify(octx, rule, action, event, log)
			span.End()
			return err
		}
		span.SetStatus(codes.Ok, "output successfully completed")
		span.AddEvent(result.Output)

		utils.PrintLog("info", log)
		go notifiers.Notify(octx, rule, action, event, log)
		span.End()
		return nil
	}

	if actionner.IsOutputAllowed() && output != nil && data != nil {
		octx, span := tracer.Start(actx, "output")

		log = utils.LogLine{
			Message: "output",
			Rule:    rule.GetName(),
			Action:  action.GetName(),
			TraceID: event.TraceID,
		}

		target := output.GetTarget()
		o := outputs.GetOutputs().FindOutput(target)
		if o == nil {
			err = fmt.Errorf("unknown target '%v'", target)
			log.OutputTarget = target
			log.Status = utils.FailureStr
			log.Error = err.Error()
			utils.PrintLog("error", log)
			span.SetAttributes(attribute.String("output.target", target))
			span.SetStatus(codes.Error, err.Error())
			span.RecordError(err)
			go notifiers.Notify(octx, rule, action, event, log)
			span.End()
			return err
		}

		log.OutputTarget = target
		log.OutputCategory = o.GetCategory()

		span.SetAttributes(attribute.String("output.name", o.GetName()))
		span.SetAttributes(attribute.String("output.category", o.GetCategory()))
		span.SetAttributes(attribute.String("output.target", target))

		if len(data.Bytes) == 0 {
			err = fmt.Errorf("empty output")
			log.Status = utils.FailureStr
			log.Error = err.Error()
			utils.PrintLog("error", log)
			metrics.IncreaseCounter(log)
			span.SetStatus(codes.Error, err.Error())
			span.RecordError(err)
			go notifiers.Notify(octx, rule, action, event, log)
			span.End()
			return err
		}

		result, err = o.Output(output, data)
		log.Status = result.Status
		log.Objects = result.Objects
		if result.Output != "" {
			log.Output = result.Output
		}
		if result.Error != "" {
			log.Error = result.Error
		}

		span.SetAttributes(attribute.String("output.status", result.Status))
		span.SetAttributes(attribute.String("output.message", result.Output))

		metrics.IncreaseCounter(log)

		if err != nil {
			log.Error = err.Error()
			utils.PrintLog("error", log)
			span.SetStatus(codes.Error, err.Error())
			span.RecordError(err)
			go notifiers.Notify(octx, rule, action, event, log)
			span.End()
			return err
		}
		span.SetStatus(codes.Ok, "output successfully completed")
		span.AddEvent(result.Output)

		utils.PrintLog("info", log)
		go notifiers.Notify(octx, rule, action, event, log)
		span.End()
		return nil
	}

	return nil
}

func StartConsumer(eventsC <-chan nats.MessageWithContext) {
	config := configuration.GetConfiguration()
	for {
		m := <-eventsC
		e := m.Data
		ectx := m.Ctx
		var event *events.Event
		err := json.Unmarshal(e, &event)
		if err != nil {
			continue
		}
		if event == nil {
			continue
		}

		log := utils.LogLine{
			Message:  "event",
			Event:    event.Rule,
			Priority: event.Priority,
			Output:   event.Output,
			Source:   event.Source,
			TraceID:  event.TraceID,
		}

		enabledRules := rules.GetRules()
		triggeredRules := make([]*rules.Rule, 0)
		for _, i := range *enabledRules {
			if i.CompareRule(event) {
				triggeredRules = append(triggeredRules, i)
			}
		}

		if len(triggeredRules) == 0 {
			continue
		}

		if !config.PrintAllEvents {
			utils.PrintLog("info", log)
		}

		for _, i := range triggeredRules {
			log.Message = "match"
			log.Rule = i.GetName()

			tracer := traces.GetTracer()
			mctx, span := tracer.Start(ectx, "match",
				trace.WithAttributes(attribute.String("event.rule", event.Rule)),
				trace.WithAttributes(attribute.String("event.output", event.Output)),
				trace.WithAttributes(attribute.String("event.source", event.Source)),
				trace.WithAttributes(attribute.String("event.source", event.TraceID)),
				trace.WithAttributes(attribute.String("rule.name", i.GetName())),
				trace.WithAttributes(attribute.String("rule.description", i.GetDescription())),
			)
			span.AddEvent(event.Output, trace.EventOption(trace.WithTimestamp(event.Time)))
			span.SetStatus(codes.Ok, "match detected")
			span.End()

			utils.PrintLog("info", log)
			metrics.IncreaseCounter(log)

			for _, a := range i.GetActions() {
				e := new(events.Event)
				*e = *event
				i.AddFalcoTalonContext(e, a)
				if GetDefaultActionners().FindActionner(a.GetActionner()).AllowAdditionalContext() &&
					len(a.GetAdditionalContexts()) != 0 {
					for _, j := range a.GetAdditionalContexts() {
						elements, err := talonContext.GetContext(mctx, j, e)
						if err != nil {
							log := utils.LogLine{
								Message:   "context",
								Context:   j,
								Rule:      e.Rule,
								Action:    a.GetName(),
								Actionner: a.GetActionner(),
								TraceID:   e.TraceID,
								Error:     err.Error(),
							}
							utils.PrintLog("error", log)
							if a.IgnoreErrors != trueStr {
								break
							}
						} else {
							e.AddContext(elements)
						}
					}
				}
				err := runAction(mctx, i, a, e)
				if err != nil && a.IgnoreErrors != trueStr {
					break
				}
				if a.Continue == falseStr || a.Continue != trueStr && !GetDefaultActionners().FindActionner(a.GetActionner()).MustDefaultContinue() {
					break
				}
			}

			if i.Continue == falseStr {
				break
			}
		}
	}
}
