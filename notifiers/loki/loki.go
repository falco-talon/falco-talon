package loki

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/falcosecurity/falco-talon/internal/models"
	"github.com/falcosecurity/falco-talon/notifiers/http"
	"github.com/falcosecurity/falco-talon/utils"
)

const (
	Name        string = "loki"
	Description string = "Send a log to Loki over HTTP"
	Permissions string = ""
	Example     string = `notifiers:
  loki:
    host_port: "https://lolcalhost:3100"
    user: "xxxxx"
    api_key: "xxxxx"
`
)

type Parameters struct {
	CustomHeaders map[string]string `field:"custom_headers"`
	URL           string            `field:"url" validate:"required"`
	User          string            `field:"user"`
	APIKey        string            `field:"api_key"`
	Tenant        string            `field:"tenant"`
}

type Payload struct {
	Streams []Stream `json:"streams"`
}

type Stream struct {
	Stream map[string]string `json:"stream"`
	Values []Value           `json:"values"`
}

type Value []string

const contentType = "application/json"

var parameters *Parameters

type Notifier struct{}

func Register() *Notifier {
	return new(Notifier)
}

func (n Notifier) Init(fields map[string]any) error {
	parameters = new(Parameters)
	parameters = utils.SetFields(parameters, fields).(*Parameters)
	if err := checkParameters(parameters); err != nil {
		return err
	}
	return nil
}

func (n Notifier) Information() models.Information {
	return models.Information{
		Name:        Name,
		Description: Description,
		Permissions: Permissions,
		Example:     Example,
	}
}
func (n Notifier) Parameters() models.Parameters {
	return Parameters{}
}

func (n Notifier) Run(log utils.LogLine) error {
	if parameters.URL == "" {
		return errors.New("wrong `host_port` setting")
	}

	if err := http.CheckURL(parameters.URL); err != nil {
		return err
	}

	client := http.NewClient("", contentType, "", parameters.CustomHeaders)

	if parameters.User != "" && parameters.APIKey != "" {
		client.SetBasicAuth(parameters.User, parameters.APIKey)
	}

	if parameters.Tenant != "" {
		client.SetHeader("X-Scope-OrgID", parameters.Tenant)
	}

	err := client.Request(parameters.URL+"/loki/api/v1/push", NewPayload(log))
	if err != nil {
		return err
	}
	return nil
}

func checkParameters(parameters *Parameters) error {
	if parameters.URL == "" {
		return errors.New("wrong `host_port` setting")
	}

	if err := utils.ValidateStruct(parameters); err != nil {
		return err
	}

	return nil
}

func NewPayload(log utils.LogLine) Payload {
	s := make(map[string]string)

	s["status"] = log.Status
	if log.Rule != "" {
		s["rule"] = strings.ReplaceAll(strings.ToLower(log.Rule), " ", "_")
	}
	if log.Action != "" {
		s["action"] = strings.ReplaceAll(strings.ToLower(log.Action), " ", "_")
	}
	if log.Actionner != "" {
		s["actionner"] = log.Actionner
	}
	if log.OutputTarget != "" {
		s["outputtarget"] = log.OutputTarget
	}
	s["message"] = log.Message
	s["traceid"] = log.TraceID

	for k, v := range log.Objects {
		s[strings.ToLower(k)] = v
	}

	var t string

	if log.Output != "" {
		t = log.Output
	}
	if log.Result != "" {
		t = log.Result
	}
	if log.Error != "" {
		t = log.Error
	}

	return Payload{Streams: []Stream{
		{
			Stream: s,
			Values: []Value{[]string{
				fmt.Sprintf("%v", time.Now().UnixNano()),
				t,
			}},
		},
	}}
}
