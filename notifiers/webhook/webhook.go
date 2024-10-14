package webhook

import (
	"errors"

	"github.com/falcosecurity/falco-talon/internal/models"
	"github.com/falcosecurity/falco-talon/notifiers/http"
	"github.com/falcosecurity/falco-talon/utils"
)

const (
	Name        string = "webhook"
	Description string = "Send a message to an HTTP endpoint"
	Permissions string = ""
	Example     string = `notifiers:
  webhook:
    url: "http://xxxxx"
    http_method: "POST"
    user_agent: "Falco-Talon"
    content_type: "application/json; charset=utf-8"
    custom_headers:
      Authorization: "Bearer xxxxx"
`
)

type Parameters struct {
	CustomHeaders map[string]string `field:"custom_headers"`
	URL           string            `field:"url"`
	HTTPMethod    string            `field:"http_method" default:"POST"`
	ContentType   string            `field:"content_type" default:"application/json; charset=utf-8"`
	UserAgent     string            `field:"user_agent" default:"falco-talon"`
}

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
	return Parameters{
		HTTPMethod:  "POST",
		ContentType: "application/json; charset=utf-8",
		UserAgent:   "falco-talon",
	}
}

func (n Notifier) Run(log utils.LogLine) error {
	client := http.NewClient(
		parameters.HTTPMethod,
		parameters.ContentType,
		parameters.UserAgent,
		parameters.CustomHeaders,
	)

	err := client.Request(parameters.URL, log)
	if err != nil {
		return err
	}
	return nil
}

func checkParameters(parameters *Parameters) error {
	if parameters.URL == "" {
		return errors.New("wrong `url` setting")
	}

	if err := http.CheckURL(parameters.URL); err != nil {
		return err
	}

	if err := utils.ValidateStruct(parameters); err != nil {
		return err
	}

	return nil
}
