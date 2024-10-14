package slack

import (
	"errors"
	"fmt"
	"strings"

	"github.com/falcosecurity/falco-talon/internal/models"
	"github.com/falcosecurity/falco-talon/notifiers/http"
	"github.com/falcosecurity/falco-talon/utils"
)

const (
	Name        string = "slack"
	Description string = "Send a message to Slack"
	Permissions string = ""
	Example     string = `notifiers:
  slack:
    webhook_url: "https://hooks.slack.com/services/XXXX"
    icon: "https://upload.wikimedia.org/wikipedia/commons/2/26/Circaetus_gallicus_claw.jpg"
    username: "Falco Talon"
    footer: "https://github.com/falcosecurity/falco-talon"
    format: long
`
)

const (
	Red            string = "#e20b0b"
	Green          string = "#23ba47"
	Grey           string = "#a4a8b1"
	threeBackticks        = "```"
	ignoredStr     string = "ignored"
)

type Parameters struct {
	WebhookURL string `field:"webhook_url" validate:"required"`
	Icon       string `field:"icon" default:"https://upload.wikimedia.org/wikipedia/commons/2/26/Circaetus_gallicus_claw.jpg"`
	Username   string `field:"username" default:"Falco Talon"`
	Footer     string `field:"footer" default:"http://github.com/falcosecurity/falco-talon"`
	Format     string `field:"format" default:"long"`
}

type Field struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

type Attachment struct {
	Fallback   string  `json:"fallback"`
	Color      string  `json:"color"`
	Text       string  `json:"text,omitempty"`
	Footer     string  `json:"footer,omitempty"`
	FooterIcon string  `json:"footer_icon,omitempty"`
	Fields     []Field `json:"fields"`
}

// Payload
type Payload struct {
	Text        string       `json:"text,omitempty"`
	Username    string       `json:"username,omitempty"`
	IconURL     string       `json:"icon_url,omitempty"`
	Attachments []Attachment `json:"attachments,omitempty"`
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
		Icon:     "https://upload.wikimedia.org/wikipedia/commons/2/26/Circaetus_gallicus_claw.jpg",
		Username: "Falco Talon",
		Footer:   "http://github.com/falcosecurity/falco-talon",
		Format:   "long",
	}
}

func (n Notifier) Run(log utils.LogLine) error {
	client := http.DefaultClient()

	err := client.Request(parameters.WebhookURL, newPayload(log))
	if err != nil {
		return err
	}
	return nil
}

func checkParameters(parameters *Parameters) error {
	if parameters.WebhookURL == "" {
		return errors.New("wrong `webhook_url` setting")
	}

	if err := http.CheckURL(parameters.WebhookURL); err != nil {
		return err
	}

	if err := utils.ValidateStruct(parameters); err != nil {
		return err
	}

	return nil
}

func newPayload(log utils.LogLine) Payload {
	var attachments []Attachment
	var attachment Attachment

	var color string
	switch log.Status {
	case utils.FailureStr:
		color = Red
	case utils.SuccessStr:
		color = Green
	case ignoredStr:
		color = Grey
	}
	attachment.Color = color

	text := fmt.Sprintf("[*%v*][*%v*] ", strings.ToUpper(log.Status), strings.ToUpper(log.Message))
	if log.Rule != "" {
		text += fmt.Sprintf("Rule: `%v` ", log.Rule)
	}
	if log.Action != "" {
		text += fmt.Sprintf("Action: `%v` ", log.Action)
	}
	if log.OutputTarget != "" {
		text += fmt.Sprintf("OutputTarget: `%v` ", log.OutputTarget)
	}

	text = strings.TrimSuffix(text, " ")

	if parameters.Format == "short" {
		attachment.Text = text
		text = ""
	} else {
		var fields []Field
		var field Field

		if log.Rule != "" {
			field.Title = "Rule"
			field.Value = "`" + log.Rule + "`"
			field.Short = false
			fields = append(fields, field)
		}
		if log.Action != "" {
			field.Title = "Action"
			field.Value = "`" + log.Action + "`"
			field.Short = false
			fields = append(fields, field)
		}
		if log.Actionner != "" {
			field.Title = "Actionner"
			field.Value = "`" + log.Actionner + "`"
			field.Short = true
			fields = append(fields, field)
		}
		field.Title = "Status"
		field.Value = "`" + log.Status + "`"
		field.Short = true
		fields = append(fields, field)
		if len(log.Objects) > 0 {
			for i, j := range log.Objects {
				field.Title = i
				field.Value = "`" + j + "`"
				field.Short = true
				fields = append(fields, field)
			}
		}
		if log.Event != "" {
			field.Title = "Event"
			field.Value = threeBackticks + log.Event + threeBackticks
			field.Short = false
			fields = append(fields, field)
		}
		field.Title = "Message"
		field.Value = "`" + log.Message + "`"
		field.Short = false
		fields = append(fields, field)
		if log.Error != "" {
			field.Title = "Error"
			field.Value = "`" + log.Error + "`"
			field.Short = false
			fields = append(fields, field)
		}
		if log.OutputTarget != "" {
			field.Title = "OutputTarget"
			field.Value = "`" + log.OutputTarget + "`"
			field.Short = false
			fields = append(fields, field)
		}
		if log.TraceID != "" {
			field.Title = "Trace ID"
			field.Value = "`" + log.TraceID + "`"
			field.Short = false
			fields = append(fields, field)
		}
		if log.Result != "" {
			field.Title = "Result"
			field.Value = "`" + log.Result + "`"
			field.Short = false
			fields = append(fields, field)
		}
		if log.Output != "" {
			field.Title = "Output"
			field.Value = fmt.Sprintf("```\n%v```", utils.RemoveSpecialCharacters(log.Output))
			field.Short = false
			fields = append(fields, field)
		}

		if parameters.Footer != "" {
			attachment.Footer = parameters.Footer
		}

		attachment.Fallback = ""
		attachment.Fields = fields
	}

	attachments = append(attachments, attachment)

	s := Payload{
		Text:        text,
		Username:    parameters.Username,
		IconURL:     parameters.Icon,
		Attachments: attachments,
	}

	return s
}
