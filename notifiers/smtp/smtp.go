package smtp

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"time"

	textTemplate "text/template"

	sasl "github.com/emersion/go-sasl"
	gosmtp "github.com/emersion/go-smtp"

	"github.com/falcosecurity/falco-talon/internal/models"
	"github.com/falcosecurity/falco-talon/utils"
)

const (
	Name        string = "smtp"
	Description string = "Send an email with SMTP"
	Permissions string = ""
	Example     string = `notifiers:
  smtp:
    host_port: "localhost:1025"
    from: "falco@falcosecurity.org"
    to: "user@test.com, other@test.com"
    user: "xxxxx"
    password: "xxxxx"
    format: "html"
    tls: false
`
)

const (
	Red   string = "#e20b0b"
	Green string = "#23ba47"
	Grey  string = "#a4a8b1"
	Text  string = "text"

	rfc2822 string = "Mon Jan 02 15:04:05 -0700 2006"
)

type Parameters struct {
	HostPort string `field:"host_port" validate:"required"`
	User     string `field:"user"`
	Password string `field:"password"`
	From     string `field:"from" validate:"required"`
	To       string `field:"to" validate:"required"`
	Format   string `field:"format" default:"html"`
	TLS      bool   `field:"tls" default:"false"`
}

// Payload
type Payload struct {
	From    string
	To      string
	Subject string
	Body    string
	Mime    string
	Date    string
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
		Format: "html",
	}
}

func (n Notifier) Run(log utils.LogLine) error {
	if parameters.HostPort == "" {
		return errors.New("wrong `host_port` setting")
	}

	payload, err := NewPayload(log)
	if err != nil {
		return err
	}
	err = Send(payload)
	if err != nil {
		return err
	}
	return nil
}

func checkParameters(parameters *Parameters) error {
	if parameters.HostPort == "" {
		return errors.New("wrong `host_port` setting")
	}

	if err := utils.ValidateStruct(parameters); err != nil {
		return err
	}

	return nil
}

func NewPayload(log utils.LogLine) (Payload, error) {
	subject := fmt.Sprintf("Subject: [falco-talon][%v][%v] ", log.Status, log.Message)
	if log.OutputTarget != "" {
		subject += fmt.Sprintf("OutputTarget '%v' ", log.OutputTarget)
	}
	if log.Action != "" {
		subject += fmt.Sprintf("Action '%v' ", log.Action)
	}
	if log.Rule != "" {
		subject += fmt.Sprintf("Rule '%v' ", log.Rule)
	}
	subject = strings.TrimSuffix(subject, " ")

	payload := Payload{
		From:    fmt.Sprintf("From: %v", parameters.From),
		To:      fmt.Sprintf("To: %v", parameters.To),
		Subject: subject,
		Mime:    "MIME-version: 1.0;",
		Date:    "Date: " + time.Now().Format(rfc2822),
	}

	if parameters.Format != Text {
		payload.Mime += "\nContent-Type: multipart/alternative; boundary=4t74weu9byeSdJTM\n\n\n--4t74weu9byeSdJTM"
	}

	payload.Mime += "\nContent-Type: text/plain; charset=\"UTF-8\";\n\n"

	var err error

	ttmpl := textTemplate.New(Text)
	ttmpl, err = ttmpl.Parse(plaintextTmpl)
	if err != nil {
		return Payload{}, err
	}
	var outtext bytes.Buffer
	err = ttmpl.Execute(&outtext, log)
	if err != nil {
		return Payload{}, err
	}

	if parameters.Format == Text {
		return payload, nil
	}

	htmpl := textTemplate.New("html")
	htmpl, err = htmpl.Parse(htmlTmpl)
	if err != nil {
		return Payload{}, err
	}
	var outhtml bytes.Buffer
	log.Output = strings.ReplaceAll(utils.RemoveSpecialCharacters(log.Output), "\n", "<br>")
	err = htmpl.Execute(&outhtml, log)
	if err != nil {
		return Payload{}, err
	}

	payload.Body = fmt.Sprintf("%v\n%v\n%v\n%v\n%v\n%v\n\n%v",
		payload.From,
		payload.To,
		payload.Date,
		payload.Mime,
		outtext.String(),
		"--4t74weu9byeSdJTM\nContent-Type: text/html; charset=\"UTF-8\";",
		outhtml.String(),
	)

	return payload, nil
}

func Send(payload Payload) error {
	to := strings.Split(strings.ReplaceAll(parameters.To, " ", ""), ",")
	auth := sasl.NewPlainClient("", parameters.User, parameters.Password)

	var smtpClient *gosmtp.Client
	var err error
	if parameters.TLS {
		tlsCfg := &tls.Config{
			ServerName: strings.Split(parameters.HostPort, ":")[0],
			MinVersion: tls.VersionTLS12,
		}
		smtpClient, err = gosmtp.DialStartTLS(parameters.HostPort, tlsCfg)
	} else {
		smtpClient, err = gosmtp.Dial(parameters.HostPort)
	}
	if err != nil {
		return err
	}

	err = smtpClient.Auth(auth)
	if err != nil {
		return err
	}
	err = smtpClient.SendMail(parameters.From, to, strings.NewReader(payload.Body))
	if err != nil {
		return err
	}
	return nil
}
