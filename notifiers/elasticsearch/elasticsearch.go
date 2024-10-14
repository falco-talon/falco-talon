package elasticsearch

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/falcosecurity/falco-talon/internal/models"
	"github.com/falcosecurity/falco-talon/notifiers/http"
	"github.com/falcosecurity/falco-talon/utils"
)

const (
	Name        string = "elasticsearch"
	Description string = "Send a log to Elasticsearch"
	Permissions string = ""
	Example     string = `notifiers:
  elasticsearch:
    url: "http://localhost:9200"
    create_index_template: true
    number_of_shards: 1
    number_of_replicas: 1
notifiers:
  slack:
    webhook_url: "https://hooks.slack.com/services/XXXX"
    icon: "https://upload.wikimedia.org/wikipedia/commons/2/26/Circaetus_gallicus_claw.jpg"
    username: "Falco Talon"
    footer: "https://github.com/falcosecurity/falco-talon"
    format: long
`
)

const docType string = "/_doc"
const indexTemplate string = "/_index_template/falco-talon"

type Parameters struct {
	CustomHeaders       map[string]string `field:"custom_headers"`
	URL                 string            `field:"url" validate:"required"`
	User                string            `field:"user"`
	Password            string            `field:"password"`
	Suffix              string            `field:"suffix" default:"daily"`
	Index               string            `field:"index" default:"falco-talon"`
	NumberOfShards      int               `field:"number_of_shards" default:"3"`
	NumberOfReplicas    int               `field:"number_of_replicas" default:"3"`
	CreateIndexTemplate bool              `field:"create_index_template" default:"true"`
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
	if parameters.CreateIndexTemplate {
		client := http.NewClient("GET", "", "", parameters.CustomHeaders)
		if parameters.User != "" && parameters.Password != "" {
			client.SetBasicAuth(parameters.User, parameters.Password)
		}
		if err := client.Request(parameters.URL+indexTemplate, nil); err != nil {
			if err.Error() == "resource not found" {
				client.SetHTTPMethod("PUT")
				m := strings.ReplaceAll(mapping, "${SHARDS}", fmt.Sprintf("%v", parameters.NumberOfShards))
				m = strings.ReplaceAll(m, "${REPLICAS}", fmt.Sprintf("%v", parameters.NumberOfReplicas))
				j := make(map[string]any)
				if err := json.Unmarshal([]byte(m), &j); err != nil {
					return err
				}
				if err := client.Request(parameters.URL+indexTemplate, j); err != nil {
					return err
				}
			}
		}
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
		Suffix:              "daily",
		Index:               "falco-talon",
		NumberOfShards:      3,
		NumberOfReplicas:    3,
		CreateIndexTemplate: true,
	}
}

func (n Notifier) Run(log utils.LogLine) error {
	client := http.DefaultClient()

	current := time.Now()
	var u string
	switch parameters.Suffix {
	case "none":
		u = parameters.URL + "/" + parameters.Index + docType
	case "monthly":
		u = parameters.URL + "/" + parameters.Index + "-" + current.Format("2006.01") + docType
	case "annually":
		u = parameters.URL + "/" + parameters.Index + "-" + current.Format("2006") + docType
	default:
		u = parameters.URL + "/" + parameters.Index + "-" + current.Format("2006.01.02") + docType
	}

	log.Time = time.Now().Format(time.RFC3339)

	if err := client.Request(u, log); err != nil {
		return err
	}

	return nil
}

func checkParameters(parameters *Parameters) error {
	if parameters.URL == "" {
		return errors.New("wrong `url` setting")
	}
	if parameters.NumberOfShards < 1 {
		return errors.New("wrong `number_of_shards` setting")
	}
	if parameters.NumberOfReplicas < 1 {
		return errors.New("wrong `number_of_replcicas` setting")
	}

	if err := http.CheckURL(parameters.URL); err != nil {
		return err
	}

	if err := utils.ValidateStruct(parameters); err != nil {
		return err
	}

	return nil
}
