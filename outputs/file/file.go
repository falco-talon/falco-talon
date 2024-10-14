package file

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/falcosecurity/falco-talon/internal/models"
	"github.com/falcosecurity/falco-talon/internal/rules"
	"github.com/falcosecurity/falco-talon/utils"
)

const (
	Name        string = "file"
	Category    string = "local"
	Description string = "Store on local file system"
	Permissions string = ``
	Example     string = `- action: Get logs of the pod
  actionner: kubernetes:download
  parameters:
    tail_lines: 200
  output:
    target: local:file
    parameters:
      destination: /var/logs/falco-talon/
`
)

type Parameters struct {
	Destination string `mapstructure:"destination" validate:"required"`
}

type Output struct{}

func Register() *Output {
	return new(Output)
}

func (o Output) Init() error { return nil }

func (o Output) Information() models.Information {
	return models.Information{
		Name:        Name,
		FullName:    Category + ":" + Name,
		Category:    Category,
		Description: Description,
		Permissions: Permissions,
		Example:     Example,
	}
}
func (o Output) Parameters() models.Parameters {
	return Parameters{
		Destination: "",
	}
}

func (o Output) Checks(output *rules.Output) error {
	var parameters Parameters
	err := utils.DecodeParams(output.GetParameters(), &parameters)
	if err != nil {
		return err
	}

	dstFolder := os.ExpandEnv(parameters.Destination)
	if _, err := os.Open(dstFolder); os.IsNotExist(err) {
		return fmt.Errorf("folder '%v' does not exist", dstFolder)
	}

	return nil
}

func (o Output) Run(output *rules.Output, data *models.Data) (utils.LogLine, error) {
	var parameters Parameters
	err := utils.DecodeParams(output.GetParameters(), &parameters)
	if err != nil {
		return utils.LogLine{
			Objects: nil,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, err
	}

	var key string
	switch {
	case data.Objects["namespace"] != "" && data.Objects["pod"] != "":
		key = fmt.Sprintf("%v_%v_%v_%v", time.Now().Format("2006-01-02T15-04-05Z"), data.Objects["namespace"], data.Objects["pod"], strings.ReplaceAll(data.Name, "/", "_"))
	case data.Objects["hostname"] != "":
		key = fmt.Sprintf("%v_%v_%v", time.Now().Format("2006-01-02T15-04-05Z"), data.Objects["hostname"], strings.ReplaceAll(data.Name, "/", "_"))
	default:
		var s string
		for i, j := range data.Objects {
			if i != "file" {
				s += j + "_"
			}
		}
		key = fmt.Sprintf("%v_%v%v", time.Now().Format("2006-01-02T15-04-05Z"), s, strings.ReplaceAll(data.Name, "/", "_"))
	}

	dstfile := fmt.Sprintf("%v/%v", strings.TrimSuffix(parameters.Destination, "/"), key)

	objects := map[string]string{
		"file":        data.Name,
		"destination": dstfile,
	}

	if err := os.WriteFile(dstfile, data.Bytes, 0600); err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, err
	}

	return utils.LogLine{
		Objects: objects,
		Output:  fmt.Sprintf("the file '%v' has been copied to '%v'", filepath.Base(data.Name), dstfile),
		Status:  utils.SuccessStr,
	}, nil
}

func (o Output) CheckParameters(output *rules.Output) error {
	var parameters Parameters
	err := utils.DecodeParams(output.GetParameters(), &parameters)
	if err != nil {
		return err
	}

	err = utils.ValidateStruct(parameters)
	if err != nil {
		return err
	}

	return nil
}
