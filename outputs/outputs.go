package outputs

import (
	"github.com/falcosecurity/falco-talon/internal/rules"
	awss3 "github.com/falcosecurity/falco-talon/outputs/aws/s3"
	"github.com/falcosecurity/falco-talon/outputs/file"
	"github.com/falcosecurity/falco-talon/outputs/gcs"
	minio "github.com/falcosecurity/falco-talon/outputs/minio"

	"github.com/falcosecurity/falco-talon/internal/models"
	"github.com/falcosecurity/falco-talon/utils"
)

type Output interface {
	Init() error
	Run(output *rules.Output, data *models.Data) (utils.LogLine, error)
	CheckParameters(action *rules.Output) error
	Checks(output *rules.Output) error
	Information() models.Information
	Parameters() models.Parameters
}

type Outputs []Output

var defaultOutputs *Outputs
var enabledOutputs *Outputs

func init() {
	defaultOutputs = new(Outputs)
	defaultOutputs = ListDefaultOutputs()
	enabledOutputs = new(Outputs)
}

func ListDefaultOutputs() *Outputs {
	if len(*defaultOutputs) == 0 {
		defaultOutputs.Add(
			file.Register(),
			minio.Register(),
			awss3.Register(),
			gcs.Register(),
		)
	}

	return defaultOutputs
}

func (outputs *Outputs) Add(output ...Output) {
	for _, i := range output {
		*outputs = append(*outputs, i)
	}
}

func GetOutputs() *Outputs {
	return enabledOutputs
}

func (outputs *Outputs) FindOutput(fullname string) Output {
	if outputs == nil {
		return nil
	}

	for _, i := range *outputs {
		if i == nil {
			continue
		}
		if fullname == i.Information().FullName {
			return i
		}
	}
	return nil
}

func Init() error {
	rules := rules.GetRules()

	categories := map[string]bool{}
	enabledCategories := map[string]bool{}

	// list actionner categories to init
	for _, i := range *rules {
		for _, j := range i.Actions {
			if j.GetOutput() != nil {
				if o := ListDefaultOutputs().FindOutput(j.GetOutput().Target); o != nil {
					categories[o.Information().Category] = true
				}
			}
		}
	}

	for category := range categories {
		for _, output := range *defaultOutputs {
			if category == output.Information().Category {
				if err := output.Init(); err != nil {
					utils.PrintLog("error", utils.LogLine{Message: "init", Error: err.Error(), Category: category, Status: utils.FailureStr})
					return err
				}
				enabledCategories[category] = true
			}
		}
	}

	for i := range enabledCategories {
		for _, j := range *defaultOutputs {
			if i == j.Information().Category {
				enabledOutputs.Add(j)
			}
		}
	}

	return nil
}
