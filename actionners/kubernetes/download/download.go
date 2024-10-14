package copy

import (
	"bytes"
	"fmt"
	"os"

	"github.com/falcosecurity/falco-talon/internal/events"
	k8sChecks "github.com/falcosecurity/falco-talon/internal/kubernetes/checks"
	k8s "github.com/falcosecurity/falco-talon/internal/kubernetes/client"
	"github.com/falcosecurity/falco-talon/internal/models"
	"github.com/falcosecurity/falco-talon/internal/rules"
	"github.com/falcosecurity/falco-talon/utils"
)

const (
	Name          string = "download"
	Category      string = "kubernetes"
	Description   string = "Download a file from a pod"
	Source        string = "syscalls"
	Continue      bool   = true
	UseContext    bool   = false
	AllowOutput   bool   = false
	RequireOutput bool   = true
	Permissions   string = `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: falco-talon
rules:
- apiGroups:
  - ""
  resources:
  - pods
  verbs:
  - get
  - list
- apiGroups:
  - ""
  resources:
  - pods/exec
  verbs:
  - get
  - create
`
	Example string = `- action: Get logs of the pod
  actionner: kubernetes:download
  parameters:
    tail_lines: 200
  output:
    target: aws:s3
    parameters:
      bucket: my-bucket
      prefix: /files/
`
)

var (
	RequiredOutputFields = []string{"k8s.ns.name", "k8s.pod.name"}
)

type Parameters struct {
	File string `mapstructure:"file" validate:"required"`
}

type Actionner struct{}

func Register() *Actionner {
	return new(Actionner)
}

func (a Actionner) Init() error {
	return k8s.Init()
}

func (a Actionner) Information() models.Information {
	return models.Information{
		Name:                 Name,
		FullName:             Category + ":" + Name,
		Category:             Category,
		Description:          Description,
		Source:               Source,
		RequiredOutputFields: RequiredOutputFields,
		Permissions:          Permissions,
		Example:              Example,
		Continue:             Continue,
		AllowOutput:          AllowOutput,
		RequireOutput:        RequireOutput,
	}
}
func (a Actionner) Parameters() models.Parameters {
	return Parameters{
		File: "",
	}
}

func (a Actionner) Checks(event *events.Event, _ *rules.Action) error {
	return k8sChecks.CheckPodExist(event)
}

func (a Actionner) Run(event *events.Event, action *rules.Action) (utils.LogLine, *models.Data, error) {
	pod := event.GetPodName()
	namespace := event.GetNamespaceName()

	objects := map[string]string{
		"pod":       pod,
		"namespace": namespace,
	}

	var parameters Parameters
	err := utils.DecodeParams(action.GetParameters(), &parameters)
	if err != nil {
		return utils.LogLine{
			Objects: nil,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	file := new(string)
	*file = parameters.File

	event.ExportEnvVars()
	*file = os.ExpandEnv(*file)

	objects["file"] = *file

	client := k8s.GetClient()

	p, _ := client.GetPod(pod, namespace)
	containers := k8s.GetContainers(p)
	if len(containers) == 0 {
		err = fmt.Errorf("no container found")
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	output := new(bytes.Buffer)
	for i, container := range containers {
		command := []string{"cat", *file}
		output, err = client.Exec(namespace, pod, container, command, "")
		if err != nil {
			if i == len(containers)-1 {
				return utils.LogLine{
					Objects: objects,
					Error:   err.Error(),
					Status:  utils.FailureStr,
				}, nil, err
			}
			continue
		}
		break
	}

	return utils.LogLine{
		Objects: objects,
		Output:  fmt.Sprintf("the file '%v' has been downloaded", *file),
		Status:  utils.SuccessStr,
	}, &models.Data{Name: *file, Objects: objects, Bytes: output.Bytes()}, nil
}

func (a Actionner) CheckParameters(action *rules.Action) error {
	var parameters Parameters

	err := utils.DecodeParams(action.GetParameters(), &parameters)
	if err != nil {
		return err
	}

	err = utils.ValidateStruct(parameters)
	if err != nil {
		return err
	}

	return nil
}
