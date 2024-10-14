package exec

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
	Name          string = "exec"
	Category      string = "kubernetes"
	Description   string = "Exec a command in a pod"
	Source        string = "syscalls"
	Continue      bool   = true
	UseContext    bool   = true
	AllowOutput   bool   = false
	RequireOutput bool   = false
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
	Example string = `- action: Exec a command into the pod
  actionner: kubernetes:exec
  parameters:
    shell: /bin/bash
    command: "cat ${FD_NAME}"
`
)

var (
	RequiredOutputFields = []string{"k8s.ns.name", "k8s.pod.name"}
)

type Parameters struct {
	Command string `mapstructure:"command" validate:"required"`
	Shell   string `mapstructure:"shell" validate:"omitempty"`
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
		Command: "",
		Shell:   "/bin/sh",
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

	shell := new(string)
	if parameters.Shell != "" {
		*shell = parameters.Shell
	} else {
		*shell = "/bin/sh"
	}

	command := new(string)
	*command = parameters.Command

	event.ExportEnvVars()
	*command = os.ExpandEnv(*command)

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
		command := []string{*shell, "-c", *command}
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
	}

	return utils.LogLine{
		Objects: objects,
		Output:  utils.RemoveAnsiCharacters(output.String()),
		Status:  utils.SuccessStr,
	}, nil, nil
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
