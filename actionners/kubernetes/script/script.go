package script

import (
	"bytes"
	"errors"
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
	Name          string = "script"
	Category      string = "kubernetes"
	Description   string = "Run a script in a pod"
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
	Example string = `- action: Run a script into the pod
  actionner: kubernetes:script
  parameters:
    shell: /bin/bash
    script: |
      ps awxuf
      netstat -lpauten
      top -n 1
      cat ${FD_NAME}      
`
)

var (
	RequiredOutputFields = []string{"k8s.ns.name", "k8s.pod.name"}
)

type Parameters struct {
	Script string `mapstructure:"script" validate:"omitempty"`
	File   string `mapstructure:"file" validate:"omitempty"`
	Shell  string `mapstructure:"shell" validate:"omitempty"`
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
		Script: "",
		File:   "",
		Shell:  "/bin/sh",
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

	script := new(string)
	if parameters.Script != "" {
		*script = parameters.Script
	}

	if parameters.File != "" {
		fileContent, err2 := os.ReadFile(parameters.File)
		if err2 != nil {
			return utils.LogLine{
					Objects: objects,
					Error:   err2.Error(),
					Status:  utils.FailureStr,
				},
				nil,
				err2
		}
		*script = string(fileContent)
	}

	event.ExportEnvVars()
	*script = os.ExpandEnv(*script)

	client := k8s.GetClient()

	p, _ := client.GetPod(pod, namespace)
	containers := k8s.GetContainers(p)
	if len(containers) == 0 {
		err = fmt.Errorf("no container found")
		return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  utils.FailureStr,
			},
			nil,
			err
	}

	// copy the script to /tmp of the pod
	var container string
	output := new(bytes.Buffer)
	for i, j := range containers {
		container = j
		command := []string{"tee", "/tmp/talon-script.sh", ">", "/dev/null"}
		_, err = client.Exec(namespace, pod, container, command, *script)
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

	// run the script
	command := []string{*shell, "/tmp/talon-script.sh"}
	output, err = client.Exec(namespace, pod, container, command, "")
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	return utils.LogLine{
			Objects: objects,
			Output:  utils.RemoveAnsiCharacters(output.String()),
			Status:  utils.SuccessStr,
		},
		nil,
		nil
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

	err = validateParameters(parameters)
	if err != nil {
		return err
	}
	return nil
}

func validateParameters(parameters Parameters) error {
	if parameters.Script == "" && parameters.File == "" {
		return errors.New("missing parameter 'script' or 'file'")
	}
	if parameters.Script != "" && parameters.File != "" {
		return errors.New("'script' and 'file' parameters can't be set at the same time")
	}
	if parameters.File != "" {
		_, err := os.Stat(parameters.File)
		if os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
