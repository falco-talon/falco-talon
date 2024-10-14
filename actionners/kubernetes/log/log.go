package log

import (
	"bytes"
	"context"
	"fmt"
	"io"

	corev1 "k8s.io/api/core/v1"

	"github.com/falcosecurity/falco-talon/internal/events"
	k8sChecks "github.com/falcosecurity/falco-talon/internal/kubernetes/checks"
	k8s "github.com/falcosecurity/falco-talon/internal/kubernetes/client"
	"github.com/falcosecurity/falco-talon/internal/models"
	"github.com/falcosecurity/falco-talon/internal/rules"
	"github.com/falcosecurity/falco-talon/utils"
)

const (
	Name          string = "log"
	Category      string = "kubernetes"
	Description   string = "Get logs from a pod"
	Source        string = "syscalls"
	Continue      bool   = true
	UseContext    bool   = false
	AllowOutput   bool   = true
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
  - pods/log
  verbs:
  - get
`
	Example string = `- action: Get logs of the pod
  actionner: kubernetes:log
  parameters:
    tail_lines: 200
  output:
    target: aws:s3
    parameters:
      bucket: my-bucket
      prefix: /logs/
`
)

const (
	defaultTailLines int = 20
)

var (
	RequiredOutputFields = []string{"k8s.ns.name", "k8s.pod.name"}
)

type Parameters struct {
	TailLines int `mapstructure:"tail_lines" validate:"gte=0,omitempty"`
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
		TailLines: 20,
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

	tailLines := new(int64)
	*tailLines = int64(defaultTailLines)
	if parameters.TailLines > 0 {
		*tailLines = int64(parameters.TailLines)
	}

	client := k8s.GetClient()

	p, _ := client.GetPod(pod, namespace)
	containers := k8s.GetContainers(p)
	if len(containers) == 0 {
		err := fmt.Errorf("no container found")
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	ctx := context.Background()
	var output []byte

	for i, container := range containers {
		logs, err := client.Clientset.CoreV1().Pods(namespace).GetLogs(pod, &corev1.PodLogOptions{
			Container: container,
			TailLines: tailLines,
		}).Stream(ctx)
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
		defer logs.Close()

		buf := new(bytes.Buffer)
		_, err = io.Copy(buf, logs)
		if err != nil {
			return utils.LogLine{
				Objects: objects,
				Status:  utils.FailureStr,
				Error:   err.Error(),
			}, nil, err
		}

		output = buf.Bytes()
		if len(output) != 0 {
			break
		}
	}

	return utils.LogLine{
		Objects: objects,
		Output:  fmt.Sprintf("the logs for the pod '%v' in the namespace '%v' has been downloaded", pod, namespace),
		Status:  utils.SuccessStr,
	}, &models.Data{Name: "log", Objects: objects, Bytes: output}, nil
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
