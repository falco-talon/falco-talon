package label

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/falcosecurity/falco-talon/internal/events"
	k8sChecks "github.com/falcosecurity/falco-talon/internal/kubernetes/checks"
	k8s "github.com/falcosecurity/falco-talon/internal/kubernetes/client"
	"github.com/falcosecurity/falco-talon/internal/models"
	"github.com/falcosecurity/falco-talon/internal/rules"
	"github.com/falcosecurity/falco-talon/utils"
)

const (
	Name          string = "label"
	Category      string = "kubernetes"
	Description   string = "Add, modify or delete the labels of the pod"
	Source        string = "syscalls"
	Continue      bool   = true
	UseContext    bool   = false
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
  - update
  - patch
  - list
`
	Example string = `- action: Label the pod
  actionner: kubernetes:label
  parameters:
    level: pod
    labels:
      suspicious: true
`
)

var (
	RequiredOutputFields = []string{"k8s.ns.name", "k8s.pod.name"}
)

type patch struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value string `json:"value,omitempty"`
}

type Parameters struct {
	Labels map[string]string `mapstructure:"labels" validate:"required"`
	Level  string            `mapstructure:"level" validate:"omitempty"`
}

const (
	metadataLabels = "/metadata/labels/"
	podStr         = "pod"
	nodeStr        = "node"
)

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
		Labels: map[string]string{},
		Level:  "pod",
	}
}

func (a Actionner) Checks(event *events.Event, _ *rules.Action) error {
	return k8sChecks.CheckPodExist(event)
}

func (a Actionner) Run(event *events.Event, action *rules.Action) (utils.LogLine, *models.Data, error) {
	podName := event.GetPodName()
	namespace := event.GetNamespaceName()

	objects := map[string]string{}

	payload := make([]patch, 0)

	var parameters Parameters
	err := utils.DecodeParams(action.GetParameters(), &parameters)
	if err != nil {
		return utils.LogLine{
			Objects: nil,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	client := k8s.GetClient()

	var kind string
	var node *corev1.Node

	if parameters.Level == nodeStr {
		kind = nodeStr
		pod, err2 := client.GetPod(podName, namespace)
		if err2 != nil {
			return utils.LogLine{
				Objects: objects,
				Error:   err2.Error(),
				Status:  utils.FailureStr,
			}, nil, err2
		}
		node, err = client.GetNodeFromPod(pod)
		if err != nil {
			return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  utils.FailureStr,
			}, nil, err
		}
		objects[nodeStr] = node.Name
	} else {
		kind = podStr
		objects[podStr] = podName
		objects["namespace"] = namespace
	}

	for i, j := range parameters.Labels {
		if fmt.Sprintf("%v", j) == "" {
			continue
		}
		payload = append(payload, patch{
			Op:    "replace",
			Path:  metadataLabels + strings.ReplaceAll(i, "/", "~1"),
			Value: fmt.Sprintf("%v", j),
		})
	}

	payloadBytes, _ := json.Marshal(payload)
	if kind == podStr {
		_, err = client.Clientset.CoreV1().Pods(namespace).Patch(context.Background(), podName, types.JSONPatchType, payloadBytes, metav1.PatchOptions{})
	}
	if kind == nodeStr {
		_, err = client.Clientset.CoreV1().Nodes().Patch(context.Background(), node.Name, types.JSONPatchType, payloadBytes, metav1.PatchOptions{})
	}
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	payload = make([]patch, 0)
	action.GetParameters()
	for i, j := range parameters.Labels {
		if fmt.Sprintf("%v", j) != "" {
			continue
		}
		payload = append(payload, patch{
			Op:   "remove",
			Path: metadataLabels + strings.ReplaceAll(i, "/", "~1"),
		})
	}

	payloadBytes, _ = json.Marshal(payload)
	if kind == nodeStr {
		_, err = client.Clientset.CoreV1().Nodes().Patch(context.Background(), node.Name, types.JSONPatchType, payloadBytes, metav1.PatchOptions{})
	} else {
		_, err = client.Clientset.CoreV1().Pods(namespace).Patch(context.Background(), podName, types.JSONPatchType, payloadBytes, metav1.PatchOptions{})
	}
	if err != nil {
		if err.Error() != "the server rejected our request due to an error in our request" {
			return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  utils.FailureStr,
			}, nil, err
		}
	}
	var output string
	if kind == nodeStr {
		output = fmt.Sprintf("the node '%v' has been labeled", node.Name)
	} else {
		output = fmt.Sprintf("the pod '%v' in the namespace '%v' has been labeled", podName, namespace)
	}
	return utils.LogLine{
		Objects: objects,
		Output:  output,
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

	if len(parameters.Labels) == 0 {
		return errors.New("parameter 'labels' should have at least one label")
	}
	return nil
}
