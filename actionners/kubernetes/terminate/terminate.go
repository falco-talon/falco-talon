package terminate

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	helpers "github.com/falco-talon/falco-talon/actionners/kubernetes/helpers"
	"github.com/falco-talon/falco-talon/internal/events"
	k8sChecks "github.com/falco-talon/falco-talon/internal/kubernetes/checks"
	k8s "github.com/falco-talon/falco-talon/internal/kubernetes/client"
	"github.com/falco-talon/falco-talon/internal/models"
	"github.com/falco-talon/falco-talon/internal/rules"
	"github.com/falco-talon/falco-talon/utils"
)

const (
	Name          string = "terminate"
	Category      string = "kubernetes"
	Description   string = "Terminate a pod"
	Source        string = "syscalls"
	Continue      bool   = false
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
  - delete
  - list
- apiGroups:
  - apps
  resources:
  - replicasets
  verbs:
  - get
`
	Example string = `- action: Terminate the pod
  actionner: kubernetes:terminate
  parameters:
    grace_period_seconds: 5
    ignore_daemonsets: true
    ignore_statefulsets: true
	ignore_standalone_pods: true
    min_healthy_replicas: 33%
`
)

var (
	RequiredOutputFields = []string{"k8s.ns.name", "k8s.pod.name"}
)

type Parameters struct {
	MinHealthyReplicas   string `mapstructure:"min_healthy_replicas" validate:"omitempty,is_absolut_or_percent"`
	IgnoreDaemonsets     bool   `mapstructure:"ignore_daemonsets" validate:"omitempty"`
	IgnoreStatefulSets   bool   `mapstructure:"ignore_statefulsets" validate:"omitempty"`
	IgnoreStandalonePods bool   `mapstructure:"ignore_standalone_pods" validate:"omitempty"`
	GracePeriodSeconds   int    `mapstructure:"grace_period_seconds" validate:"omitempty"`
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
		MinHealthyReplicas:   "",
		IgnoreDaemonsets:     false,
		IgnoreStatefulSets:   false,
		IgnoreStandalonePods: true,
		GracePeriodSeconds:   0,
	}
}

func (a Actionner) Checks(event *events.Event, _ *rules.Action) error {
	return k8sChecks.CheckPodExist(event)
}

func (a Actionner) Run(event *events.Event, action *rules.Action) (utils.LogLine, *models.Data, error) {
	podName := event.GetPodName()
	namespace := event.GetNamespaceName()

	objects := map[string]string{
		"pod":       podName,
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

	gracePeriodSeconds := new(int64)
	*gracePeriodSeconds = int64(parameters.GracePeriodSeconds)

	client := k8s.GetClient()
	pod, err := client.GetPod(podName, namespace)
	if err != nil {
		return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  utils.FailureStr,
			},
			nil,
			err
	}

	ownerKind := k8s.PodKind(*pod)

	switch ownerKind {
	case utils.DaemonSetStr:
		if parameters.IgnoreDaemonsets {
			return utils.LogLine{
				Objects: objects,
				Status:  "ignored",
				Result:  fmt.Sprintf("the pod '%v' in the namespace '%v' belongs to a DaemonSet and will be ignored.", podName, namespace),
			}, nil, nil
		}
	case utils.StatefulSetStr:
		if parameters.IgnoreStatefulSets {
			return utils.LogLine{
				Objects: objects,
				Status:  "ignored",
				Result:  fmt.Sprintf("the pod '%v' in the namespace '%v' belongs to a StatefulSet and will be ignored.", podName, namespace),
			}, nil, nil
		}
	case utils.ReplicaSetStr:
		replicaSetName, err2 := k8s.GetOwnerName(*pod)
		if err2 != nil {
			return utils.LogLine{
				Objects: objects,
				Status:  utils.FailureStr,
				Error:   err2.Error(),
			}, nil, nil
		}
		if parameters.MinHealthyReplicas != "" {
			replicaSet, err2 := client.GetReplicaSet(replicaSetName, pod.Namespace)
			if err2 != nil {
				return utils.LogLine{
					Objects: objects,
					Status:  utils.FailureStr,
					Error:   err2.Error(),
				}, nil, nil
			}
			minHealthyReplicasValue, kind, err2 := helpers.ParseMinHealthyReplicas(parameters.MinHealthyReplicas)
			if err2 != nil {
				return utils.LogLine{
					Objects: objects,
					Status:  utils.FailureStr,
					Error:   err2.Error(),
				}, nil, nil
			}
			switch kind {
			case "absolut":
				healthyReplicasCount, err2 := k8s.GetHealthyReplicasCount(replicaSet)
				if err2 != nil {
					return utils.LogLine{
						Objects: objects,
						Status:  utils.FailureStr,
						Error:   err2.Error(),
					}, nil, nil
				}
				if healthyReplicasCount < minHealthyReplicasValue {
					return utils.LogLine{
						Objects: objects,
						Status:  "ignored",
						Result:  fmt.Sprintf("the pod '%v' in the namespace '%v' belongs to a ReplicaSet without enough healthy replicas and will be ignored.", podName, namespace),
					}, nil, nil
				}
			case "percent":
				healthyReplicasPercent, err2 := k8s.GetHealthyReplicasCount(replicaSet)
				if err2 != nil {
					return utils.LogLine{
						Objects: objects,
						Status:  utils.FailureStr,
						Error:   err2.Error(),
					}, nil, nil
				}
				if healthyReplicasPercent < minHealthyReplicasValue {
					return utils.LogLine{
						Objects: objects,
						Status:  "ignored",
						Result:  fmt.Sprintf("the pod '%v' in the namespace '%v' belongs to a ReplicaSet without enough healthy replicas and will be ignored.", podName, namespace),
					}, nil, nil
				}
			}
		}
	case utils.StandalonePodStr:
		if parameters.IgnoreStandalonePods {
			return utils.LogLine{
				Objects: objects,
				Status:  "ignored",
				Result:  fmt.Sprintf("the pod '%v' in the namespace '%v' is a standalone pod and will be ignored.", podName, namespace),
			}, nil, nil
		}
	}

	err = client.Clientset.CoreV1().Pods(namespace).Delete(context.Background(), podName, metav1.DeleteOptions{GracePeriodSeconds: gracePeriodSeconds})
	if err != nil {
		return utils.LogLine{
				Objects: objects,
				Status:  utils.FailureStr,
				Error:   err.Error(),
			},
			nil,
			err
	}
	return utils.LogLine{
			Objects: objects,
			Output:  fmt.Sprintf("the pod '%v' in the namespace '%v' has been terminated", podName, namespace),
			Status:  utils.SuccessStr,
		},
		nil, nil
}

func (a Actionner) CheckParameters(action *rules.Action) error {
	var parameters Parameters
	err := utils.DecodeParams(action.GetParameters(), &parameters)
	if err != nil {
		return err
	}

	err = utils.AddCustomValidation(helpers.ValidatorMinHealthyReplicas, helpers.ValidateMinHealthyReplicas)
	if err != nil {
		return err
	}

	err = utils.ValidateStruct(parameters)
	if err != nil {
		return err
	}

	return nil
}
