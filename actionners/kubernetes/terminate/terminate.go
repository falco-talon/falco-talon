package terminate

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	helpers "github.com/falco-talon/falco-talon/actionners/kubernetes/helpers"
	"github.com/falco-talon/falco-talon/internal/events"
	kubernetes "github.com/falco-talon/falco-talon/internal/kubernetes/client"
	"github.com/falco-talon/falco-talon/internal/rules"
	"github.com/falco-talon/falco-talon/outputs/model"
	"github.com/falco-talon/falco-talon/utils"
)

type Config struct {
	MinHealthyReplicas string `mapstructure:"min_healthy_replicas" validate:"omitempty,is_absolut_or_percent"`
	IgnoreDaemonsets   bool   `mapstructure:"ignore_daemonsets" validate:"omitempty"`
	IgnoreStatefulSets bool   `mapstructure:"ignore_statefulsets" validate:"omitempty"`
	GracePeriodSeconds int    `mapstructure:"grace_period_seconds" validate:"omitempty"`
}

func Action(action *rules.Action, event *events.Event) (utils.LogLine, *model.Data, error) {
	podName := event.GetPodName()
	namespace := event.GetNamespaceName()

	objects := map[string]string{
		"pod":       podName,
		"namespace": namespace,
	}

	parameters := action.GetParameters()
	var config Config
	err := utils.DecodeParams(parameters, &config)
	if err != nil {
		return utils.LogLine{
			Objects: nil,
			Error:   err.Error(),
			Status:  "failure",
		}, nil, err
	}

	gracePeriodSeconds := new(int64)
	*gracePeriodSeconds = int64(config.GracePeriodSeconds)

	client := kubernetes.GetClient()
	pod, err := client.GetPod(podName, namespace)
	if err != nil {
		return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  "failure",
			},
			nil,
			err
	}

	ownerKind, err := kubernetes.GetOwnerKind(*pod)
	if err != nil {
		return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  "failure",
			},
			nil,
			err
	}

	switch ownerKind {
	case utils.DaemonSetStr:
		if config.IgnoreDaemonsets {
			return utils.LogLine{
				Objects: objects,
				Status:  "ignored",
				Result:  fmt.Sprintf("the pod '%v' in the namespace '%v' belongs to a DaemonSet and will be ignored.", podName, namespace),
			}, nil, nil
		}
	case utils.StatefulSetStr:
		if config.IgnoreStatefulSets {
			return utils.LogLine{
				Objects: objects,
				Status:  "ignored",
				Result:  fmt.Sprintf("the pod '%v' in the namespace '%v' belongs to a StatefulSet and will be ignored.", podName, namespace),
			}, nil, nil
		}
	case utils.ReplicaSetStr:
		replicaSetName, err2 := kubernetes.GetOwnerName(*pod)
		if err2 != nil {
			return utils.LogLine{
				Objects: objects,
				Status:  "failure",
				Error:   err2.Error(),
			}, nil, nil
		}
		if config.MinHealthyReplicas != "" {
			replicaSet, err2 := client.GetReplicaSet(replicaSetName, pod.Namespace)
			if err2 != nil {
				return utils.LogLine{
					Objects: objects,
					Status:  "failure",
					Error:   err2.Error(),
				}, nil, nil
			}
			minHealthyReplicasValue, kind, err2 := helpers.ParseMinHealthyReplicas(config.MinHealthyReplicas)
			if err2 != nil {
				return utils.LogLine{
					Objects: objects,
					Status:  "failure",
					Error:   err2.Error(),
				}, nil, nil
			}
			switch kind {
			case "absolut":
				healthyReplicasCount, err2 := kubernetes.GetHealthyReplicasCount(replicaSet)
				if err2 != nil {
					return utils.LogLine{
						Objects: objects,
						Status:  "failure",
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
				healthyReplicasPercent, err2 := kubernetes.GetHealthyReplicasCount(replicaSet)
				if err2 != nil {
					return utils.LogLine{
						Objects: objects,
						Status:  "failure",
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
	}

	err = client.Clientset.CoreV1().Pods(namespace).Delete(context.Background(), podName, metav1.DeleteOptions{GracePeriodSeconds: gracePeriodSeconds})
	if err != nil {
		return utils.LogLine{
				Objects: objects,
				Status:  "failure",
				Error:   err.Error(),
			},
			nil,
			err
	}
	return utils.LogLine{
			Objects: objects,
			Output:  fmt.Sprintf("the pod '%v' in the namespace '%v' has been terminated", podName, namespace),
			Status:  "success",
		},
		nil, nil
}

func CheckParameters(action *rules.Action) error {
	parameters := action.GetParameters()

	var config Config
	err := utils.DecodeParams(parameters, &config)
	if err != nil {
		return err
	}

	err = utils.AddCustomValidation(helpers.ValidatorMinHealthyReplicas, helpers.ValidateMinHealthyReplicas)
	if err != nil {
		return err
	}

	err = utils.ValidateStruct(config)
	if err != nil {
		return err
	}

	return nil
}
