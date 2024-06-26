package drain

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	helpers "github.com/falco-talon/falco-talon/actionners/kubernetes/helpers"
	"github.com/falco-talon/falco-talon/internal/events"
	kubernetes "github.com/falco-talon/falco-talon/internal/kubernetes/client"
	"github.com/falco-talon/falco-talon/internal/rules"
	"github.com/falco-talon/falco-talon/outputs/model"
	"github.com/falco-talon/falco-talon/utils"
)

const (
	// EvictionKind represents the kind of evictions object
	EvictionKind = "Eviction"
	// EvictionSubresource represents the kind of evictions object as pod's subresource
	EvictionSubresource = "pods/eviction"
	// HoldEvictionDefaultTickerSeconds represents how much time does the ticker takes to create another request to check if pods were evicted
	HoldEvictionDefaultTickerSeconds = 5
)

type Config struct {
	MinHealthyReplicas         string   `mapstructure:"min_healthy_replicas" validate:"omitempty,is_absolut_or_percent"`
	IgnoreErrors               bool     `mapstructure:"ignore_errors" validate:"omitempty"`
	IgnoreDaemonsets           bool     `mapstructure:"ignore_daemonsets" validate:"omitempty"`
	IgnoreStatefulSets         bool     `mapstructure:"ignore_statefulsets" validate:"omitempty"`
	GracePeriodSeconds         int      `mapstructure:"grace_period_seconds" validate:"omitempty"`
	WaitPeriod                 int      `mapstructure:"wait_period" validate:"omitempty"`
	WaitTimeExcludedNamespaces []string `mapstructure:"wait_time_excluded_namespaces" validate:"omitempty"`
}

func Action(action *rules.Action, event *events.Event) (utils.LogLine, *model.Data, error) {
	podName := event.GetPodName()
	namespace := event.GetNamespaceName()
	objects := map[string]string{}

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
		objects["pod"] = podName
		objects["namespace"] = namespace
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  "failure",
		}, nil, err
	}

	node, err := client.GetNodeFromPod(pod)
	if err != nil {
		objects["pod"] = podName
		objects["namespace"] = namespace
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  "failure",
		}, nil, err
	}
	nodeName := node.GetName()
	objects["node"] = nodeName

	pods, err := client.Clientset.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{
		FieldSelector: fmt.Sprintf("spec.nodeName=%s", nodeName),
	})
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  "failure",
		}, nil, err
	}

	var ignoredPodsCount, evictionErrorsCount, otherErrorsCount int

	var wg sync.WaitGroup

	for _, p := range pods.Items {
		wg.Add(1)
		go func() {
			defer wg.Done()

			ownerKind, err := kubernetes.GetOwnerKind(p)
			if err != nil {
				utils.PrintLog("warning", utils.LogLine{Message: fmt.Sprintf("error getting pod '%v' owner kind: %v", p.Name, err)})
				otherErrorsCount++
				return
			}

			switch ownerKind {
			case "DaemonSet":
				if config.IgnoreDaemonsets {
					ignoredPodsCount++
				}
			case "StatefulSet":
				if config.IgnoreStatefulSets {
					ignoredPodsCount++
				}
			case "ReplicaSet":
				replicaSetName, err := kubernetes.GetOwnerName(p)
				if err != nil {
					utils.PrintLog("warning", utils.LogLine{Message: fmt.Sprintf("error getting pod owner name: %v", err)})
					otherErrorsCount++
				}
				if config.MinHealthyReplicas != "" {
					replicaSet, err := client.GetReplicaSet(replicaSetName, p.Namespace)
					if err != nil {
						utils.PrintLog("warning", utils.LogLine{Message: fmt.Sprintf("error getting replica set for pod '%v': %v", p.Name, err)})
						otherErrorsCount++
						return
					}
					minHealthyReplicasValue, kind, err := helpers.ParseMinHealthyReplicas(config.MinHealthyReplicas)
					if err != nil {
						utils.PrintLog("warning", utils.LogLine{Message: fmt.Sprintf("error parsing min_healthy_replicas: %v", err)})
						otherErrorsCount++
						return
					}
					switch kind {
					case "absolut":
						healthyReplicasCount, err := kubernetes.GetHealthyReplicasCount(replicaSet)
						if err != nil {
							utils.PrintLog("warning", utils.LogLine{Message: fmt.Sprintf("error getting health replicas count for pod '%v': %v", p.Name, err)})
							otherErrorsCount++
							return
						}
						if healthyReplicasCount < minHealthyReplicasValue {
							return
						}
					case "percent":
						healthyReplicasValue, err := kubernetes.GetHealthyReplicasCount(replicaSet)
						minHealthyReplicasAbsoluteValue := int64(float64(minHealthyReplicasValue) / 100.0 * float64(healthyReplicasValue))
						if err != nil {
							utils.PrintLog("warning", utils.LogLine{Message: fmt.Sprintf("error getting health replicas count for pod '%v': %v", p.Name, err)})
							otherErrorsCount++
							return
						}
						if healthyReplicasValue < minHealthyReplicasAbsoluteValue {
							ignoredPodsCount++
							return
						}
					}
				}
			}

			eviction := &policyv1.Eviction{
				ObjectMeta: metav1.ObjectMeta{
					Name:      p.GetName(),
					Namespace: p.GetNamespace(),
				},
				DeleteOptions: &metav1.DeleteOptions{
					GracePeriodSeconds: gracePeriodSeconds,
				},
			}
			if err := client.PolicyV1().Evictions(pod.GetNamespace()).Evict(context.Background(), eviction); err != nil {
				utils.PrintLog("warning", utils.LogLine{Message: fmt.Sprintf("error evicting pod '%v': %v", p.Name, err)})
				evictionErrorsCount++
			}
		}()
	}

	wg.Wait()
	if config.WaitPeriod != 0 {
		err = verifyEvictionHasFinished(client, config.WaitPeriod, nodeName, config)
		if err != nil {
			return utils.LogLine{
				Objects: objects,
				Error:   fmt.Sprintf("pods were not evited during the wait period of %v seconds for node %s.", config.WaitPeriod, nodeName),
				Status:  "failure",
			}, nil, fmt.Errorf("pods were not evited during the wait period of %v seconds for node %s", config.WaitPeriod, nodeName)
		}
	}

	if config.IgnoreErrors || (evictionErrorsCount == 0 && otherErrorsCount == 0) {
		return utils.LogLine{
			Objects: objects,
			Output:  fmt.Sprintf("the node '%v' has been drained, errors are ignored: %v ignored pods, %v eviction errors, %v other errors", nodeName, ignoredPodsCount, evictionErrorsCount, otherErrorsCount),
			Status:  "success",
		}, nil, nil
	}
	return utils.LogLine{
		Objects: objects,
		Error:   fmt.Sprintf("the node '%v' has not been fully drained: %v pods ignored, %v eviction errors, %v other errors", nodeName, ignoredPodsCount, evictionErrorsCount, otherErrorsCount),
		Status:  "failure",
	}, nil, fmt.Errorf("the node '%v' has not been fully drained: %v eviction errors, %v other errors", nodeName, evictionErrorsCount, otherErrorsCount)
}

func verifyEvictionHasFinished(c *kubernetes.Client, period int, nodeName string, config Config) error {
	timeout := time.After(time.Duration(period) * time.Second)
	ticker := time.NewTicker(HoldEvictionDefaultTickerSeconds * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return errors.New("timeout reached before eviction finished")
		case <-ticker.C:

			var nonDaemonSetPods []string
			excludedNamespaces := make(map[string]bool)
			for _, namespace := range config.WaitTimeExcludedNamespaces {
				excludedNamespaces[namespace] = true
			}
			pods, err := c.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{
				FieldSelector: fmt.Sprintf("spec.nodeName=%s", nodeName),
			})
			if err != nil {
				return err
			}

			for _, pod := range pods.Items {
				isDaemonSet := false
				if pod.OwnerReferences != nil {
					for _, ownerRef := range pod.OwnerReferences {
						if ownerRef.Kind == "DaemonSet" {
							isDaemonSet = true
							break
						}
					}
				}

				if !isDaemonSet && !excludedNamespaces[pod.Namespace] {
					nonDaemonSetPods = append(nonDaemonSetPods, pod.Name)
				}

				if len(nonDaemonSetPods) == 0 || nonDaemonSetPods == nil {
					return nil
				}
			}
		}
	}
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
