package drain

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/falco-talon/falco-talon/actionners/kubernetes/helpers"

	k8s "github.com/falco-talon/falco-talon/internal/kubernetes/client"

	"github.com/falco-talon/falco-talon/internal/events"
	k8sChecks "github.com/falco-talon/falco-talon/internal/kubernetes/checks"
	"github.com/falco-talon/falco-talon/internal/models"
	"github.com/falco-talon/falco-talon/internal/rules"
	"github.com/falco-talon/falco-talon/utils"
)

const (
	Name          string = "drain"
	Category      string = "kubernetes"
	Description   string = "Drain a pod"
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
  - list
- apiGroups:
  - ""
  resources:
  - pods/eviction
  verbs:
  - get
  - create
- apiGroups:
  - apps
  resources:
  - replicasets
  verbs:
  - get
`
	Example string = `- action: Drain the node
  actionner: kubernetes:drain
`
)

var (
	RequiredOutputFields = []string{"k8s.ns.name", "k8s.pod.name"}
)

type Parameters struct {
	MinHealthyReplicas           string   `mapstructure:"min_healthy_replicas" validate:"omitempty,is_absolut_or_percent"`
	WaitPeriodExcludedNamespaces []string `mapstructure:"wait_period_excluded_namespaces" validate:"omitempty"`
	IgnoreErrors                 bool     `mapstructure:"ignore_errors" validate:"omitempty"`
	IgnoreDaemonsets             bool     `mapstructure:"ignore_daemonsets" validate:"omitempty"`
	IgnoreStatefulSets           bool     `mapstructure:"ignore_statefulsets" validate:"omitempty"`
	MaxWaitPeriod                int      `mapstructure:"max_wait_period" validate:"omitempty"`
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
		MinHealthyReplicas:           "",
		IgnoreErrors:                 false,
		IgnoreDaemonsets:             false,
		IgnoreStatefulSets:           false,
		MaxWaitPeriod:                0,
		WaitPeriodExcludedNamespaces: []string{},
	}
}

func (a Actionner) Checks(event *events.Event, _ *rules.Action) error {
	return k8sChecks.CheckPodExist(event)
}

func (a Actionner) Run(event *events.Event, action *rules.Action) (utils.LogLine, *models.Data, error) {
	client := k8s.GetClient()
	return a.RunWithClient(*client, event, action)
}

func (a Actionner) RunWithClient(client k8s.DrainClient, event *events.Event, action *rules.Action) (utils.LogLine, *models.Data, error) {
	podName := event.GetPodName()
	namespace := event.GetNamespaceName()
	objects := map[string]string{}

	var parameters Parameters
	err := utils.DecodeParams(action.GetParameters(), &parameters)
	if err != nil {
		return utils.LogLine{
			Objects: nil,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	pod, err := client.GetPod(podName, namespace)
	if err != nil {
		objects["pod"] = podName
		objects["namespace"] = namespace
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	node, err := client.GetNodeFromPod(pod)
	if err != nil {
		objects["pod"] = podName
		objects["namespace"] = namespace
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}
	nodeName := node.GetName()
	objects["node"] = nodeName

	pods, err := client.ListPods(context.Background(), metav1.ListOptions{
		FieldSelector: fmt.Sprintf("spec.nodeName=%s", nodeName),
	})
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	var podState atomic.Value

	initialPodState := make(map[string]bool)
	for _, p := range pods.Items {
		key := fmt.Sprintf("%s/%s", p.Namespace, p.Name)
		initialPodState[key] = true
	}
	podState.Store(initialPodState)
	stopListingDone := make(chan struct{})

	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-stopListingDone:
				return
			case <-ticker.C:
				pods2, err2 := client.ListPods(context.Background(), metav1.ListOptions{
					FieldSelector: fmt.Sprintf("spec.nodeName=%s", nodeName),
				})
				if err2 != nil {
					utils.PrintLog("warning", utils.LogLine{Message: fmt.Sprintf("error listing pods on node '%v': %v", nodeName, err2)})
					continue
				}

				newPodState := make(map[string]bool)
				for _, p := range pods2.Items {
					key := fmt.Sprintf("%s/%s", p.Namespace, p.Name)
					newPodState[key] = true
				}
				podState.Store(newPodState)
			}
		}
	}()

	var (
		ignoredPodsCount              int32
		evictionErrorsCount           int32
		evictionWaitPeriodErrorsCount int32
		otherErrorsCount              int32
	)

	var wg sync.WaitGroup

	for _, p := range pods.Items {
		wg.Add(1)
		go func(pod corev1.Pod) {
			defer wg.Done()

			ownerKind := k8s.PodKind(p)
			switch ownerKind {
			case utils.DaemonSetStr:
				if parameters.IgnoreDaemonsets {
					atomic.AddInt32(&ignoredPodsCount, 1)
					return
				}
			case utils.StatefulSetStr:
				if parameters.IgnoreStatefulSets {
					atomic.AddInt32(&ignoredPodsCount, 1)
					return
				}
			case utils.ReplicaSetStr:
				replicaSetName, err := k8s.GetOwnerName(p)
				if err != nil {
					utils.PrintLog("warning", utils.LogLine{Message: fmt.Sprintf("error getting pod owner name: %v", err)})
					atomic.AddInt32(&otherErrorsCount, 1)
					return
				}
				if parameters.MinHealthyReplicas != "" {
					replicaSet, err := client.GetReplicaSet(replicaSetName, p.Namespace)
					if err != nil {
						utils.PrintLog("warning", utils.LogLine{Message: fmt.Sprintf("error getting replica set for pod '%v': %v", p.Name, err)})
						atomic.AddInt32(&otherErrorsCount, 1)
						return
					}
					minHealthyReplicasValue, kind, err := helpers.ParseMinHealthyReplicas(parameters.MinHealthyReplicas)
					if err != nil {
						utils.PrintLog("warning", utils.LogLine{Message: fmt.Sprintf("error parsing min_healthy_replicas: %v", err)})
						atomic.AddInt32(&otherErrorsCount, 1)
						return
					}
					switch kind {
					case "absolut":
						healthyReplicasCount, err := k8s.GetHealthyReplicasCount(replicaSet)
						if err != nil {
							utils.PrintLog("warning", utils.LogLine{Message: fmt.Sprintf("error getting health replicas count for pod '%v': %v", p.Name, err)})
							atomic.AddInt32(&otherErrorsCount, 1)
							return
						}
						if healthyReplicasCount < minHealthyReplicasValue {
							atomic.AddInt32(&ignoredPodsCount, 1)
							return
						}
					case "percent":
						healthyReplicasValue, err := k8s.GetHealthyReplicasCount(replicaSet)
						minHealthyReplicasAbsoluteValue := int64(float64(minHealthyReplicasValue) / 100.0 * float64(healthyReplicasValue))
						if err != nil {
							utils.PrintLog("warning", utils.LogLine{Message: fmt.Sprintf("error getting health replicas count for pod '%v': %v", p.Name, err)})
							atomic.AddInt32(&otherErrorsCount, 1)
							return
						}
						if healthyReplicasValue < minHealthyReplicasAbsoluteValue {
							atomic.AddInt32(&ignoredPodsCount, 1)
							return
						}
					}
				}
			}

			if err := client.EvictPod(p); err != nil {
				utils.PrintLog("warning", utils.LogLine{Message: fmt.Sprintf("error evicting pod '%v': %v", p.Name, err)})
				atomic.AddInt32(&evictionErrorsCount, 1)
				return
			}

			if parameters.MaxWaitPeriod > 0 {
				timeout := time.After(time.Duration(parameters.MaxWaitPeriod) * time.Second)
				ticker := time.NewTicker(5 * time.Second)
				defer ticker.Stop()

				for {
					select {
					case <-timeout:
						utils.PrintLog("error", utils.LogLine{Message: fmt.Sprintf("pod '%v' did not terminate within the max_wait_period", pod.Name)})
						atomic.AddInt32(&evictionWaitPeriodErrorsCount, 1)
						return

					case <-ticker.C:
						key := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
						currentPodState := podState.Load().(map[string]bool)
						if _, ok := currentPodState[key]; !ok {
							return
						}
					}
				}
			}
		}(p)
	}

	wg.Wait()
	close(stopListingDone)

	if parameters.IgnoreErrors || (evictionErrorsCount == 0 && otherErrorsCount == 0 && evictionWaitPeriodErrorsCount == 0) {
		return utils.LogLine{
			Objects: objects,
			Output:  fmt.Sprintf("the node '%v' has been drained, errors are ignored: %v ignored pods, %v eviction errors, %v other errors", nodeName, ignoredPodsCount, evictionErrorsCount, otherErrorsCount),
			Status:  utils.SuccessStr,
		}, nil, nil
	}
	return utils.LogLine{
		Objects: objects,
		Error:   fmt.Sprintf("the node '%v' has not been fully drained: %v pods ignored, %v eviction errors, %v were not evicted during max_wait_period, %v other errors", nodeName, ignoredPodsCount, evictionErrorsCount, evictionWaitPeriodErrorsCount, otherErrorsCount),
		Status:  utils.FailureStr,
	}, nil, fmt.Errorf("the node '%v' has not been fully drained: %v pods ignored, %v eviction errors, %v were not evicted during max_wait_period, %v other errors", nodeName, ignoredPodsCount, evictionErrorsCount, evictionWaitPeriodErrorsCount, otherErrorsCount)
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
