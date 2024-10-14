package networkpolicy

import (
	"context"
	"fmt"
	"net"

	networkingv1 "k8s.io/api/networking/v1"
	errorsv1 "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/falcosecurity/falco-talon/internal/events"
	k8sChecks "github.com/falcosecurity/falco-talon/internal/kubernetes/checks"
	k8s "github.com/falcosecurity/falco-talon/internal/kubernetes/client"
	"github.com/falcosecurity/falco-talon/internal/models"
	"github.com/falcosecurity/falco-talon/internal/rules"
	"github.com/falcosecurity/falco-talon/utils"
)

const (
	Name          string = "networkpolicy"
	Category      string = "kubernetes"
	Description   string = "Create, update a network policy to block all egress traffic for pod"
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
  - networking.k8s.io
  resources:
  - networkpolicies
  verbs:
  - get
  - update
  - patch
  - create
- apiGroups:
  - apps
  resources:
  - daemonsets
  verbs:
  - get
- apiGroups:
  - apps
  resources:
  - deployments
  verbs:
  - get
- apiGroups:
  - apps
  resources:
  - replicasets
  verbs:
  - get
- apiGroups:
  - apps
  resources:
  - statefulsets
  verbs:
  - get
`
	Example string = `- action: Create a network policy
  actionner: kubernetes:networkpolicy
  parameters:
    allow_cidr:
      - "192.168.1.0/24"
      - "172.17.0.0/16"
    allow_namespaces:
      - "green-ns"
      - "blue-ns"
`
)

var (
	RequiredOutputFields = []string{"k8s.ns.name", "k8s.pod.name"}
)

type Parameters struct {
	AllowCIDR       []string `mapstructure:"allow_cidr" validate:"omitempty"`
	AllowNamespaces []string `mapstructure:"allow_namespaces" validate:"omitempty"`
}

const managedByStr string = "app.k8s.io/managed-by"

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
		AllowCIDR:       []string{"0.0.0.0/0"},
		AllowNamespaces: []string{},
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
	client := k8s.GetClient()

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
		return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  utils.FailureStr,
			},
			nil,
			err
	}

	var owner string
	labels := make(map[string]string)

	if len(pod.OwnerReferences) != 0 {
		switch pod.OwnerReferences[0].Kind {
		case "DaemonSet":
			u, err2 := client.GetDaemonsetFromPod(pod)
			if err2 != nil {
				return utils.LogLine{
						Objects: objects,
						Error:   err2.Error(),
						Status:  utils.FailureStr,
					},
					nil,
					err2
			}
			owner = u.ObjectMeta.Name
			labels = u.Spec.Selector.MatchLabels
		case "StatefulSet":
			u, err2 := client.GetStatefulsetFromPod(pod)
			if err2 != nil {
				return utils.LogLine{
						Objects: objects,
						Error:   err2.Error(),
						Status:  utils.FailureStr,
					},
					nil,
					err2
			}
			owner = u.ObjectMeta.Name
			labels = u.Spec.Selector.MatchLabels
		case "ReplicaSet":
			u, err2 := client.GetReplicasetFromPod(pod)
			if err2 != nil {
				return utils.LogLine{
						Objects: objects,
						Error:   err2.Error(),
						Status:  utils.FailureStr,
					},
					nil,
					err2
			}
			owner = u.ObjectMeta.Name
			labels = u.Spec.Selector.MatchLabels
		}
	} else {
		owner = pod.ObjectMeta.Name
		labels = pod.ObjectMeta.Labels
	}

	if owner == "" || len(labels) == 0 {
		err3 := fmt.Errorf("can't find the owner and/or labels for the pod '%v' in namespace '%v'", podName, namespace)
		return utils.LogLine{
				Objects: objects,
				Error:   err3.Error(),
				Status:  utils.FailureStr,
			},
			nil,
			err3
	}

	delete(labels, "pod-template-hash")
	delete(labels, "pod-template-generation")
	delete(labels, "controller-revision-hash")
	labels[managedByStr] = utils.FalcoTalonStr

	selector := make(map[string]string)
	for i, j := range labels {
		if i != managedByStr {
			selector[i] = j
		}
	}

	payload := networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      owner,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PolicyTypes: []networkingv1.PolicyType{"Egress"},
			PodSelector: metav1.LabelSelector{
				MatchLabels: selector,
			},
		},
	}

	np, err := createEgressRule(&parameters)
	if err != nil {
		return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  utils.FailureStr,
			},
			nil,
			err
	}

	if np != nil {
		payload.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{*np}
	}

	objects["networkpolicy"] = owner

	var output string
	_, err = client.Clientset.NetworkingV1().NetworkPolicies(namespace).Get(context.Background(), owner, metav1.GetOptions{})
	if errorsv1.IsNotFound(err) {
		_, err = client.Clientset.NetworkingV1().NetworkPolicies(namespace).Create(context.Background(), &payload, metav1.CreateOptions{})
		output = fmt.Sprintf("the networkpolicy '%v' in the namespace '%v' has been created", owner, namespace)
	} else {
		_, err = client.Clientset.NetworkingV1().NetworkPolicies(namespace).Update(context.Background(), &payload, metav1.UpdateOptions{})
		output = fmt.Sprintf("the networkpolicy '%v' in the namespace '%v' has been updated", owner, namespace)
	}
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	return utils.LogLine{
		Objects: objects,
		Output:  output,
		Status:  utils.SuccessStr,
	}, nil, nil
}

func createEgressRule(parameters *Parameters) (*networkingv1.NetworkPolicyEgressRule, error) {
	if len(parameters.AllowCIDR) == 0 && len(parameters.AllowNamespaces) == 0 {
		return nil, nil
	}

	np := make([]networkingv1.NetworkPolicyPeer, 0)
	if allowedCidr := parameters.AllowCIDR; len(allowedCidr) != 0 {
		for _, i := range allowedCidr {
			np = append(np,
				networkingv1.NetworkPolicyPeer{
					IPBlock: &networkingv1.IPBlock{
						CIDR: i,
					},
				},
			)
		}
	}
	if allowedNamespaces := parameters.AllowNamespaces; len(allowedNamespaces) != 0 {
		for _, i := range allowedNamespaces {
			np = append(np,
				networkingv1.NetworkPolicyPeer{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"k8s.io/metadata.name": i,
						},
					},
				},
			)
		}
	}
	return &networkingv1.NetworkPolicyEgressRule{To: np}, nil
}

func (a Actionner) CheckParameters(action *rules.Action) error {
	var parameters Parameters

	err := utils.DecodeParams(action.GetParameters(), &parameters)
	if err != nil {
		return err
	}

	for _, i := range parameters.AllowCIDR {
		if _, _, err2 := net.ParseCIDR(i); err2 != nil {
			return fmt.Errorf("wrong CIDR '%v'", i)
		}
	}

	err = utils.ValidateStruct(parameters)
	if err != nil {
		return err
	}

	return nil
}
