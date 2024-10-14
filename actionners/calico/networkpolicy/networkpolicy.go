package networkpolicy

import (
	"context"
	"fmt"
	"net"
	"strings"

	networkingv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	errorsv1 "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	calico "github.com/falcosecurity/falco-talon/internal/calico/client"

	"github.com/falcosecurity/falco-talon/internal/events"
	k8sChecks "github.com/falcosecurity/falco-talon/internal/kubernetes/checks"
	k8s "github.com/falcosecurity/falco-talon/internal/kubernetes/client"
	"github.com/falcosecurity/falco-talon/internal/models"
	"github.com/falcosecurity/falco-talon/internal/rules"
	"github.com/falcosecurity/falco-talon/utils"
)

const (
	Name          string = "networkpolicy"
	Category      string = "calico"
	Description   string = "Create a Calico Network Policy to block the egress traffic to a specific IP"
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
  - projectcalico.org
  resources:
  - caliconetworkpolicies
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
	Example string = `- action: Create Calico netpol
  actionner: calico:networkpolicy
  parameters:
    order: 20
    allow_cidr:
      - "192.168.1.0/24"
      - "172.17.0.0/16"
    allow_namespaces:
      - "green-ns"
      - "blue-ns"
`
)

var (
	RequiredOutputFields = []string{"fd.sip / fd.rip"}
)

type Parameters struct {
	AllowCIDR       []string `mapstructure:"allow_cidr" validate:"omitempty"`
	AllowNamespaces []string `mapstructure:"allow_namespaces" validate:"omitempty"`
	Order           int      `mapstructure:"order" validate:"omitempty"`
}

const mask32 string = "/32"
const managedByStr string = "app.k8s.io/managed-by"

type Actionner struct{}

func Register() *Actionner {
	return new(Actionner)
}

func (a Actionner) Init() error {
	return calico.Init()
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
		Order:           0,
	}
}

func (a Actionner) Checks(event *events.Event, _ *rules.Action) error {
	if err := k8sChecks.CheckPodExist(event); err != nil {
		return err
	}
	if err := k8sChecks.CheckRemoteIP(event); err != nil {
		return err
	}

	return nil
}

func (a Actionner) Run(event *events.Event, action *rules.Action) (utils.LogLine, *models.Data, error) {
	podName := event.GetPodName()
	namespace := event.GetNamespaceName()

	var parameters Parameters
	err := utils.DecodeParams(action.GetParameters(), &parameters)
	if err != nil {
		return utils.LogLine{
			Objects: nil,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	objects := map[string]string{
		"pod":       podName,
		"namespace": namespace,
	}
	k8sClient := k8s.GetClient()
	calicoClient := calico.GetClient()

	pod, err := k8sClient.GetPod(podName, namespace)
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	var owner string
	labels := make(map[string]string)

	if len(pod.OwnerReferences) != 0 {
		switch pod.OwnerReferences[0].Kind {
		case "DaemonSet":
			u, err2 := k8sClient.GetDaemonsetFromPod(pod)
			if err2 != nil {
				return utils.LogLine{
					Objects: objects,
					Error:   err2.Error(),
					Status:  utils.FailureStr,
				}, nil, err2
			}
			owner = u.ObjectMeta.Name
			labels = u.Spec.Selector.MatchLabels
		case "StatefulSet":
			u, err2 := k8sClient.GetStatefulsetFromPod(pod)
			if err2 != nil {
				return utils.LogLine{
					Objects: objects,
					Error:   err2.Error(),
					Status:  utils.FailureStr,
				}, nil, err2
			}
			owner = u.ObjectMeta.Name
			labels = u.Spec.Selector.MatchLabels
		case "ReplicaSet":
			u, err2 := k8sClient.GetReplicasetFromPod(pod)
			if err2 != nil {
				return utils.LogLine{
					Objects: objects,
					Error:   err2.Error(),
					Status:  utils.FailureStr,
				}, nil, err2
			}
			owner = u.ObjectMeta.Name
			labels = u.Spec.Selector.MatchLabels
		}
	} else {
		owner = pod.ObjectMeta.Name
		labels = pod.ObjectMeta.Labels
	}

	if owner == "" || len(labels) == 0 {
		err3 := fmt.Errorf("can't find the owner and/or labels for the pod '%v' in the namespace '%v'", podName, namespace)
		return utils.LogLine{
			Objects: objects,
			Error:   err3.Error(),
			Status:  utils.FailureStr,
		}, nil, err3
	}

	delete(labels, "pod-template-hash")
	delete(labels, "pod-template-generation")
	delete(labels, "controller-revision-hash")
	labels[managedByStr] = utils.FalcoTalonStr

	payload := networkingv3.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      owner,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: networkingv3.NetworkPolicySpec{
			Types: []networkingv3.PolicyType{networkingv3.PolicyTypeEgress},
		},
	}

	order := float64(parameters.Order)
	payload.Spec.Order = &order

	var selector string
	for i, j := range labels {
		if i != managedByStr {
			selector += fmt.Sprintf(`%v == "%v" && `, i, j)
		}
	}

	payload.Spec.Selector = strings.TrimSuffix(selector, " && ")

	var allowCIDRRule, allowNamespacesRule *networkingv3.Rule

	if parameters.AllowCIDR == nil && parameters.AllowNamespaces == nil {
		allowCIDRRule = &networkingv3.Rule{
			Action: "Allow",
			Destination: networkingv3.EntityRule{
				Nets: []string{"0.0.0.0/0"},
			},
		}
		allowNamespacesRule = nil
	} else {
		allowCIDRRule = createAllowCIDREgressRule(&parameters)
		allowNamespacesRule = createAllowNamespaceEgressRule(&parameters)
	}

	denyRule := createDenyEgressRule([]string{event.GetRemoteIP() + mask32})
	if denyRule == nil {
		err2 := fmt.Errorf("can't create the rule for the networkpolicy '%v' in the namespace '%v'", owner, namespace)
		return utils.LogLine{
			Objects: objects,
			Error:   err2.Error(),
			Status:  utils.FailureStr,
		}, nil, err2
	}

	var output string
	var netpol *networkingv3.NetworkPolicy
	netpol, err = calicoClient.ProjectcalicoV3().NetworkPolicies(namespace).Get(context.Background(), owner, metav1.GetOptions{})
	if errorsv1.IsNotFound(err) {
		payload.Spec.Egress = []networkingv3.Rule{*denyRule}
		if allowCIDRRule != nil {
			payload.Spec.Egress = append(payload.Spec.Egress, *allowCIDRRule)
		}
		if allowNamespacesRule != nil {
			payload.Spec.Egress = append(payload.Spec.Egress, *allowNamespacesRule)
		}
		_, err2 := calicoClient.ProjectcalicoV3().NetworkPolicies(namespace).Create(context.Background(), &payload, metav1.CreateOptions{})
		if err2 != nil {
			if !errorsv1.IsAlreadyExists(err2) {
				return utils.LogLine{
					Objects: objects,
					Error:   err2.Error(),
					Status:  utils.FailureStr,
				}, nil, err2
			}
			netpol, err = calicoClient.ProjectcalicoV3().NetworkPolicies(namespace).Get(context.Background(), owner, metav1.GetOptions{})
		} else {
			output = fmt.Sprintf("the caliconetworkpolicy '%v' in the namespace '%v' has been created", owner, namespace)
			return utils.LogLine{
				Objects: objects,
				Output:  output,
				Status:  utils.SuccessStr,
			}, nil, nil
		}
	}
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}
	payload.ObjectMeta.ResourceVersion = netpol.ObjectMeta.ResourceVersion
	var denyCIDR []string
	for _, i := range netpol.Spec.Egress {
		if i.Action == "Deny" {
			denyCIDR = append(denyCIDR, i.Destination.Nets...)
		}
	}
	denyCIDR = append(denyCIDR, event.GetRemoteIP()+mask32)
	denyCIDR = utils.Deduplicate(denyCIDR)
	denyRule = createDenyEgressRule(denyCIDR)
	payload.Spec.Egress = []networkingv3.Rule{*denyRule}
	if allowCIDRRule != nil {
		payload.Spec.Egress = append(payload.Spec.Egress, *allowCIDRRule)
	}
	if allowNamespacesRule != nil {
		payload.Spec.Egress = append(payload.Spec.Egress, *allowNamespacesRule)
	}
	_, err = calicoClient.ProjectcalicoV3().NetworkPolicies(namespace).Update(context.Background(), &payload, metav1.UpdateOptions{})
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}
	objects["caliconetworpolicy"] = owner
	output = fmt.Sprintf("the caliconetworkpolicy '%v' in the namespace '%v' has been updated", owner, namespace)

	return utils.LogLine{
		Objects: objects,
		Output:  output,
		Status:  utils.SuccessStr,
	}, nil, nil
}

func createAllowCIDREgressRule(parameters *Parameters) *networkingv3.Rule {
	if len(parameters.AllowCIDR) == 0 {
		return nil
	}

	rule := networkingv3.Rule{
		Action:      "Allow",
		Destination: networkingv3.EntityRule{},
	}

	rule.Destination.Nets = append(rule.Destination.Nets, parameters.AllowCIDR...)

	return &rule
}

func createAllowNamespaceEgressRule(parameters *Parameters) *networkingv3.Rule {
	if len(parameters.AllowNamespaces) == 0 {
		return nil
	}

	rule := networkingv3.Rule{
		Action:      "Allow",
		Destination: networkingv3.EntityRule{},
	}

	allowedNamespacesStr := []string{}
	allowedNamespacesStr = append(allowedNamespacesStr, parameters.AllowNamespaces...)

	selector := "k8s.io/metadata.name in { '"
	selector += strings.Join(allowedNamespacesStr, "', '")
	selector += "' }"

	rule.Destination.NamespaceSelector = selector

	return &rule
}

func createDenyEgressRule(ips []string) *networkingv3.Rule {
	r := networkingv3.Rule{
		Action: "Deny",
		Destination: networkingv3.EntityRule{
			Nets: ips,
		},
	}

	return &r
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
