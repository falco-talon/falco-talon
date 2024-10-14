package networkpolicy

import (
	"context"
	"fmt"
	"net"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/policy/api"
	errorsv1 "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cilium "github.com/falcosecurity/falco-talon/internal/cilium/client"
	"github.com/falcosecurity/falco-talon/internal/models"

	"github.com/falcosecurity/falco-talon/internal/events"
	k8sChecks "github.com/falcosecurity/falco-talon/internal/kubernetes/checks"
	k8s "github.com/falcosecurity/falco-talon/internal/kubernetes/client"
	"github.com/falcosecurity/falco-talon/internal/rules"
	"github.com/falcosecurity/falco-talon/utils"
)

const (
	Name          string = "networkpolicy"
	Category      string = "cilium"
	Description   string = "Create a Cilium Network Policy to block the egress traffic to a specific IP"
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
  - cilium.io
  resources:
  - ciliumnetworkpolicies
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
	Example string = `- action: Create Cilium netpol
actionner: cilium:networkpolicy
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
	RequiredOutputFields = []string{"fd.sip / fd.rip"}
)

type Parameters struct {
	AllowCIDR       []string `mapstructure:"allow_cidr" validate:"omitempty"`
	AllowNamespaces []string `mapstructure:"allow_namespaces" validate:"omitempty"`
}

const (
	mask32            string = "/32"
	managedByStr      string = "app.k8s.io/managed-by"
	netpolDescription string = "Network policy created by Falco Talon"
	namespaceKey             = "k8s.io/metadata.name"
)

type Actionner struct{}

func Register() *Actionner {
	return new(Actionner)
}

func (a Actionner) Init() error {
	return cilium.Init()
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

	var parameters Parameters
	err := utils.DecodeParams(action.GetParameters(), &parameters)
	if err != nil {
		return utils.LogLine{
				Objects: nil,
				Error:   err.Error(),
				Status:  utils.FailureStr,
			},
			nil,
			err
	}

	objects := map[string]string{
		"pod":       podName,
		"namespace": namespace,
	}

	k8sClient := k8s.GetClient()
	ciliumClient := cilium.GetClient()

	pod, err := k8sClient.GetPod(podName, namespace)
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
			u, err2 := k8sClient.GetDaemonsetFromPod(pod)
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
			u, err2 := k8sClient.GetStatefulsetFromPod(pod)
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
			u, err2 := k8sClient.GetReplicasetFromPod(pod)
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
		err3 := fmt.Errorf("can't find the owner and/or labels for the pod '%v' in the namespace '%v'", podName, namespace)
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

	resourceLabels := make(map[string]string)
	for key, value := range labels {
		resourceLabels[key] = value
	}
	resourceLabels[managedByStr] = utils.FalcoTalonStr

	payload := v2.CiliumNetworkPolicy{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:      owner,
			Namespace: namespace,
			Labels:    resourceLabels,
		},
		Spec: &api.Rule{
			Description: netpolDescription,
		},
		Status: v2.CiliumNetworkPolicyStatus{},
	}

	payload.Spec.EndpointSelector = api.EndpointSelector{
		LabelSelector: &v1.LabelSelector{MatchLabels: labels},
	}

	var allowCIDRRule, allowNamespacesRule *api.EgressRule

	if parameters.AllowCIDR == nil && parameters.AllowNamespaces == nil {
		allowCIDRRule = &api.EgressRule{
			EgressCommonRule: api.EgressCommonRule{
				ToCIDR: api.CIDRSlice{"0.0.0.0/0"},
			},
		}
	} else {
		allowCIDRRule = createAllowCIDREgressRule(parameters)
		allowNamespacesRule = createAllowNamespaceEgressRule(parameters)
	}

	denyRule := createDenyEgressRule([]string{event.GetRemoteIP() + mask32})
	if denyRule == nil {
		err2 := fmt.Errorf("can't create deny rule for the networkpolicy '%v' in the namespace '%v'", owner, namespace)
		return utils.LogLine{
				Objects: objects,
				Error:   err2.Error(),
				Status:  utils.FailureStr,
			},
			nil,
			err2
	}

	var output string
	var netpol *v2.CiliumNetworkPolicy

	netpol, err = ciliumClient.CiliumV2().CiliumNetworkPolicies(namespace).Get(context.Background(), owner, metav1.GetOptions{})
	if errorsv1.IsNotFound(err) {
		payload.Spec.EgressDeny = []api.EgressDenyRule{*denyRule}
		if allowCIDRRule != nil {
			payload.Spec.Egress = append(payload.Spec.Egress, *allowCIDRRule)
		}
		if allowNamespacesRule != nil {
			payload.Spec.Egress = append(payload.Spec.Egress, *allowNamespacesRule)
		}
		_, err2 := ciliumClient.CiliumV2().CiliumNetworkPolicies(namespace).Create(context.Background(), &payload, metav1.CreateOptions{})
		if err2 != nil {
			return utils.LogLine{
					Objects: objects,
					Error:   err2.Error(),
					Status:  utils.FailureStr,
				},
				nil,
				err2
		}
		output = fmt.Sprintf("the ciliumnetworkpolicy '%v' in the namespace '%v' has been created", owner, namespace)
		return utils.LogLine{
				Objects: objects,
				Output:  output,
				Status:  utils.SuccessStr,
			},
			nil,
			nil
	}
	if err != nil {
		return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  utils.FailureStr,
			},
			nil,
			err
	}

	payload.ObjectMeta.ResourceVersion = netpol.ObjectMeta.ResourceVersion
	payload.Spec.Egress = netpol.Spec.Egress
	payload.Spec.EgressDeny = netpol.Spec.EgressDeny

	denyRule = createDenyEgressRule([]string{event.GetRemoteIP() + mask32})

	for i := range payload.Spec.EgressDeny {
		if !denyEgressRuleExists(&payload.Spec.EgressDeny[i], denyRule) {
			payload.Spec.EgressDeny = append(payload.Spec.EgressDeny, *denyRule)
		}
	}

	for i := range payload.Spec.Egress {
		if !egressRuleExists(&payload.Spec.Egress[i], allowCIDRRule) && allowCIDRRule != nil {
			payload.Spec.Egress = append(payload.Spec.Egress, *allowCIDRRule)
		}
		if !egressRuleExists(&payload.Spec.Egress[i], allowNamespacesRule) && allowNamespacesRule != nil {
			payload.Spec.Egress = append(payload.Spec.Egress, *allowNamespacesRule)
		}
	}

	_, err = ciliumClient.CiliumV2().CiliumNetworkPolicies(namespace).Update(context.Background(), &payload, metav1.UpdateOptions{})
	if err != nil {
		return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  utils.FailureStr,
			},
			nil,
			err
	}
	output = fmt.Sprintf("the ciliumnetworkpolicy '%v' in the namespace '%v' has been updated", owner, namespace)
	objects["NetworkPolicy"] = owner

	return utils.LogLine{
			Objects: objects,
			Output:  output,
			Status:  utils.SuccessStr,
		},
		nil,
		nil
}

func createAllowNamespaceEgressRule(parameters Parameters) *api.EgressRule {
	if len(parameters.AllowCIDR) == 0 {
		return nil
	}

	selector := api.EndpointSelector{
		LabelSelector: &v1.LabelSelector{
			MatchExpressions: []v1.LabelSelectorRequirement{
				{
					Key:      namespaceKey,
					Operator: v1.LabelSelectorOpIn,
					Values:   parameters.AllowNamespaces,
				},
			},
		},
	}

	rule := api.EgressRule{
		EgressCommonRule: api.EgressCommonRule{
			ToEndpoints: []api.EndpointSelector{selector},
		},
	}

	return &rule
}

func createAllowCIDREgressRule(parameters Parameters) *api.EgressRule {
	if len(parameters.AllowCIDR) == 0 {
		return nil
	}

	var apiCidr api.CIDRSlice

	for _, cidr := range parameters.AllowCIDR {
		apiCidr = append(apiCidr, api.CIDR(cidr))
	}

	rule := api.EgressRule{
		EgressCommonRule: api.EgressCommonRule{
			ToCIDR: apiCidr,
		},
	}

	return &rule
}

func createDenyEgressRule(ips []string) *api.EgressDenyRule {
	var cidrSlice api.CIDRSlice
	for _, ip := range ips {
		cidrSlice = append(cidrSlice, api.CIDR(ip))
	}
	r := api.EgressDenyRule{
		EgressCommonRule: api.EgressCommonRule{
			ToCIDR: cidrSlice,
		},
	}

	return &r
}

func egressRuleExists(rule *api.EgressRule, newRule *api.EgressRule) bool {
	return rule.DeepEqual(newRule)
}

func denyEgressRuleExists(denyEgressRule *api.EgressDenyRule, newDenyEgressRule *api.EgressDenyRule) bool {
	return denyEgressRule.DeepEqual(newDenyEgressRule)
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
