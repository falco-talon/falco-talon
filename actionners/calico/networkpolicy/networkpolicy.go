package networkpolicy

import (
	"context"
	"fmt"
	"net"
	"strings"

	networkingv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	errorsv1 "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	calico "github.com/falco-talon/falco-talon/internal/calico/client"

	"github.com/falco-talon/falco-talon/internal/events"
	kubernetes "github.com/falco-talon/falco-talon/internal/kubernetes/client"
	"github.com/falco-talon/falco-talon/internal/rules"
	"github.com/falco-talon/falco-talon/utils"
)

type Config struct {
	Allow []string `mapstructure:"allow" validate:"omitempty"`
	Order int      `mapstructure:"order" validate:"omitempty"`
}

const mask32 string = "/32"
const managedByStr string = "app.kubernetes.io/managed-by"

func Action(action *rules.Action, event *events.Event) (utils.LogLine, error) {
	podName := event.GetPodName()
	namespace := event.GetNamespaceName()

	parameters := action.GetParameters()

	objects := map[string]string{
		"pod":       podName,
		"namespace": namespace,
	}
	k8sClient := kubernetes.GetClient()
	calicoClient := calico.GetClient()

	var err error
	pod, err := k8sClient.GetPod(podName, namespace)
	if err != nil {
		return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  "failure",
			},
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
						Status:  "failure",
					},
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
						Status:  "failure",
					},
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
						Status:  "failure",
					},
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
				Status:  "failure",
			},
			err3
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

	if parameters["order"] != nil {
		order := float64(parameters["order"].(int))
		payload.Spec.Order = &order
	}

	var selector string
	for i, j := range labels {
		if i != managedByStr {
			selector += fmt.Sprintf(`%v == "%v" && `, i, j)
		}
	}

	payload.Spec.Selector = strings.TrimSuffix(selector, " && ")

	allowRule := createAllowEgressRule(action)
	denyRule := createDenyEgressRule([]string{event.GetRemoteIP() + mask32})
	if denyRule == nil {
		err2 := fmt.Errorf("can't create the rule for the networkpolicy '%v' in the namespace '%v'", owner, namespace)
		return utils.LogLine{
				Objects: objects,
				Error:   err2.Error(),
				Status:  "failure",
			},
			err2
	}

	var output string
	var netpol *networkingv3.NetworkPolicy
	netpol, err = calicoClient.ProjectcalicoV3().NetworkPolicies(namespace).Get(context.Background(), owner, metav1.GetOptions{})
	if errorsv1.IsNotFound(err) {
		payload.Spec.Egress = []networkingv3.Rule{*denyRule}
		payload.Spec.Egress = append(payload.Spec.Egress, *allowRule)
		_, err2 := calicoClient.ProjectcalicoV3().NetworkPolicies(namespace).Create(context.Background(), &payload, metav1.CreateOptions{})
		if err2 != nil {
			if !errorsv1.IsAlreadyExists(err2) {
				return utils.LogLine{
						Objects: objects,
						Error:   err2.Error(),
						Status:  "failure",
					},
					err2
			}
			netpol, err = calicoClient.ProjectcalicoV3().NetworkPolicies(namespace).Get(context.Background(), owner, metav1.GetOptions{})
		} else {
			output = fmt.Sprintf("the caliconetworkpolicy '%v' in the namespace '%v' has been created", owner, namespace)
			return utils.LogLine{
					Objects: objects,
					Output:  output,
					Status:  "success",
				},
				nil
		}
	}
	if err != nil {
		return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  "failure",
			},
			err
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
	payload.Spec.Egress = append(payload.Spec.Egress, *allowRule)
	_, err = calicoClient.ProjectcalicoV3().NetworkPolicies(namespace).Update(context.Background(), &payload, metav1.UpdateOptions{})
	if err != nil {
		return utils.LogLine{
				Objects: objects,
				Error:   err.Error(),
				Status:  "failure",
			},
			err
	}
	output = fmt.Sprintf("the caliconetworkpolicy '%v' in the namespace '%v' has been updated", owner, namespace)
	objects["NetworkPolicy"] = owner

	return utils.LogLine{
			Objects: objects,
			Output:  output,
			Status:  "success",
		},
		nil
}

func createAllowEgressRule(action *rules.Action) *networkingv3.Rule {
	var allowCIDR []string
	if action.GetParameters()["allow"] != nil {
		if allowedCidr := action.GetParameters()["allow"].([]interface{}); len(allowedCidr) != 0 {
			for _, i := range allowedCidr {
				allowedCidr = append(allowedCidr, i.(string))
			}
		} else {
			allowCIDR = append(allowCIDR, "0.0.0.0/0")
		}
	} else {
		allowCIDR = append(allowCIDR, "0.0.0.0/0")
	}

	rule := &networkingv3.Rule{
		Action: "Allow",
		Destination: networkingv3.EntityRule{
			Nets: allowCIDR,
		},
	}

	return rule
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

func CheckParameters(action *rules.Action) error {
	parameters := action.GetParameters()

	var config Config

	err := utils.DecodeParams(parameters, &config)
	if err != nil {
		return err
	}

	err = utils.ValidateStruct(config)
	if err != nil {
		return err
	}

	if config.Allow == nil {
		return nil
	}
	for _, i := range config.Allow {
		if _, _, err := net.ParseCIDR(i); err != nil {
			return fmt.Errorf("wrong CIDR '%v'", i)
		}
	}

	return nil
}
