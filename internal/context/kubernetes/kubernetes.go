package kubernetes

import (
	"github.com/falcosecurity/falco-talon/internal/events"
	kubernetes "github.com/falcosecurity/falco-talon/internal/kubernetes/client"
)

func GetNodeContext(event *events.Event) (map[string]any, error) {
	podName := event.GetPodName()
	namespace := event.GetNamespaceName()

	client := kubernetes.GetClient()
	pod, err := client.GetPod(podName, namespace)
	if err != nil {
		return nil, err
	}
	node, err := client.GetNodeFromPod(pod)
	if err != nil {
		return nil, err
	}

	elements := make(map[string]any)
	elements["node.hostname"] = node.Labels["kubernetes.io/hostname"]
	elements["node.instancetype"] = node.Labels["node.kubernetes.io/instance-type"]
	elements["node.role"] = node.Labels["kubernetes.io/role"]
	elements["node.topology.region"] = node.Labels["topology.kubernetes.io/region"]
	elements["node.topology.zone"] = node.Labels["topology.kubernetes.io/zone"]
	elements["node.spec.providerid"] = node.Spec.ProviderID

	return elements, nil
}
