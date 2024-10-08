package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/apimachinery/pkg/watch"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/tools/remotecommand"
	toolsWatch "k8s.io/client-go/tools/watch"
	"k8s.io/kubectl/pkg/scheme"

	klog "k8s.io/klog/v2"

	"github.com/falco-talon/falco-talon/configuration"
	"github.com/falco-talon/falco-talon/utils"
)

type Client struct {
	*k8s.Clientset
	RestConfig *rest.Config
}

// need to be renamed to Client
// all the actionners need to depend on this interface so we can rename it to Client
// without generating errors
//
//nolint:revive
type KubernetesClient interface {
	GetPod(pod, namespace string) (*corev1.Pod, error)
	GetDeployment(name, namespace string) (*appsv1.Deployment, error)
	GetDaemonSet(name, namespace string) (*appsv1.DaemonSet, error)
	GetStatefulSet(name, namespace string) (*appsv1.StatefulSet, error)
	GetReplicaSet(name, namespace string) (*appsv1.ReplicaSet, error)
	GetNode(name string) (*corev1.Node, error)
	GetDeploymentFromPod(pod *corev1.Pod) (*appsv1.Deployment, error)
	GetDaemonsetFromPod(pod *corev1.Pod) (*appsv1.DaemonSet, error)
	GetStatefulsetFromPod(pod *corev1.Pod) (*appsv1.StatefulSet, error)
	GetReplicasetFromPod(pod *corev1.Pod) (*appsv1.ReplicaSet, error)
	GetNodeFromPod(pod *corev1.Pod) (*corev1.Node, error)
	GetTarget(resource, name, namespace string) (any, error)
	GetNamespace(name string) (*corev1.Namespace, error)
	GetConfigMap(name, namespace string) (*corev1.ConfigMap, error)
	GetSecret(name, namespace string) (*corev1.Secret, error)
	GetService(name, namespace string) (*corev1.Service, error)
	GetServiceAccount(name, namespace string) (*corev1.ServiceAccount, error)
	GetRole(name, namespace string) (*rbacv1.Role, error)
	GetClusterRole(name, namespace string) (*rbacv1.ClusterRole, error)
	GetWatcherEndpointSlices(labelSelector, namespace string) (<-chan watch.Event, error)
	GetLeaseHolder() (<-chan string, error)
	Exec(namespace, pod, container string, command []string, script string) (*bytes.Buffer, error)
	CreateEphemeralContainer(pod *corev1.Pod, container, name string, ttl int) error
	ListPods(ctx context.Context, opts metav1.ListOptions) (*corev1.PodList, error)
	EvictPod(pod corev1.Pod) error
}

type DrainClient interface {
	GetPod(name, namespace string) (*corev1.Pod, error)
	GetNodeFromPod(pod *corev1.Pod) (*corev1.Node, error)
	ListPods(ctx context.Context, options metav1.ListOptions) (*corev1.PodList, error)
	EvictPod(pod corev1.Pod) error
	GetReplicaSet(name, namespace string) (*appsv1.ReplicaSet, error)
}

var (
	client          *Client
	leaseHolderChan chan string
	once            sync.Once
)

func Init() error {
	if client != nil {
		return nil
	}

	var initErr error

	once.Do(func() {
		client = new(Client)
		config := configuration.GetConfiguration()
		var err error
		if config.KubeConfig != "" {
			client.RestConfig, err = clientcmd.BuildConfigFromFlags("", config.KubeConfig)
		} else {
			client.RestConfig, err = rest.InClusterConfig()
		}
		if err != nil {
			initErr = err
			return
		}

		// creates the clientset
		client.Clientset, err = k8s.NewForConfig(client.RestConfig)
		if err != nil {
			initErr = err
			return
		}

		// // disable klog
		klog.InitFlags(nil)
		if err := flag.Set("logtostderr", "false"); err != nil {
			initErr = err
			return
		}
		if err := flag.Set("alsologtostderr", "false"); err != nil {
			initErr = err
			return
		}
		flag.Parse()

		if initErr == nil {
			utils.PrintLog("info", utils.LogLine{Message: "init", Category: "kubernetes", Status: utils.SuccessStr})
		}
	})

	return initErr
}

func GetClient() *Client {
	if client == nil {
		if err := Init(); err != nil {
			return nil
		}
	}
	return client
}

func (client Client) GetPod(pod, namespace string) (*corev1.Pod, error) {
	p, err := client.Clientset.CoreV1().Pods(namespace).Get(context.Background(), pod, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("the pod '%v' in the namespace '%v' doesn't exist", pod, namespace)
	}
	return p, nil
}

func (client Client) GetDeployment(name, namespace string) (*appsv1.Deployment, error) {
	p, err := client.Clientset.AppsV1().Deployments(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("the deployment '%v' in the namespace '%v' doesn't exist", name, namespace)
	}
	return p, nil
}

func (client Client) GetDaemonSet(name, namespace string) (*appsv1.DaemonSet, error) {
	p, err := client.Clientset.AppsV1().DaemonSets(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("the daemonset '%v' in the namespace '%v' doesn't exist", name, namespace)
	}
	return p, nil
}

func (client Client) GetStatefulSet(name, namespace string) (*appsv1.StatefulSet, error) {
	p, err := client.Clientset.AppsV1().StatefulSets(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("the statefulset '%v' in the namespace '%v' doesn't exist", name, namespace)
	}
	return p, nil
}

func (client Client) GetReplicaSet(name, namespace string) (*appsv1.ReplicaSet, error) {
	p, err := client.Clientset.AppsV1().ReplicaSets(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("the replicaset '%v' in the namespace '%v' doesn't exist", name, namespace)
	}
	return p, nil
}

func (client Client) GetNode(name string) (*corev1.Node, error) {
	p, err := client.Clientset.CoreV1().Nodes().Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error getting node '%v': %v", name, err)
	}
	return p, nil
}

func (client Client) GetDeploymentFromPod(pod *corev1.Pod) (*appsv1.Deployment, error) {
	podName := pod.OwnerReferences[0].Name
	namespace := pod.ObjectMeta.Namespace
	r, err := client.GetDeployment(podName, namespace)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("can't find the deployment for the pod'%v' in namespace '%v'", podName, namespace)
	}
	return r, nil
}

func (client Client) GetDaemonsetFromPod(pod *corev1.Pod) (*appsv1.DaemonSet, error) {
	podName := pod.OwnerReferences[0].Name
	namespace := pod.ObjectMeta.Namespace
	r, err := client.GetDaemonSet(podName, namespace)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("can't find the daemonset for the pod'%v' in namespace '%v'", podName, namespace)
	}
	return r, nil
}

func (client Client) GetStatefulsetFromPod(pod *corev1.Pod) (*appsv1.StatefulSet, error) {
	podName := pod.OwnerReferences[0].Name
	namespace := pod.ObjectMeta.Namespace
	r, err := client.GetStatefulSet(podName, namespace)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("can't find the statefulset for the pod'%v' in namespace '%v'", podName, namespace)
	}
	return r, nil
}

func (client Client) GetReplicasetFromPod(pod *corev1.Pod) (*appsv1.ReplicaSet, error) {
	podName := pod.OwnerReferences[0].Name
	namespace := pod.ObjectMeta.Namespace
	r, err := client.GetReplicaSet(podName, namespace)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("can't find the replicaset for the pod'%v' in namespace '%v'", podName, namespace)
	}
	return r, nil
}

func (client Client) GetNodeFromPod(pod *corev1.Pod) (*corev1.Node, error) {
	podName := pod.GetName()
	namespace := pod.GetNamespace()
	nodeName := pod.Spec.NodeName
	r, err := client.GetNode(nodeName)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("can't find the node for the pod'%v' in namespace '%v'", podName, namespace)
	}
	return r, nil
}

func (client Client) GetTarget(resource, name, namespace string) (any, error) {
	switch resource {
	case "namespaces":
		return client.GetNamespace(name)
	case "configmaps":
		return client.GetConfigMap(name, namespace)
	case "secrets":
		return client.GetSecret(name, namespace)
	case "deployments":
		return client.GetDeployment(name, namespace)
	case "daemonsets":
		return client.GetDeployment(name, namespace)
	case "statefulsets":
		return client.GetStatefulSet(name, namespace)
	case "replicasets":
		return client.GetReplicaSet(name, namespace)
	case "services":
		return client.GetService(name, namespace)
	case "serviceaccounts":
		return client.GetServiceAccount(name, namespace)
	case "roles":
		return client.GetRole(name, namespace)
	case "clusterroles":
		return client.GetClusterRole(name, namespace)
	}

	return nil, errors.New("the resource doesn't exist or its type is not yet managed")
}

func (client Client) GetNamespace(name string) (*corev1.Namespace, error) {
	p, err := client.Clientset.CoreV1().Namespaces().Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("the namespace '%v' doesn't exist", name)
	}
	return p, nil
}

func (client Client) GetConfigMap(name, namespace string) (*corev1.ConfigMap, error) {
	p, err := client.Clientset.CoreV1().ConfigMaps(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("the configmap '%v' in the namespace '%v' doesn't exist", name, namespace)
	}
	return p, nil
}

func (client Client) GetSecret(name, namespace string) (*corev1.Secret, error) {
	p, err := client.Clientset.CoreV1().Secrets(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("the secret '%v' in the namespace '%v' doesn't exist", name, namespace)
	}
	return p, nil
}

func (client Client) GetService(name, namespace string) (*corev1.Service, error) {
	p, err := client.Clientset.CoreV1().Services(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("the service '%v' in the namespace '%v' doesn't exist", name, namespace)
	}
	return p, nil
}

func (client Client) GetServiceAccount(name, namespace string) (*corev1.ServiceAccount, error) {
	p, err := client.Clientset.CoreV1().ServiceAccounts(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("the serviceaccount '%v' in the namespace '%v' doesn't exist", name, namespace)
	}
	return p, nil
}

func (client Client) GetRole(name, namespace string) (*rbacv1.Role, error) {
	p, err := client.Clientset.RbacV1().Roles(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("the role '%v' in the namespace '%v' doesn't exist", name, namespace)
	}
	return p, nil
}

func (client Client) GetClusterRole(name, namespace string) (*rbacv1.ClusterRole, error) {
	p, err := client.Clientset.RbacV1().ClusterRoles().Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("the clusterrole '%v' in the namespace '%v' doesn't exist", name, namespace)
	}
	return p, nil
}

func (client Client) GetWatcherEndpointSlices(labelSelector, namespace string) (<-chan watch.Event, error) {
	watchFunc := func(_ metav1.ListOptions) (watch.Interface, error) {
		timeOut := int64(5)
		return client.Clientset.DiscoveryV1().EndpointSlices(namespace).Watch(context.Background(), metav1.ListOptions{LabelSelector: labelSelector, TimeoutSeconds: &timeOut})
	}

	watcher, err := toolsWatch.NewRetryWatcher("1", &cache.ListWatch{WatchFunc: watchFunc})
	if err != nil {
		return nil, err
	}
	return watcher.ResultChan(), nil
}

func (client Client) GetLeaseHolder() (<-chan string, error) {
	if leaseHolderChan != nil {
		return leaseHolderChan, nil
	}

	leaseHolderChan = make(chan string, 20)
	namespace := os.Getenv("NAMESPACE")
	if namespace == "" {
		namespace = "falco"
	}
	leaderElectionConfig := leaderelection.LeaderElectionConfig{
		Lock: &resourcelock.LeaseLock{
			LeaseMeta: metav1.ObjectMeta{
				Name:      "falco-talon",
				Namespace: namespace,
				Labels: map[string]string{
					"app.kubernetes.io/part-of": "falco-talon",
					"app.kubernetes.io/name":    "falco-talon",
				},
			},
			Client: client.Clientset.CoordinationV1(),
			LockConfig: resourcelock.ResourceLockConfig{
				Identity: *utils.GetLocalIP(),
			},
		},
		LeaseDuration: time.Duration(4) * time.Second,
		RenewDeadline: time.Duration(3) * time.Second,
		RetryPeriod:   time.Duration(2) * time.Second,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(_ context.Context) {},
			OnStoppedLeading: func() {},
			OnNewLeader: func(identity string) {
				leaseHolderChan <- identity
			},
		},
		ReleaseOnCancel: true,
	}

	leaderElector, err := leaderelection.NewLeaderElector(leaderElectionConfig)
	if err != nil {
		return nil, err
	}

	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		leaderElector.Run(ctx)
	}()

	return leaseHolderChan, nil
}

func (client Client) Exec(namespace, pod, container string, command []string, script string) (*bytes.Buffer, error) {
	var err error
	buf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	var exec remotecommand.Executor
	request := client.Clientset.CoreV1().RESTClient().
		Post().
		Namespace(namespace).
		Resource("pods").
		Name(pod).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: container,
			Command:   command,
			Stdin:     true,
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, scheme.ParameterCodec)
	exec, err = remotecommand.NewSPDYExecutor(client.RestConfig, "POST", request.URL())
	if err != nil {
		return nil, err
	}

	reader := new(strings.Reader)
	if script != "" {
		reader = strings.NewReader(script)
	}
	err = exec.StreamWithContext(context.Background(), remotecommand.StreamOptions{
		Stdin:  reader,
		Stdout: buf,
		Stderr: errBuf,
		Tty:    false,
	})
	if err != nil {
		return nil, fmt.Errorf("%v", errBuf.String())
	}

	// return utils.RemoveAnsiCharacters(buf.String()), nil
	return buf, nil
}

func (client Client) CreateEphemeralContainer(pod *corev1.Pod, container, name, image string, ttl int) error {
	ec := &corev1.EphemeralContainer{
		EphemeralContainerCommon: corev1.EphemeralContainerCommon{
			Name:                     name,
			Image:                    image,
			ImagePullPolicy:          corev1.PullAlways,
			Command:                  []string{"sleep", fmt.Sprintf("%v", ttl)},
			Stdin:                    true,
			TTY:                      false,
			TerminationMessagePolicy: corev1.TerminationMessageReadFile,
		},
		TargetContainerName: container,
	}

	podWithEphemeralContainer := pod.DeepCopy()
	podWithEphemeralContainer.Spec.EphemeralContainers = append(podWithEphemeralContainer.Spec.EphemeralContainers, *ec)

	podJSON, err := json.Marshal(pod)
	if err != nil {
		return err
	}

	podWithEphemeralContainerJSON, err := json.Marshal(podWithEphemeralContainer)
	if err != nil {
		return err
	}

	patch, err := strategicpatch.CreateTwoWayMergePatch(podJSON, podWithEphemeralContainerJSON, pod)
	if err != nil {
		return err
	}

	_, err = client.CoreV1().
		Pods(pod.Namespace).
		Patch(
			context.Background(),
			pod.Name,
			types.StrategicMergePatchType,
			patch,
			metav1.PatchOptions{},
			"ephemeralcontainers",
		)
	if err != nil {
		return err
	}

	timeout := time.NewTimer(10 * time.Second)
	ticker := time.NewTicker(300 * time.Millisecond)
	defer timeout.Stop()
	defer ticker.Stop()

	var ready bool
	for !ready {
		select {
		case <-timeout.C:
			return fmt.Errorf("ephemeral container for the tcpdump not ready in the pod '%v' in the namespace '%v'", pod.Name, pod.Namespace)
		case <-ticker.C:
			p, err := client.GetPod(pod.Name, pod.Namespace)
			if err != nil {
				return err
			}
			for _, i := range p.Status.EphemeralContainerStatuses {
				if i.Name == name && i.State.Running != nil {
					ready = true
				}
			}
		}
	}

	return nil
}

func (client Client) ListPods(ctx context.Context, opts metav1.ListOptions) (*corev1.PodList, error) {
	return client.CoreV1().Pods("").List(ctx, opts)
}

func (client Client) EvictPod(pod corev1.Pod) error {
	eviction := &policyv1.Eviction{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pod.Name,
			Namespace: pod.Namespace,
		},
	}
	err := client.PolicyV1().Evictions(pod.GetNamespace()).Evict(context.Background(), eviction)
	if err != nil {
		return err
	}
	return nil
}

// PodKind returns the type of the pod
// if no owner reference is found, the pod is considered as a standalone pod
func PodKind(pod corev1.Pod) string {
	if len(pod.OwnerReferences) == 0 {
		return utils.StandalonePodStr
	}
	return pod.OwnerReferences[0].Kind
}

func GetOwnerName(pod corev1.Pod) (string, error) {
	if len(pod.OwnerReferences) == 0 {
		return "", fmt.Errorf("no owner reference found")
	}
	return pod.OwnerReferences[0].Name, nil
}

func GetHealthyReplicasCount(replicaset *appsv1.ReplicaSet) (int64, error) {
	if replicaset == nil {
		return 0, fmt.Errorf("no replicaset found")
	}
	healthyReplicas := int64(replicaset.Status.ReadyReplicas)
	return healthyReplicas, nil
}

func GetContainers(pod *corev1.Pod) []string {
	c := make([]string, 0)
	for _, i := range pod.Spec.Containers {
		c = append(c, i.Name)
	}
	return c
}
