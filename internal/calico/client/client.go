package kubernetes

import (
	calico "github.com/projectcalico/api/pkg/client/clientset_generated/clientset"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/falcosecurity/falco-talon/configuration"
	kubernetes "github.com/falcosecurity/falco-talon/internal/kubernetes/client"
)

type Client struct {
	*calico.Clientset
}

var client *Client

func Init() error {
	// the calico category requires also a k8s client
	if err := kubernetes.Init(); err != nil {
		return err
	}

	client = new(Client)
	config := configuration.GetConfiguration()
	var err error
	var restConfig *rest.Config
	if config.KubeConfig != "" {
		restConfig, err = clientcmd.BuildConfigFromFlags("", config.KubeConfig)
	} else {
		restConfig, err = rest.InClusterConfig()
	}
	if err != nil {
		return err
	}

	// creates the clientset
	client.Clientset, err = calico.NewForConfig(restConfig)
	if err != nil {
		return err
	}
	return nil
}

func GetClient() *Client {
	return client
}
