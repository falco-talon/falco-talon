package networkpolicy

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/falcosecurity/falco-talon/internal/events"
	k8sChecks "github.com/falcosecurity/falco-talon/internal/kubernetes/checks"
	k8s "github.com/falcosecurity/falco-talon/internal/kubernetes/client"
	"github.com/falcosecurity/falco-talon/internal/models"
	"github.com/falcosecurity/falco-talon/internal/rules"
	"github.com/falcosecurity/falco-talon/utils"
)

const (
	Name          string = "delete"
	Category      string = "kubernetes"
	Description   string = "Delete a resource"
	Source        string = "k8saudit"
	Continue      bool   = false
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
  - namespaces
  verbs:
  - get
  - delete
- apiGroups:
  - ""
  resources:
  - pods
  verbs:
  - get
  - delete
  - list
- apiGroups:
  - apps
  resources:
  - daemonsets
  verbs:
  - get
  - delete
- apiGroups:
  - apps
  resources:
  - deployments
  verbs:
  - get
  - delete
- apiGroups:
  - apps
  resources:
  - replicasets
  verbs:
  - get
  - delete
- apiGroups:
  - apps
  resources:
  - statefulsets
  verbs:
  - get
  - delete
- apiGroups:
  - rbac.authorization.k8s.io
  resources:
  - roles
  verbs:
  - get
  - delete
- apiGroups:
  - rbac.authorization.k8s.io
  resources:
  - clusterroles
  verbs:
  - get
  - delete
- apiGroups:
  - ""
  resources:
  - configmaps
  verbs:
  - get
  - delete
- apiGroups:
  - ""
  resources:
  - secrets
  verbs:
  - get
  - delete
`
	Example string = `- action: Delete the suspicious resource
  actionner: kubernetes:delete
`
)

const namespaces string = "namespaces"

var (
	RequiredOutputFields = []string{"ka.target.resource", "ka.target.name", "ka.target.namespace"}
)

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
	return nil
}

func (a Actionner) Checks(event *events.Event, _ *rules.Action) error {
	return k8sChecks.CheckTargetExist(event)
}

func (a Actionner) Run(event *events.Event, _ *rules.Action) (utils.LogLine, *models.Data, error) {
	name := event.GetTargetName()
	resource := event.GetTargetResource()
	namespace := event.GetTargetNamespace()

	objects := map[string]string{
		"name":      name,
		"resource":  resource,
		"namespace": namespace,
	}

	client := k8s.GetClient()

	var err error

	switch resource {
	case namespaces:
		err = client.Clientset.CoreV1().Namespaces().Delete(context.Background(), name, metav1.DeleteOptions{})
	case "configmaps":
		err = client.Clientset.CoreV1().ConfigMaps(namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	case "secrets":
		err = client.Clientset.CoreV1().Secrets(namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	case "deployments":
		err = client.Clientset.AppsV1().Deployments(namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	case "daemonsets":
		err = client.Clientset.AppsV1().DaemonSets(namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	case "statefulsets":
		err = client.Clientset.AppsV1().StatefulSets(namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	case "replicasets":
		err = client.Clientset.AppsV1().ReplicaSets(namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	case "services":
		err = client.Clientset.CoreV1().Services(namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	case "serviceaccounts":
		err = client.Clientset.CoreV1().ServiceAccounts(namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	case "roles":
		err = client.Clientset.RbacV1().Roles(namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	case "clusterroles":
		err = client.Clientset.RbacV1().ClusterRoles().Delete(context.Background(), name, metav1.DeleteOptions{})
	}

	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	var output string
	if resource == namespaces {
		output = fmt.Sprintf("the %v '%v' has been deleted", strings.TrimSuffix(resource, "s"), name)
	} else {
		output = fmt.Sprintf("the %v '%v' in the namespace '%v' has been deleted", strings.TrimSuffix(resource, "s"), name, namespace)
	}

	return utils.LogLine{
		Objects: objects,
		Output:  output,
		Status:  utils.SuccessStr,
	}, nil, nil
}

func (a Actionner) CheckParameters(_ *rules.Action) error { return nil }
