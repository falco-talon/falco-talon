package tcpdump

import (
	"fmt"

	"github.com/google/uuid"

	"github.com/falcosecurity/falco-talon/internal/events"
	k8sChecks "github.com/falcosecurity/falco-talon/internal/kubernetes/checks"
	k8s "github.com/falcosecurity/falco-talon/internal/kubernetes/client"
	"github.com/falcosecurity/falco-talon/internal/models"
	"github.com/falcosecurity/falco-talon/internal/rules"
	"github.com/falcosecurity/falco-talon/utils"
)

const (
	Name          string = "tcpdump"
	Category      string = "kubernetes"
	Description   string = "Capture the network packets in a pod"
	Source        string = "syscalls"
	Continue      bool   = false
	UseContext    bool   = false
	AllowOutput   bool   = false
	RequireOutput bool   = true
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
  - update
  - patch
  - list
- apiGroups:
  - ""
  resources:
  - pods/ephemeralcontainers
  verbs:
  - patch
  - create
- apiGroups:
  - ""
  resources:
  - pods/exec
  verbs:
  - get
  - create
`
	Example string = `- action: Get logs of the pod
  actionner: kubernetes:tcpdump
  parameters:
    duration: 10
    snaplen: 1024
  output:
    target: aws:s3
    parameters:
      bucket: my-bucket
      prefix: /captures/
`
)

var (
	RequiredOutputFields = []string{"k8s.ns.name", "k8s.pod.name"}
)

type Parameters struct {
	Image    string `mapstructure:"image"`
	Duration int    `mapstructure:"duration" validate:"gte=0"`
	Snaplen  int    `mapstructure:"snaplen" validate:"gte=0"`
}

const (
	baseName        string = "falco-talon-tcpdump-"
	defaultImage    string = "issif/tcpdump:latest"
	defaultTTL      int    = 300
	defaultDuration int    = 5
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
	return Parameters{
		Duration: 20,
		Snaplen:  4096,
		Image:    "issif/tcpdump:latest",
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

	var parameters Parameters
	err := utils.DecodeParams(action.GetParameters(), &parameters)
	if err != nil {
		return utils.LogLine{
			Objects: nil,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	if parameters.Duration == 0 {
		parameters.Duration = defaultDuration
	}

	if parameters.Image == "" {
		parameters.Image = defaultImage
	}

	client := k8s.GetClient()

	pod, _ := client.GetPod(podName, namespace)
	containers := k8s.GetContainers(pod)
	if len(containers) == 0 {
		err = fmt.Errorf("no container found")
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	ephemeralContainerName := fmt.Sprintf("%v%v", baseName, uuid.NewString()[:5])

	err = client.CreateEphemeralContainer(pod, containers[0], ephemeralContainerName, parameters.Image, defaultTTL)
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	command := []string{"tee", "/tmp/talon-script.sh", ">", "/dev/null"}
	script := fmt.Sprintf("timeout %vs tcpdump -n -i any -s %v -w /tmp/tcpdump.pcap || [ $? -eq 124 ] && echo OK || exit 1", parameters.Duration, parameters.Snaplen)
	_, err = client.Exec(namespace, podName, ephemeralContainerName, command, script)
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	command = []string{"sh", "/tmp/talon-script.sh"}
	_, err = client.Exec(namespace, podName, ephemeralContainerName, command, "")
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	command = []string{"cat", "/tmp/tcpdump.pcap"}
	output, err := client.Exec(namespace, podName, ephemeralContainerName, command, "")
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	return utils.LogLine{
		Objects: objects,
		Output:  fmt.Sprintf("a tcpdump '%v' has been created", "tcpdump.pcap"),
		Status:  utils.SuccessStr,
	}, &models.Data{Name: "tcpdump.pcap", Objects: objects, Bytes: output.Bytes()}, nil
}

func (a Actionner) CheckParameters(action *rules.Action) error {
	var parameters Parameters

	err := utils.DecodeParams(action.GetParameters(), &parameters)
	if err != nil {
		return err
	}

	err = utils.ValidateStruct(parameters)
	if err != nil {
		return err
	}

	return nil
}
