package k8sevents

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	textTemplate "text/template"

	kubernetes "github.com/falcosecurity/falco-talon/internal/kubernetes/client"
	"github.com/falcosecurity/falco-talon/internal/models"
	"github.com/falcosecurity/falco-talon/utils"
)

const (
	Name        string = "k8sevents"
	Description string = "Create a Kubernetes Event"
	Permissions string = `- apiGroups:
  - ""
  resources:
  - events
  verbs:
  - get
  - update
  - patch
  - create
`
	Example string = ``
)

const (
	falcoTalon string = "falco-talon"
	defaultStr string = "default"
)

type Parameters struct{}

var plaintextTmpl = `Status: {{ .Status }}
Message: {{ .Message }}
{{- if .Rule }}
Rule: {{ .Rule }}
{{- end }}
{{- if .Action }}
Action: {{ .Action }}
{{- end }}
{{- if .Actionner }}
Actionner: {{ .Actionner }}
{{- end }}
{{- if .Event }}
Event: {{ .Event }}
{{- end }}
{{- range $key, $value := .Objects }}
{{ $key }}: {{ $value }}
{{- end }}
{{- if .Error }}
Error: {{ .Error }}
{{- end }}
{{- if .Result }}
Result: {{ .Result }}
{{- end }}
{{- if .Output }}
Output: {{ .Output }}
{{- end }}
{{- if .OutputTarget }}
OutputTarget: {{ .OutputTarget }}
{{- end }}
TraceID: {{ .TraceID }}
`

type Notifier struct{}

func Register() *Notifier {
	return new(Notifier)
}

func (n Notifier) Init(_ map[string]any) error { return nil }

func (n Notifier) Information() models.Information {
	return models.Information{
		Name:        Name,
		Description: Description,
		Permissions: Permissions,
		Example:     Example,
	}
}
func (n Notifier) Parameters() models.Parameters { return Parameters{} }

func (n Notifier) Run(log utils.LogLine) error {
	var err error
	var message string
	ttmpl := textTemplate.New("message")
	ttmpl, err = ttmpl.Parse(plaintextTmpl)
	if err != nil {
		return err
	}
	var messageBuf bytes.Buffer
	err = ttmpl.Execute(&messageBuf, log)
	if err != nil {
		return err
	}

	message = utils.RemoveSpecialCharacters(messageBuf.String())

	if len(message) > 1024 {
		message = message[:1024]
	}

	client := kubernetes.GetClient()

	namespace := log.Objects["namespace"]
	ns, err := client.GetNamespace(namespace)
	if err != nil {
		namespace = defaultStr
	}
	if ns == nil {
		namespace = defaultStr
	}

	var reason string
	if log.Actionner != "" {
		reason = log.Actionner
	}
	if log.OutputTarget != "" {
		reason = log.OutputTarget
	}

	k8sevent := &corev1.Event{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Event",
			APIVersion: "v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: falcoTalon + "-",
		},
		InvolvedObject: corev1.ObjectReference{
			Kind:      "Pod",
			Namespace: namespace,
			Name:      log.Objects["pod"],
		},
		Reason:  fmt.Sprintf("%v:%v:%v:%v", falcoTalon, log.Message, reason, log.Status),
		Message: strings.ReplaceAll(message, `'`, `"`),
		Source: corev1.EventSource{
			Component: falcoTalon,
		},
		Type:                corev1.EventTypeNormal,
		EventTime:           metav1.NowMicro(),
		ReportingController: "falcosecurity.org/" + falcoTalon,
		ReportingInstance:   falcoTalon,
		Action:              reason,
	}
	_, err = client.Clientset.CoreV1().Events(namespace).Create(context.TODO(), k8sevent, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}
