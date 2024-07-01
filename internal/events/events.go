package events

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
)

type Event struct {
	TraceID      string
	Output       string                 `json:"output"`
	Priority     string                 `json:"priority"`
	Rule         string                 `json:"rule"`
	Hostname     string                 `json:"hostname"`
	Time         time.Time              `json:"time"`
	Source       string                 `json:"source"`
	OutputFields map[string]interface{} `json:"output_fields"`
	Context      map[string]interface{} `json:"context"`
	Tags         []interface{}          `json:"tags"`
}

const (
	trimPrefix = "(?i)^\\d{2}:\\d{2}:\\d{2}\\.\\d{9}\\:\\ (Debug|Info|Informational|Notice|Warning|Error|Critical|Alert|Emergency)"
)

var regTrimPrefix *regexp.Regexp

func init() {
	regTrimPrefix = regexp.MustCompile(trimPrefix)
}

func DecodeEvent(payload io.Reader) (*Event, error) {
	var event Event

	d := json.NewDecoder(payload)
	d.UseNumber()

	err := d.Decode(&event)
	if err != nil {
		return &Event{}, err
	}

	if event.Source == "" {
		event.Source = "syscall"
	}

	event.Output = regTrimPrefix.ReplaceAllString(event.Output, "")
	event.Output = strings.TrimPrefix(event.Output, " ")

	return &event, nil
}

func (event *Event) GetPodName() string {
	if event.OutputFields["k8s.pod.name"] != nil {
		return event.OutputFields["k8s.pod.name"].(string)
	}
	return ""
}

func (event *Event) GetNamespaceName() string {
	if event.OutputFields["k8s.ns.name"] != nil {
		return event.OutputFields["k8s.ns.name"].(string)
	}
	return ""
}

func (event *Event) GetHostname() string {
	return event.Hostname
}

func (event *Event) GetTargetName() string {
	if event.OutputFields["ka.target.name"] != nil {
		return event.OutputFields["ka.target.name"].(string)
	}
	return ""
}

func (event *Event) GetTargetNamespace() string {
	if event.OutputFields["ka.target.namespace"] != nil {
		return event.OutputFields["ka.target.namespace"].(string)
	}
	return ""
}

func (event *Event) GetTargetResource() string {
	if event.OutputFields["ka.target.resource"] != nil {
		return event.OutputFields["ka.target.resource"].(string)
	}
	return ""
}

func (event *Event) GetRemoteIP() string {
	if i := event.OutputFields["fd.rip"]; i != nil {
		return i.(string)
	}
	if i := event.OutputFields["fd.sip"]; i != nil {
		return i.(string)
	}
	return ""
}

func (event *Event) GetRemotePort() string {
	if i := event.OutputFields["fd.rport"]; i != nil {
		return i.(string)
	}
	if i := event.OutputFields["fd.sport"]; i != nil {
		return i.(string)
	}
	return ""
}

func (event *Event) GetRemoteProtocol() string {
	if i := event.OutputFields["fd.rproto"]; i != nil {
		return i.(string)
	}
	if i := event.OutputFields["fd.rproto"]; i != nil {
		return i.(string)
	}
	return ""
}

func (event *Event) AddContext(elements map[string]interface{}) {
	if event.Context == nil {
		event.Context = make(map[string]interface{})
	}
	if len(elements) == 0 {
		return
	}
	for i, j := range elements {
		if fmt.Sprintf("%v", j) == "" {
			delete(elements, i)
		}
	}
	for i, j := range elements {
		event.Context[i] = j
	}
}

func (event *Event) ExportEnvVars() {
	for i, j := range event.OutputFields {
		key := strings.ReplaceAll(strings.ToUpper(i), ".", "_")
		key = strings.ReplaceAll(key, "[", "_")
		key = strings.ReplaceAll(key, "]", "")
		os.Setenv(key, fmt.Sprintf("%v", j))
	}
	for i, j := range event.Context {
		key := strings.ReplaceAll(strings.ToUpper(i), ".", "_")
		os.Setenv(key, fmt.Sprintf("%v", j))
	}
	os.Setenv("PRIORITY", event.Priority)
	os.Setenv("HOSTNAME", event.Hostname)
	os.Setenv("RULE", event.Rule)
	os.Setenv("SOURCE", event.Source)
	var tags []string
	for _, i := range event.Tags {
		tags = append(tags, fmt.Sprintf("%v", i))
	}
	os.Setenv("TAGS", strings.Join(tags, ","))
}

func (event *Event) String() string {
	e, _ := json.Marshal(*event)
	return string(e)
}
