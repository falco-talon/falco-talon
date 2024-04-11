package checks

import (
	"errors"
	"net"
	"strconv"

	"github.com/falco-talon/falco-talon/internal/rules"

	"github.com/falco-talon/falco-talon/internal/events"
	kubernetes "github.com/falco-talon/falco-talon/internal/kubernetes/client"
)

func CheckPodName(event *events.Event, _ *rules.Action) error {
	pod := event.GetPodName()
	if pod == "" {
		return errors.New("missing pod name")
	}
	return nil
}

func CheckNamespace(event *events.Event, _ *rules.Action) error {
	namespace := event.GetNamespaceName()
	if namespace == "" {
		return errors.New("missing namespace")
	}
	return nil
}

func CheckPodExist(event *events.Event, _ *rules.Action) error {
	if err := CheckPodName(event, nil); err != nil {
		return err
	}
	if err := CheckNamespace(event, nil); err != nil {
		return err
	}

	client := kubernetes.GetClient()
	if client == nil {
		return errors.New("wrong k8s client")
	}
	_, err := client.GetPod(event.GetPodName(), event.GetNamespaceName())
	return err
}

func CheckTargetName(event *events.Event, _ *rules.Action) error {
	if event.OutputFields["ka.target.name"] == nil {
		return errors.New("missing target name (ka.target.name)")
	}
	return nil
}

func CheckTargetResource(event *events.Event, _ *rules.Action) error {
	if event.OutputFields["ka.target.resource"] == nil {
		return errors.New("missing target resource (ka.target.resource)")
	}
	return nil
}

func CheckTargetNamespace(event *events.Event, _ *rules.Action) error {
	if event.OutputFields["ka.target.resource"] == "namespaces" {
		return nil
	}
	if event.OutputFields["ka.target.namespace"] == nil {
		return errors.New("missing target namespace (ka.target.namespace)")
	}
	return nil
}

func CheckRemoteIP(event *events.Event, _ *rules.Action) error {
	if event.OutputFields["fd.sip"] == nil &&
		event.OutputFields["fd.rip"] == nil {
		return errors.New("missing IP field(s) (fd.sip or fd.rip)")
	}
	if event.OutputFields["fd.sip"] != nil {
		if net.ParseIP(event.OutputFields["fd.sip"].(string)) == nil {
			return errors.New("wrong value for fd.sip")
		}
	}
	if event.OutputFields["fd.rip"] != nil {
		if net.ParseIP(event.OutputFields["fd.rip"].(string)) == nil {
			return errors.New("wrong value for fd.rip")
		}
	}

	return nil
}

func CheckRemotePort(event *events.Event, _ *rules.Action) error {
	if event.OutputFields["fd.sport"] == nil &&
		event.OutputFields["fd.rport"] == nil {
		return errors.New("missing Port field(s) (fd.sport or fd.port)")
	}
	if event.OutputFields["fd.sport"] != nil {
		if _, err := strconv.ParseUint(event.GetRemotePort(), 0, 16); err != nil {
			return errors.New("wrong value for fd.sport")
		}
	}
	if event.OutputFields["fd.rport"] != nil {
		if _, err := strconv.ParseUint(event.GetRemotePort(), 0, 16); err != nil {
			return errors.New("wrong value for fd.rport")
		}
	}

	return nil
}

func CheckTargetExist(event *events.Event, _ *rules.Action) error {
	if err := CheckTargetResource(event, nil); err != nil {
		return err
	}
	if err := CheckTargetName(event, nil); err != nil {
		return err
	}
	if err := CheckTargetNamespace(event, nil); err != nil {
		return err
	}

	client := kubernetes.GetClient()
	if client == nil {
		return errors.New("wrong k8s client")
	}
	_, err := client.GetTarget(event.GetTargetResource(), event.GetTargetName(), event.GetTargetNamespace())
	return err
}
