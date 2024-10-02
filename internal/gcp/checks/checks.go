package checks

import (
	"context"

	"cloud.google.com/go/functions/apiv2/functionspb"

	"github.com/falco-talon/falco-talon/internal/gcp/client"
)

type CheckFunctionExist struct{}

func (c CheckFunctionExist) Name() string {
	return "CheckFunctionExist"
}

func (c CheckFunctionExist) Run(functionName, location string) error {
	gcpClient, err := client.GetGCPClient()
	if err != nil {
		return err
	}

	functionClient, err := gcpClient.GetGcpFunctionClient(context.Background())
	if err != nil {
		return err
	}

	// Create a request to get function information
	req := &functionspb.GetFunctionRequest{
		Name: "projects/" + gcpClient.ProjectID() + "/locations/" + location + "/functions/" + functionName,
	}

	_, err = functionClient.GetFunction(context.Background(), req)
	if err != nil {
		return err
	}

	return nil
}
