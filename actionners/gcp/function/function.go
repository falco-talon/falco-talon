package functions

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"cloud.google.com/go/functions/apiv2/functionspb"
	"google.golang.org/api/idtoken"

	"github.com/falco-talon/falco-talon/internal/events"
	"github.com/falco-talon/falco-talon/internal/gcp/checks"
	"github.com/falco-talon/falco-talon/internal/gcp/client"
	"github.com/falco-talon/falco-talon/internal/models"
	"github.com/falco-talon/falco-talon/internal/rules"
	"github.com/falco-talon/falco-talon/utils"
)

const (
	Name          string = "function"
	Category      string = "gcp"
	Description   string = "Invoke a GCP function forwarding the Falco event payload"
	Source        string = "any"
	Continue      bool   = true
	AllowOutput   bool   = false
	RequireOutput bool   = false
	Permissions   string = `{
		"roles/cloudfunctions.invoker"
	}`
	Example string = `- action: Invoke GCP Cloud Function
  actionner: gcp:function
  parameters:
    gcp_function_name: sample-function
    gcp_function_location: us-central1
    gcp_function_timeout: 10
	`
)

var (
	RequiredOutputFields = []string{}
)

type Parameters struct {
	GCPFunctionName     string `mapstructure:"gcp_function_name" validate:"required"`
	GCPFunctionLocation string `mapstructure:"gcp_function_location" validate:"required"`
	GCPFunctionTimeout  int    `mapstructure:"gcp_function_timeout"`
}

type Actionner struct{}

func Register() *Actionner {
	return new(Actionner)
}

func (a Actionner) Init() error {
	return client.Init()
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
		GCPFunctionName:     "",
		GCPFunctionLocation: "us-central1", // Default location
	}
}

func (a Actionner) Checks(_ *events.Event, action *rules.Action) error {
	var parameters Parameters
	err := utils.DecodeParams(action.GetParameters(), &parameters)
	if err != nil {
		return err
	}

	return checks.CheckFunctionExist{}.Run(parameters.GCPFunctionName, parameters.GCPFunctionLocation)
}

func (a Actionner) Run(event *events.Event, action *rules.Action) (utils.LogLine, *models.Data, error) {
	gcpClient, err := client.GetGCPClient()
	if err != nil {
		return utils.LogLine{
			Objects: nil,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}
	return a.RunWithClient(gcpClient, event, action)
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

func (a Actionner) RunWithClient(c client.GCPClientAPI, event *events.Event, action *rules.Action) (utils.LogLine, *models.Data, error) {
	var parameters Parameters
	err := utils.DecodeParams(action.GetParameters(), &parameters)
	if err != nil {
		return utils.LogLine{
			Objects: nil,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	objects := map[string]string{
		"name":     parameters.GCPFunctionName,
		"location": parameters.GCPFunctionLocation,
	}

	functionName := fmt.Sprintf("projects/%s/locations/%s/functions/%s", c.ProjectID(), parameters.GCPFunctionLocation, parameters.GCPFunctionName)

	getFunctionReq := &functionspb.GetFunctionRequest{
		Name: functionName,
	}

	gcpFunctionClient, err := c.GetGcpFunctionClient(context.Background())
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	ctx := context.Background()

	function, err := gcpFunctionClient.GetFunction(ctx, getFunctionReq)
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   fmt.Sprintf("failed to get function: %v", err),
			Status:  utils.FailureStr,
		}, nil, err
	}

	if function.ServiceConfig.Uri == "" {
		return utils.LogLine{
			Objects: objects,
			Error:   "function does not have a valid URL",
			Status:  utils.FailureStr,
		}, nil, fmt.Errorf("function does not have a valid URL")
	}

	functionURL := function.ServiceConfig.Uri

	payload, err := json.Marshal(event)
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	tokenSource, err := idtoken.NewTokenSource(ctx, functionURL)
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   fmt.Sprintf("failed to create ID token source: %v", err),
			Status:  utils.FailureStr,
		}, nil, err
	}
	token, err := tokenSource.Token()
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   fmt.Sprintf("failed to obtain ID token: %v", err),
			Status:  utils.FailureStr,
		}, nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", functionURL, bytes.NewReader(payload))
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   fmt.Sprintf("failed to create HTTP request: %v", err),
			Status:  utils.FailureStr,
		}, nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	if parameters.GCPFunctionTimeout != 0 {
		httpClient := http.Client{
			Timeout: time.Duration(parameters.GCPFunctionTimeout),
		}
		c.SetHTTPClient(&httpClient)
	}

	resp, err := c.HTTPClient().Do(req)
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   fmt.Sprintf("failed to invoke function: %v", err),
			Status:  utils.FailureStr,
		}, nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   fmt.Sprintf("failed to read response body: %v", err),
			Status:  utils.FailureStr,
		}, nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return utils.LogLine{
			Objects: objects,
			Error:   fmt.Sprintf("function invocation failed with status %d: %s", resp.StatusCode, string(respBody)),
			Status:  utils.FailureStr,
		}, nil, fmt.Errorf("function invocation failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	objects["function_response"] = string(respBody)
	objects["function_response_status"] = strconv.Itoa(resp.StatusCode)

	return utils.LogLine{
		Objects: objects,
		Status:  utils.SuccessStr,
	}, nil, nil
}
