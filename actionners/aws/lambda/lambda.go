package lambda

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"

	awsChecks "github.com/falcosecurity/falco-talon/internal/aws/checks"
	aws "github.com/falcosecurity/falco-talon/internal/aws/client"
	"github.com/falcosecurity/falco-talon/internal/events"
	"github.com/falcosecurity/falco-talon/internal/models"
	"github.com/falcosecurity/falco-talon/internal/rules"
	"github.com/falcosecurity/falco-talon/utils"
)

const (
	Name          string = "lambda"
	Category      string = "aws"
	Description   string = "Invoke an AWS lambda function forwarding the Falco event payload"
	Source        string = "any"
	Continue      bool   = true
	UseContext    bool   = true
	AllowOutput   bool   = false
	RequireOutput bool   = false
	Permissions   string = `{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowInvokeLambdaFunction",
            "Effect": "Allow",
            "Action": "lambda:InvokeFunction",
            "Resource": "arn:aws:lambda:<region>:<account_id>:function:<function_name>"
        },
        {
            "Sid": "AllowSTSGetCallerIdentity",
            "Effect": "Allow",
            "Action": "sts:GetCallerIdentity"
        }
    ]
}
`
	Example string = `- action: Invoke Lambda function
  actionner: aws:lambda
  parameters:
    aws_lambda_name: sample-function
    aws_lambda_alias_or_version: $LATEST
    aws_lambda_invocation_type: RequestResponse
`
)

var (
	RequiredOutputFields = []string{}
)

type Parameters struct {
	AWSLambdaName           string `mapstructure:"aws_lambda_name" validate:"required"`
	AWSLambdaAliasOrVersion string `mapstructure:"aws_lambda_alias_or_version" validate:"omitempty"`
	AWSLambdaInvocationType string `mapstructure:"aws_lambda_invocation_type" validate:"omitempty,oneof=RequestResponse Event DryRun"`
}

type Actionner struct{}

func Register() *Actionner {
	return new(Actionner)
}

func (a Actionner) Init() error {
	return aws.Init()
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
		AWSLambdaName:           "",
		AWSLambdaAliasOrVersion: "$LATEST",
		AWSLambdaInvocationType: "RequestResponse",
	}
}

func (a Actionner) Checks(_ *events.Event, action *rules.Action) error {
	var parameters Parameters
	err := utils.DecodeParams(action.GetParameters(), &parameters)
	if err != nil {
		return err
	}
	return awsChecks.CheckLambdaExist.Run(awsChecks.CheckLambdaExist{}, parameters.AWSLambdaName)
}

func (a Actionner) Run(event *events.Event, action *rules.Action) (utils.LogLine, *models.Data, error) {
	lambdaClient := aws.GetLambdaClient()

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
		"name":    parameters.AWSLambdaName,
		"version": parameters.AWSLambdaAliasOrVersion,
	}

	payload, err := json.Marshal(event)
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	input := &lambda.InvokeInput{
		FunctionName:   &parameters.AWSLambdaName,
		ClientContext:  nil,
		InvocationType: getInvocationType(parameters.AWSLambdaInvocationType),
		Payload:        payload,
		Qualifier:      getLambdaVersion(&parameters.AWSLambdaAliasOrVersion),
	}

	lambdaOutput, err := lambdaClient.Invoke(context.Background(), input)
	if err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, nil, err
	}

	status := utils.SuccessStr
	if lambdaOutput.StatusCode != http.StatusOK && lambdaOutput.StatusCode != http.StatusNoContent {
		status = utils.FailureStr
	}
	return utils.LogLine{
		Objects: objects,
		Output:  string(lambdaOutput.Payload),
		Status:  status,
	}, nil, nil
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

func getInvocationType(invocationType string) types.InvocationType {
	switch invocationType {
	case "RequestResponse":
		return types.InvocationTypeRequestResponse
	case "Event":
		return types.InvocationTypeEvent
	case "DryRun":
		return types.InvocationTypeDryRun
	default:
		return types.InvocationTypeRequestResponse // Default
	}
}

func getLambdaVersion(qualifier *string) *string {
	if qualifier == nil || *qualifier == "" {
		defaultVal := "$LATEST"
		return &defaultVal
	}
	return qualifier
}
