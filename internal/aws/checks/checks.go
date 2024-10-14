package checks

import (
	"context"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"

	aws "github.com/falcosecurity/falco-talon/internal/aws/client"
)

type CheckLambdaExist struct{}

func (c CheckLambdaExist) Name() string {
	return "CheckLambdaExist"
}

func (c CheckLambdaExist) Run(functionName string) error {
	client := aws.GetLambdaClient()

	_, err := client.GetFunction(context.Background(), &lambda.GetFunctionInput{
		FunctionName: awssdk.String(functionName),
	})
	if err != nil {
		return err
	}
	return nil
}

func (c CheckLambdaExist) ListPermissions() string {
	return "permissions"
}
