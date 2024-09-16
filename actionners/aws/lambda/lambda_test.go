package lambda_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/falco-talon/falco-talon/internal/models"

	lambdaActionner "github.com/falco-talon/falco-talon/actionners/aws/lambda"
	"github.com/falco-talon/falco-talon/internal/events"
	"github.com/falco-talon/falco-talon/internal/rules"
	"github.com/falco-talon/falco-talon/utils"
)

// MockLambdaClient is a mock implementation of the LambdaClientAPI interface
type MockLambdaClient struct {
	mock.Mock
}

func (m *MockLambdaClient) Invoke(ctx context.Context, input *lambda.InvokeInput, _ ...func(*lambda.Options)) (*lambda.InvokeOutput, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*lambda.InvokeOutput), args.Error(1)
}

func (m *MockLambdaClient) GetFunction(_ context.Context, _ *lambda.GetFunctionInput, _ ...func(*lambda.Options)) (*lambda.GetFunctionOutput, error) {
	return &lambda.GetFunctionOutput{}, nil
}

type lambdaTestCase struct {
	name             string
	event            *events.Event
	action           *rules.Action
	mockInvokeOutput *lambda.InvokeOutput
	mockInvokeError  error
	expectedData     *models.Data
	expectedLogLine  utils.LogLine
	expectError      bool
}

var lambdaTestCases = []lambdaTestCase{
	{
		name: "Successful Invocation",
		event: &events.Event{
			TraceID: "123",
			Source:  "falco-talon",
			Rule:    "sample-rule",
		},
		action: &rules.Action{
			Parameters: map[string]interface{}{
				"aws_lambda_name":             "sample-function",
				"aws_lambda_alias_or_version": "$LATEST",
				"aws_lambda_invocation_type":  "RequestResponse",
			},
		},
		mockInvokeOutput: &lambda.InvokeOutput{
			StatusCode: 200,
			Payload:    []byte(`{"message":"success"}`),
		},
		mockInvokeError: nil,
		expectedLogLine: utils.LogLine{
			Status:  utils.SuccessStr,
			Output:  "{\"message\":\"success\"}",
			Objects: map[string]string{"name": "sample-function", "version": "$LATEST"},
		},
		expectedData: nil,
		expectError:  false,
	},
	{
		name: "Successful invocation of custom version",
		event: &events.Event{
			TraceID: "123",
			Source:  "falco-talon",
			Rule:    "sample-rule",
		},
		action: &rules.Action{
			Parameters: map[string]interface{}{
				"aws_lambda_name":             "sample-function",
				"aws_lambda_alias_or_version": "1",
				"aws_lambda_invocation_type":  "RequestResponse",
			},
		},
		mockInvokeOutput: &lambda.InvokeOutput{
			StatusCode: 200,
			Payload:    []byte(`{"message":"success"}`),
		},
		mockInvokeError: nil,
		expectedLogLine: utils.LogLine{
			Status:  utils.SuccessStr,
			Output:  "{\"message\":\"success\"}",
			Objects: map[string]string{"name": "sample-function", "version": "1"},
		},
		expectedData: nil,
		expectError:  false,
	},
	{
		name: "Successful invocation of event",
		event: &events.Event{
			TraceID: "123",
			Source:  "falco-talon",
			Rule:    "sample-rule",
		},
		action: &rules.Action{
			Parameters: map[string]interface{}{
				"aws_lambda_name":             "sample-function",
				"aws_lambda_alias_or_version": "1",
				"aws_lambda_invocation_type":  " Event",
			},
		},
		mockInvokeOutput: &lambda.InvokeOutput{
			StatusCode: 200,
			Payload:    []byte(`{"message":"success"}`),
		},
		mockInvokeError: nil,
		expectedLogLine: utils.LogLine{
			Status:  utils.SuccessStr,
			Output:  "{\"message\":\"success\"}",
			Objects: map[string]string{"name": "sample-function", "version": "1"},
		},
		expectedData: nil,
		expectError:  false,
	},
	{
		name:  "Invocation Error",
		event: &events.Event{}, // Provide event data as needed
		action: &rules.Action{
			Parameters: map[string]interface{}{
				"aws_lambda_name":             "sample-function",
				"aws_lambda_alias_or_version": "$LATEST",
				"aws_lambda_invocation_type":  "RequestResponse",
			},
		},
		mockInvokeOutput: new(lambda.InvokeOutput),
		mockInvokeError:  errors.New("invoke error"),
		expectedLogLine: utils.LogLine{
			Status:  utils.FailureStr,
			Error:   "invoke error",
			Objects: map[string]string{"name": "sample-function", "version": "$LATEST"},
		},
		expectedData: nil,
		expectError:  true,
	},
}

func TestRunWithClient(t *testing.T) {
	for _, tt := range lambdaTestCases {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := new(MockLambdaClient)

			lambdaName := tt.action.Parameters["aws_lambda_name"].(string)
			lambdaVersion := tt.action.Parameters["aws_lambda_alias_or_version"].(string)
			lambdaInvocationType := tt.action.Parameters["aws_lambda_invocation_type"].(string)
			expectedPayload, _ := json.Marshal(tt.event)

			mockClient.On("Invoke", mock.Anything, &lambda.InvokeInput{
				FunctionName:   &lambdaName,
				InvocationType: lambdaActionner.GetInvocationType(lambdaInvocationType),
				Payload:        expectedPayload,
				Qualifier:      lambdaActionner.GetLambdaVersion(&lambdaVersion),
			}).Return(tt.mockInvokeOutput, tt.mockInvokeError)

			actionner := lambdaActionner.Actionner{}

			logLine, data, err := actionner.RunWithClient(mockClient, tt.event, tt.action)

			if tt.expectError {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedLogLine.Status, logLine.Status)
				assert.Contains(t, logLine.Error, tt.expectedLogLine.Error)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedLogLine.Status, logLine.Status)
				assert.Equal(t, tt.expectedLogLine.Output, logLine.Output)
				assert.Equal(t, tt.expectedLogLine.Objects, logLine.Objects)
			}

			assert.Equal(t, tt.expectedData, data)

			mockClient.AssertExpectations(t)
		})
	}
}
