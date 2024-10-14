package s3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	aws "github.com/falcosecurity/falco-talon/internal/aws/client"
	"github.com/falcosecurity/falco-talon/internal/models"
	"github.com/falcosecurity/falco-talon/internal/rules"
	"github.com/falcosecurity/falco-talon/utils"
)

const (
	Name        string = "s3"
	Category    string = "aws"
	Description string = "Store on AWS S3"
	Permissions string = `{
  "Id": "Policy1724925555994",
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Stmt1724925537082",
      "Action": [
        "s3:PutObject",
        "s3:PutObjectAcl"
      ],
      "Effect": "Allow",
      "Resource": [
	  	"arn:aws:s3:::${BucketName}/",
	  	"arn:aws:s3:::${BucketName}/*"
	  ]
    }
  ]
}`
	Example string = `- action: Get logs of the pod
  actionner: kubernetes:download
  parameters:
    tail_lines: 200
  output:
    target: aws:s3
    parameters:
      bucket: falco-talon
      prefix: files
	  region: eu-west-1
`
)

type Parameters struct {
	Bucket string `mapstructure:"bucket" validate:"required"`
	Prefix string `mapstructure:"prefix" validate:""`
	Region string `mapstructure:"region" validate:""`
}

type Output struct{}

func Register() *Output {
	return new(Output)
}

func (o Output) Init() error { return aws.Init() }

func (o Output) Information() models.Information {
	return models.Information{
		Name:        Name,
		FullName:    Category + ":" + Name,
		Category:    Category,
		Description: Description,
		Permissions: Permissions,
		Example:     Example,
	}
}
func (o Output) Parameters() models.Parameters {
	return Parameters{
		Prefix: "",
		Bucket: "",
	}
}

func (o Output) Checks(_ *rules.Output) error { return nil }

func (o Output) Run(output *rules.Output, data *models.Data) (utils.LogLine, error) {
	var parameters Parameters
	err := utils.DecodeParams(output.GetParameters(), &parameters)
	if err != nil {
		return utils.LogLine{
			Objects: nil,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, err
	}

	parameters.Prefix = strings.TrimSuffix(parameters.Prefix, "/")
	parameters.Prefix = strings.TrimPrefix(parameters.Prefix, "/") + "/"

	var key string
	switch {
	case data.Objects["namespace"] != "" && data.Objects["pod"] != "":
		key = fmt.Sprintf("%v_%v_%v_%v", time.Now().Format("2006-01-02T15-04-05Z"), data.Objects["namespace"], data.Objects["pod"], strings.ReplaceAll(data.Name, "/", "_"))
	case data.Objects["hostname"] != "":
		key = fmt.Sprintf("%v_%v_%v", time.Now().Format("2006-01-02T15-04-05Z"), data.Objects["hostname"], strings.ReplaceAll(data.Name, "/", "_"))
	default:
		var s string
		for i, j := range data.Objects {
			if i != "file" {
				s += j + "_"
			}
		}
		key = fmt.Sprintf("%v_%v%v", time.Now().Format("2006-01-02T15-04-05Z"), s, strings.ReplaceAll(data.Name, "/", "_"))
	}

	var region string
	awsClient := aws.GetAWSClient()
	if awsClient != nil {
		region = awsClient.GetRegion()
	}
	if parameters.Region != "" {
		region = parameters.Region
	}

	objects := map[string]string{
		"file":   data.Name,
		"bucket": parameters.Bucket,
		"prefix": parameters.Prefix,
		"key":    key,
		"region": region,
	}

	if err := putObject(region, parameters.Bucket, parameters.Prefix, key, *data); err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, err
	}

	return utils.LogLine{
		Objects: objects,
		Output:  fmt.Sprintf("the file '%v' has been uploaded as the key '%v' to the bucket '%v'", data.Name, parameters.Prefix+key, parameters.Bucket),
		Status:  utils.SuccessStr,
	}, nil
}

func (o Output) CheckParameters(output *rules.Output) error {
	var parameters Parameters

	err := utils.DecodeParams(output.GetParameters(), &parameters)
	if err != nil {
		return err
	}

	err = utils.ValidateStruct(parameters)
	if err != nil {
		return err
	}

	return nil
}

func putObject(region, bucket, prefix, key string, data models.Data) error {
	client := aws.GetS3Client()
	if client == nil {
		return errors.New("client error")
	}

	ctx := context.Background()
	body := bytes.NewReader(data.Bytes)

	opts := func(o *s3.Options) {
		o.Region = region
	}

	_, err := client.PutObject(
		ctx,
		&s3.PutObjectInput{
			Bucket: awssdk.String(bucket),
			Key:    awssdk.String(prefix + key),
			Body:   body,
		},
		opts,
	)
	if err != nil {
		return err
	}
	return nil
}
