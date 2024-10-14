package minio

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	miniosdk "github.com/minio/minio-go/v7"

	minio "github.com/falcosecurity/falco-talon/internal/minio/client"
	"github.com/falcosecurity/falco-talon/internal/models"
	"github.com/falcosecurity/falco-talon/internal/rules"
	"github.com/falcosecurity/falco-talon/utils"
)

const (
	Name        string = "s3"
	Category    string = "minio"
	Description string = "Store on Minio"
	Permissions string = ``
	Example     string = `- action: Get logs of the pod
  actionner: kubernetes:download
  parameters:
    tail_lines: 200
  output:
    target: minio:s3
    parameters:
      bucket: falco-talon
      prefix: /files
`
)

const (
	defaultContentType string = "text/plain; charset=UTF-8"
)

type Parameters struct {
	Bucket string `mapstructure:"bucket" validate:"required"`
	Prefix string `mapstructure:"prefix" validate:""`
}

type Output struct{}

func Register() *Output {
	return new(Output)
}

func (o Output) Init() error { return minio.Init() }

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

func (o Output) Checks(output *rules.Output) error {
	var parameters Parameters
	err := utils.DecodeParams(output.GetParameters(), &parameters)
	if err != nil {
		return err
	}

	ctx := context.Background()
	exist, err := minio.GetClient().BucketExists(ctx, parameters.Bucket)
	if err != nil {
		return err
	}
	if !exist {
		return fmt.Errorf("the bucket '%v' does not exist", parameters.Bucket)
	}

	return nil
}

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

	parameters.Prefix = strings.TrimSuffix(parameters.Prefix, "/") + "/"

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

	objects := map[string]string{
		"file":   data.Name,
		"bucket": parameters.Bucket,
		"prefix": parameters.Prefix,
		"key":    key,
	}

	if err := putObject(parameters.Bucket, parameters.Prefix, key, *data); err != nil {
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

func putObject(bucket, prefix, key string, data models.Data) error {
	client := minio.GetClient()
	if client == nil {
		return errors.New("client error")
	}

	ctx := context.Background()
	body := bytes.NewReader(data.Bytes)

	_, err := client.PutObject(ctx, bucket, prefix+key, body, int64(len(data.Bytes)), miniosdk.PutObjectOptions{ContentType: defaultContentType})
	if err != nil {
		return err
	}
	return nil
}
