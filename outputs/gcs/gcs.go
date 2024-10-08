package gcs

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/falco-talon/falco-talon/internal/gcp/client"
	"github.com/falco-talon/falco-talon/internal/models"
	"github.com/falco-talon/falco-talon/internal/rules"
	"github.com/falco-talon/falco-talon/utils"
)

const (
	Name        string = "gcs"
	Category    string = "gcp"
	Description string = "Store on GCP Cloud Storage"
	Permissions string = `Required IAM permissions for GCS:
- storage.objects.create
- storage.objects.get
- storage.objects.list
- storage.objects.update`
	Example string = `- action: Get logs of the pod
  actionner: kubernetes:download
  parameters:
    tail_lines: 200
  output:
    target: gcp:gcs
    parameters:
      bucket: falco-talon
      prefix: files
`
)

type Parameters struct {
	Bucket string `mapstructure:"bucket" validate:"required"`
	Prefix string `mapstructure:"prefix" validate:""`
}

type Output struct{}

func Register() *Output {
	return new(Output)
}

func (o Output) Init() error {
	return client.Init()
}

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
	gcpClient, err := client.GetGCPClient()
	if err != nil {
		return utils.LogLine{
			Objects: nil,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, err
	}

	storageClient, err := gcpClient.GetStorageClient(context.Background())
	if err != nil {
		return utils.LogLine{
			Objects: nil,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, err
	}
	return o.RunWithClient(storageClient, output, data)
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

func (o Output) RunWithClient(client client.GcpGcsAPI, output *rules.Output, data *models.Data) (utils.LogLine, error) {
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
	if parameters.Prefix != "" {
		parameters.Prefix += "/"
	}

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

	ctx := context.Background()

	if err := putObject(ctx, client, parameters.Bucket, parameters.Prefix, key, *data); err != nil {
		return utils.LogLine{
			Objects: objects,
			Error:   err.Error(),
			Status:  utils.FailureStr,
		}, err
	}

	return utils.LogLine{
		Objects: objects,
		Output:  fmt.Sprintf("The file '%v' has been uploaded as the key '%v' to the bucket '%v'", data.Name, parameters.Prefix+key, parameters.Bucket),
		Status:  utils.SuccessStr,
	}, nil
}

func putObject(ctx context.Context, storageClient client.GcpGcsAPI, bucketName, prefix, key string, data models.Data) error {
	bucket := storageClient.Bucket(bucketName)
	objectName := prefix + key
	wc := bucket.Object(objectName).NewWriter(ctx)
	defer wc.Close()

	if _, err := wc.Write(data.Bytes); err != nil {
		return err
	}
	return nil
}
