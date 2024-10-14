package client

import (
	"context"
	"sync"

	"github.com/falcosecurity/falco-talon/configuration"
	"github.com/falcosecurity/falco-talon/utils"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type AWSClient struct {
	lambdaClient *lambda.Client
	imdsClient   *imds.Client
	s3Client     *s3.Client
	cfg          aws.Config
}

var (
	awsClient *AWSClient
	once      sync.Once
)

func Init() error {
	if awsClient != nil {
		return nil
	}

	var initErr error

	once.Do(func() {
		awsConfig := configuration.GetConfiguration().AwsConfig
		var cfg aws.Config
		var err error

		if awsConfig.AccessKey != "" && awsConfig.SecretKey != "" && awsConfig.Region != "" {
			cfg, err = config.LoadDefaultConfig(
				context.TODO(),
				config.WithRegion(awsConfig.Region),
				config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(awsConfig.AccessKey, awsConfig.SecretKey, "")),
			)
		} else {
			cfg, err = config.LoadDefaultConfig(context.TODO())
		}
		if err != nil {
			initErr = err
			return
		}

		if awsConfig.RoleArn != "" {
			stsClient := sts.NewFromConfig(cfg)
			assumeRoleOptions := func(o *stscreds.AssumeRoleOptions) {
				if awsConfig.ExternalID != "" {
					o.ExternalID = aws.String(awsConfig.ExternalID)
				}
			}
			provider := stscreds.NewAssumeRoleProvider(stsClient, awsConfig.RoleArn, assumeRoleOptions)
			cfg.Credentials = aws.NewCredentialsCache(provider)
		}

		// Perform a dry run to validate credentials
		stsClient := sts.NewFromConfig(cfg)
		_, err = stsClient.GetCallerIdentity(context.TODO(), &sts.GetCallerIdentityInput{})
		if err != nil {
			initErr = err
			return
		}

		awsClient = &AWSClient{
			cfg: cfg,
		}

		if initErr == nil {
			utils.PrintLog("info", utils.LogLine{Message: "init", Category: "aws", Status: utils.SuccessStr})
		}
	})

	return initErr
}

func GetAWSClient() *AWSClient {
	return awsClient
}

func GetLambdaClient() *lambda.Client {
	c := GetAWSClient()
	if c == nil {
		return nil
	}
	if c.lambdaClient == nil {
		c.lambdaClient = lambda.NewFromConfig(c.cfg)
	}
	return c.lambdaClient
}

func GetImdsClient() *imds.Client {
	c := GetAWSClient()
	if c == nil {
		return nil
	}
	if c.imdsClient == nil {
		c.imdsClient = imds.NewFromConfig(c.cfg)
	}
	return GetAWSClient().imdsClient
}

func GetS3Client() *s3.Client {
	c := GetAWSClient()
	if c == nil {
		return nil
	}
	if c.s3Client == nil {
		c.s3Client = s3.NewFromConfig(c.cfg)
	}
	return c.s3Client
}

func (client AWSClient) GetRegion() string {
	return client.cfg.Region
}
