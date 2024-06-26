package aws

import (
	"context"

	aws "github.com/falco-talon/falco-talon/internal/aws/client"
	"github.com/falco-talon/falco-talon/internal/events"
)

func GetAwsContext(_ *events.Event) (map[string]interface{}, error) {
	imdsClient := aws.GetImdsClient()

	info, err := imdsClient.GetIAMInfo(context.Background(), nil)
	if err != nil {
		return nil, err
	}

	region, err := imdsClient.GetRegion(context.Background(), nil)
	if err != nil {
		return nil, err
	}

	elements := make(map[string]interface{})
	elements["aws.instance_profile_arn"] = info.InstanceProfileArn
	elements["aws.instance_profile_id"] = info.InstanceProfileID
	elements["aws.region"] = region.Region
	return elements, nil
}
