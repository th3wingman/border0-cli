package util

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/borderzero/border0-go/lib/types/pointer"
	"github.com/borderzero/border0-go/types/common"
)

// GetAwsConfig builds an aws.Config given some options.
func GetAwsConfig(
	ctx context.Context,
	awsRegion string,
	creds *common.AwsCredentials,
) (*aws.Config, error) {
	opts := []func(*config.LoadOptions) error{}

	if awsRegion != "" {
		opts = append(opts, config.WithRegion(awsRegion))
	}
	if creds != nil {
		if pointer.ValueOrZero(creds.AwsProfile) != "" {
			opts = append(opts, config.WithSharedConfigProfile(*creds.AwsProfile))
		}
		if pointer.ValueOrZero(creds.AwsAccessKeyId) != "" && pointer.ValueOrZero(creds.AwsSecretAccessKey) != "" {
			opts = append(opts, config.WithCredentialsProvider(
				credentials.NewStaticCredentialsProvider(
					pointer.ValueOrZero(creds.AwsAccessKeyId),
					pointer.ValueOrZero(creds.AwsSecretAccessKey),
					pointer.ValueOrZero(creds.AwsSessionToken),
				),
			))
		}
	}

	awsConfig, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load aws config: %v", err)
	}

	return &awsConfig, nil
}
