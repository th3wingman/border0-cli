package varsource

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// interface with only the ssm API functionality we need
type ssmAPI interface {
	GetParameter(
		ctx context.Context,
		params *ssm.GetParameterInput,
		optFns ...func(*ssm.Options),
	) (*ssm.GetParameterOutput, error)
}

// returns a newly initialized AWS SSM client
func getSSMClient(ctx context.Context, optFns ...func(*config.LoadOptions) error) (ssmAPI, error) {
	cfg, err := config.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS configuration: %v", err)
	}
	return ssm.NewFromConfig(cfg), nil
}

// variableUpstream implementation for fetching values from aws ssm
type awsSSMVariableUpstream struct {
	ssmClient ssmAPI
}

// ensure awsSSMVariableUpstream implements variableUpstream at compile-time
var _ variableUpstream = (*awsSSMVariableUpstream)(nil)

// GetVariable gets a variable from AWS SSM
func (vg *awsSSMVariableUpstream) GetVariable(ctx context.Context, varDefn string) (string, error) {
	// initialize client if not yet initialized
	if vg.ssmClient == nil {
		ssmClient, err := getSSMClient(ctx)
		if err != nil {
			return "", fmt.Errorf("failed to initialize new SSM client: %v", err)
		}
		vg.ssmClient = ssmClient
	}

	// compute parameter name and fetch it via the ssm api
	parameterName := varDefn // FIXME: allow specifying non-default region
	getParameterOutput, err := vg.ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(parameterName),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		return "", fmt.Errorf("failed to get ssm parameter \"%s\": %v", parameterName, err)
	}
	if getParameterOutput.Parameter == nil || getParameterOutput.Parameter.Value == nil {
		return "", fmt.Errorf("retrieved ssm parameter \"%s\" came back with a nil value", parameterName)
	}
	return *getParameterOutput.Parameter.Value, nil
}
