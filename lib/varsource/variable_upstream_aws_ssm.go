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

// variableUpstream implementation for fetching values from aws ssm
type awsSSMVariableUpstream struct{}

// ensure awsSSMVariableUpstream implements variableUpstream at compile-time
var _ variableUpstream = (*awsSSMVariableUpstream)(nil)

// GetVariable gets a variable from AWS SSM
func (vg *awsSSMVariableUpstream) GetVariable(ctx context.Context, varDefn string) (string, error) {
	variable, overrides, err := parseVariableDefinitionParts(varDefn)
	if err != nil {
		return "", err
	}
	varDefn = variable

	opts := []func(*config.LoadOptions) error{
		config.WithEC2IMDSRegion(),
	}
	if region, ok := overrides["aws_region"]; ok {
		opts = append(opts, config.WithRegion(region))
	}
	if profile, ok := overrides["aws_profile"]; ok {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return "", fmt.Errorf("failed to load AWS configuration: %v", err)
	}
	ssmClient := ssm.NewFromConfig(cfg)

	// compute parameter name and fetch it via the ssm api
	parameterName := varDefn
	getParameterOutput, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
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
