package varsource

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// interface with only the secretsmanager API functionality we need
type secretsmanagerAPI interface {
	GetSecretValue(
		ctx context.Context,
		params *secretsmanager.GetSecretValueInput,
		optFns ...func(*secretsmanager.Options),
	) (*secretsmanager.GetSecretValueOutput, error)
}

// variableUpstream implementation for fetching values from aws secrets manager
type awsSecretsmanagerVariableUpstream struct{}

// ensure awsSecretsmanagerVariableUpstream implements variableUpstream at compile-time
var _ variableUpstream = (*awsSecretsmanagerVariableUpstream)(nil)

// GetVariable gets a variable from AWS Secrets Manager
func (vg *awsSecretsmanagerVariableUpstream) GetVariable(ctx context.Context, varDefn string) (string, error) {
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
	secretsManagerClient := secretsmanager.NewFromConfig(cfg)

	// compute secret id and fetch it via the ssm api
	secretID := varDefn
	getSecretValueOutput, err := secretsManagerClient.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretID),
	})
	if err != nil {
		return "", fmt.Errorf("failed to get secretsmanager secret \"%s\": %v", secretID, err)
	}
	if getSecretValueOutput.SecretString == nil {
		return "", fmt.Errorf("retrieved secretsmanager secret \"%s\" came back with a nil value", secretID)
	}
	return *getSecretValueOutput.SecretString, nil
}
