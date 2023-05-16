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

// returns a newly initialized AWS Secrets Manager client
func getSecretsManagerClient(ctx context.Context, optFns ...func(*config.LoadOptions) error) (secretsmanagerAPI, error) {
	cfg, err := config.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS configuration: %v", err)
	}
	return secretsmanager.NewFromConfig(cfg), nil
}

// variableUpstream implementation for fetching values from aws secrets manager
type awsSecretsmanagerVariableUpstream struct {
	secretsmanagerClient secretsmanagerAPI
}

// ensure awsSecretsmanagerVariableUpstream implements variableUpstream at compile-time
var _ variableUpstream = (*awsSecretsmanagerVariableUpstream)(nil)

// GetVariable gets a variable from AWS Secrets Manager
func (vg *awsSecretsmanagerVariableUpstream) GetVariable(ctx context.Context, varDefn string) (string, error) {
	// initialize client if not yet initialized
	if vg.secretsmanagerClient == nil {
		secretsManagerClient, err := getSecretsManagerClient(ctx)
		if err != nil {
			return "", fmt.Errorf("failed to initialize new SSM client: %v", err)
		}
		vg.secretsmanagerClient = secretsManagerClient
	}

	// compute secret id and fetch it via the ssm api
	secretID := varDefn // FIXME: allow specifying non-default region
	getSecretValueOutput, err := vg.secretsmanagerClient.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
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
