package varsource

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	cache "github.com/Code-Hex/go-generics-cache"
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
type awsSecretsmanagerVariableUpstream struct {
	cache        *cache.Cache[string, *secretsmanager.GetSecretValueOutput]
	cacheItemTTL time.Duration
}

// ensure awsSecretsmanagerVariableUpstream implements variableUpstream at compile-time
var _ variableUpstream = (*awsSecretsmanagerVariableUpstream)(nil)

// GetVariable gets a variable from AWS Secrets Manager
func (vg *awsSecretsmanagerVariableUpstream) GetVariable(ctx context.Context, varDefn string) (string, error) {
	variable, overrides, err := parseVariableDefinitionParts(varDefn)
	if err != nil {
		return "", err
	}
	secretID := variable
	cacheKey := varDefn

	opts := []func(*config.LoadOptions) error{
		config.WithEC2IMDSRegion(),
	}
	if region, ok := overrides["aws_region"]; ok {
		cacheKey = fmt.Sprintf("%s-%s", region, cacheKey)
		opts = append(opts, config.WithRegion(region))
	}
	if profile, ok := overrides["aws_profile"]; ok {
		cacheKey = fmt.Sprintf("%s-%s", profile, cacheKey)
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}

	getSecretValueOutput, ok := vg.cache.Get(cacheKey)
	if !ok {
		cfg, err := config.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			return "", fmt.Errorf("failed to load AWS configuration: %v", err)
		}
		getSecretValueOutput, err = secretsmanager.NewFromConfig(cfg).
			GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(secretID)})
		if err != nil {
			return "", fmt.Errorf("failed to get secretsmanager secret \"%s\": %v", secretID, err)
		}
		if getSecretValueOutput.SecretString == nil {
			return "", fmt.Errorf("retrieved secretsmanager secret \"%s\" came back with a nil value", secretID)
		}
		vg.cache.Set(cacheKey, getSecretValueOutput, cache.WithExpiration(vg.cacheItemTTL))
	}

	// if this secret was created by using the console, then AWS Secrets
	// Manager stores the information as a JSON structure of key/value pairs.
	// so we support retrieving specific keys from a secret.
	if key, ok := overrides["json_secret_key"]; ok {
		var m map[string]interface{}
		if err = json.Unmarshal([]byte(*getSecretValueOutput.SecretString), &m); err != nil {
			return "", fmt.Errorf("The option json_secret_key was set to \"%s\", but the secret was not JSON", key)
		}
		if value, ok := m[key]; ok {
			if strValue, ok := value.(string); ok {
				return strValue, nil
			}
			return "", fmt.Errorf("The given json_secret_key \"%s\" is a valid key in the JSON secret, but the JSON value is not a string", key)
		}
		return "", fmt.Errorf("The option json_secret_key was set to \"%s\", but the secret JSON did not contain a value for that key", key)
	}

	return *getSecretValueOutput.SecretString, nil
}
