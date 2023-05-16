package varsource

import (
	"context"
	"fmt"
	"os"
)

// variableUpstream implementation for fetching values from environment variables
type envVariableUpstream struct{}

// ensure envVariableUpstream implements variableUpstream at compile-time
var _ variableUpstream = (*envVariableUpstream)(nil)

// GetVariable gets a variable from the environment
func (vg *envVariableUpstream) GetVariable(ctx context.Context, varDefn string) (string, error) {
	envName := varDefn
	value := os.Getenv(envName)
	if value != "" {
		return value, nil
	}
	return "", fmt.Errorf("no value in environment for \"%s\"", envName)
}
