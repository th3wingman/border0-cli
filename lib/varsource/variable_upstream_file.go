package varsource

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// variableUpstream implementation for fetching values from a file
type fileVariableUpstream struct{}

// ensure fileVariableUpstream implements variableUpstream at compile-time
var _ variableUpstream = (*fileVariableUpstream)(nil)

// GetVariable gets a variable from a file
func (vg *fileVariableUpstream) GetVariable(ctx context.Context, varDefn string) (string, error) {
	filePath := varDefn
	if strings.HasPrefix(filePath, `~/`) {
		filePath = strings.TrimPrefix(filePath, `~/`)
		filePath = fmt.Sprintf("%s/%s", os.Getenv("HOME"), filePath)
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read file at path \"%s\"", filePath)
	}
	return strings.TrimSuffix(string(data), "\n"), nil
}
