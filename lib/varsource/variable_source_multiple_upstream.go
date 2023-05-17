package varsource

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

const (
	prefixAWSSecretsManager = "aws:secretsmanager:"
	prefixAWSSSM            = "aws:ssm:"
	prefixEnv               = "env:"
	prefixFile              = "file:"
)

// variableUpstream represents functioanlity of an upstream source of variable values
type variableUpstream interface {
	GetVariable(ctx context.Context, varDefn string) (string, error)
}

// MultipleUpstreamVariableSource is a VariableSource with multiple possible upstreams
type MultipleUpstreamVariableSource struct {
	prefixes  []string
	upstreams map[string]variableUpstream
}

// ensures MultipleUpstreamVariableSource implements VariableSource at compile-time
var _ VariableSource = (*MultipleUpstreamVariableSource)(nil)

// Option represents a constructor option to set configuration settings (e.g.
// an entry in the upstreams map) for a new MultipleUpstreamVariableSource
type Option func(muvs *MultipleUpstreamVariableSource)

// WithEnvVariableUpstream is the Option to set the environment
// variable upstream source in a new MultipleUpstreamVariableSource
func WithEnvVariableUpstream() Option {
	return func(m *MultipleUpstreamVariableSource) {
		m.upstreams[prefixEnv] = &envVariableUpstream{}
	}
}

// WithFileVariableUpstream is the Option to set the
// file contents source in a new MultipleUpstreamVariableSource
func WithFileVariableUpstream() Option {
	return func(m *MultipleUpstreamVariableSource) {
		m.upstreams[prefixFile] = &fileVariableUpstream{}
	}
}

// WithAWSSSMVariableUpstream is the Option to set the aws ssm
// parameter store upstream source in a new MultipleUpstreamVariableSource
func WithAWSSSMVariableUpstream() Option {
	return func(m *MultipleUpstreamVariableSource) {
		m.upstreams[prefixAWSSSM] = &awsSSMVariableUpstream{}
	}
}

// WithAWSSecretsManagerVariableUpstream is the Option to set the aws
// secrets manager upstream source in a new MultipleUpstreamVariableSource
func WithAWSSecretsManagerVariableUpstream() Option {
	return func(m *MultipleUpstreamVariableSource) {
		m.upstreams[prefixAWSSecretsManager] = &awsSecretsmanagerVariableUpstream{}
	}
}

// NewMultipleUpstreamVariableSource is the MultipleUpstreamVariableSource constructor. It returns
// a newly-initialized MultipleUpstreamVariableSource with all the given upstream sources set.
func NewMultipleUpstreamVariableSource(opts ...Option) *MultipleUpstreamVariableSource {
	varSource := &MultipleUpstreamVariableSource{
		prefixes:  []string{},
		upstreams: make(map[string]variableUpstream),
	}
	for _, opt := range opts {
		opt(varSource)
	}
	for prefix := range varSource.upstreams {
		varSource.prefixes = append(varSource.prefixes, prefix)
	}
	// NOTE: we sort the prefixes slice by decreasing length of string (in order to do longest-prefix-match in GetVariables)
	sort.Slice(varSource.prefixes, func(i, j int) bool { return len(varSource.prefixes[i]) > len(varSource.prefixes[j]) })
	return varSource
}

// GetVariables takes a map of variable names to variable definitions
// and returns a map of variable name to variable values. i.e. returns
// fetches the variable values based on the variable definitions and
// returns the same map populated with values instead of definitions.
func (vs *MultipleUpstreamVariableSource) GetVariables(ctx context.Context, vars map[string]string) (map[string]string, error) {
	processed := make(map[string]string)
	for varName, varDefn := range vars {
		value, err := vs.GetVariable(ctx, varDefn)
		if err != nil {
			return nil, fmt.Errorf("failed to process variable \"%s\": %v", varName, err)
		}
		processed[varName] = value
	}
	return processed, nil
}

// GetVariable takes a single variable definition and returns the variable's
// value i.e. fetches the variable's value based on the variable definition
func (vs *MultipleUpstreamVariableSource) GetVariable(ctx context.Context, varDefn string) (string, error) {
	// if the variable definition is an escaped variable definition
	// e.g. "\${env:USERNAME}" simply remove the escaping and skip processing
	if strings.HasPrefix(varDefn, `\${`) {
		return strings.TrimPrefix(varDefn, `\`), nil

	}

	// if the variable definition does not have start and end curly braces
	// (i.e. is not of the form ${VARIABLE}) we simply skip processing (i.e. assume
	// that the variable definition is the variable value - does not need fetching)
	if !(strings.HasPrefix(varDefn, "${") && strings.HasSuffix(varDefn, "}")) {
		return varDefn, nil
	}

	// remove the upstream variable indicators (the curly braces)
	upstreamVarDefn := strings.TrimSuffix(strings.TrimPrefix(varDefn, "${"), "}")

	// iterate over the sorted prefixes (in order of longest
	// to shortest prefix) breaking after the first match
	// (e.g. 'aws:ssm:' would match before 'aws:')
	for _, prefix := range vs.prefixes {
		if strings.HasPrefix(upstreamVarDefn, prefix) {
			value, err := vs.upstreams[prefix].GetVariable(ctx, strings.TrimPrefix(upstreamVarDefn, prefix))
			if err != nil {
				return "", fmt.Errorf("failed to get value for variable definition \"%s\": %v", varDefn, err)
			}
			return value, nil
		}
	}
	return "", fmt.Errorf("no upstream variable source available for variable definition \"%s\"", varDefn)
}
