# varsource

A package for sourcing variable values from multiple upstreams. 

Currently supported upstreams include:

- `env:` an environment variable value
- `file:` the contents of a file
- `aws:ssm:` an AWS Systems Manager Parameter Store parameter value
- `aws:secretsmanager:` an AWS Secrets Manager secret value

### Usage

```
vs := varsource.NewDefaultVariableSource()

vars, err := vs.GetVariables(ctx, map[string]string{
	"DB_USERNAME": "from:env:DB_USERNAME",
	"DB_PASSWORD": "from:aws:secretsmanager:my-password",
}
if err != nil {
	log.Fatalf("failed to fetch variables: %v", err)
}

username := vars["DB_USERNAME"]
password := vars["DB_PASSWORD"]

// ... do something useful ...
```