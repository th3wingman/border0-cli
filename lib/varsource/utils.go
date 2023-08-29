package varsource

import (
	"fmt"
	"strings"
)

func parseVariableDefinitionParts(input string) (string, map[string]string, error) {
	data := make(map[string]string)

	parts := strings.Split(input, ",")
	if len(parts) == 0 {
		return "", nil, fmt.Errorf("invalid input: %s", input)
	}

	firstValue := parts[0]

	for _, part := range parts[1:] {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return "", nil, fmt.Errorf("invalid key-value pair: %s", part)
		}
		data[kv[0]] = kv[1]
	}

	return firstValue, data, nil
}
