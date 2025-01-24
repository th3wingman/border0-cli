package server

import "fmt"

// jsonError returns JSON for an error message.
func jsonError(msg string) []byte {
	return []byte(fmt.Sprintf(`{"error": "%s"}`, msg))
}
