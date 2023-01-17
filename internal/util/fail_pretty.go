package util

import (
	"fmt"
	"os"
)

// FailPretty prints an error message
func FailPretty(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)

	fmt.Printf("\nError: %s\n", msg)
	os.Exit(1)
}
