package util

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// replace all special characters except for '-' with a dash
func replaceSpecialCharactersWithDash(input string) string {
	reg := regexp.MustCompile(`[^a-zA-Z0-9-]`)
	return reg.ReplaceAllString(input, "-")
}

// GetFormattedHostname gets a hostname with no special characters.
func GetFormattedHostname() (string, error) {
	hn, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("failed to get hostname: %v", err)
	}
	return strings.ToLower(replaceSpecialCharactersWithDash(hn)), nil
}
