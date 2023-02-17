package models

import "strings"

const (
	CredentialsTypeUser  = "User"
	CredentialsTypeToken = "Token"
)

type Credentials struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func (a *Credentials) ShouldRefresh() bool {
	return a.TokenType == "User"
}

func NewCredentials(accessToken string, credentialsType string) *Credentials {
	sanitizedAccessToken := strings.Trim(accessToken, "\n")
	sanitizedAccessToken = strings.Trim(sanitizedAccessToken, " ")

	return &Credentials{
		AccessToken: sanitizedAccessToken,
		TokenType:   credentialsType,
	}
}
