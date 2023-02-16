package models

import "strings"

const (
	CredentialsTypeUser  = "User"
	CredentialsTypeToken = "Token"
)

type AccessToken struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func (a *AccessToken) ShouldRefresh() bool {
	return a.TokenType == "User"
}

func NewAccessToken(accessToken string, credentialsType string) *AccessToken {
	sanitizedAccessToken := strings.Trim(accessToken, "\n")
	sanitizedAccessToken = strings.Trim(sanitizedAccessToken, " ")

	return &AccessToken{
		AccessToken: sanitizedAccessToken,
		TokenType:   credentialsType,
	}
}
