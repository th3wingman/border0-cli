package idp

import (
	"fmt"
	"net/http"

	border0 "github.com/borderzero/border0-cli/internal/http"
	"github.com/borderzero/border0-cli/internal/util"
	"github.com/spf13/cobra"
)

var (
	// flags
	idpAddGoogleWorkspaceName         string
	idpAddGoogleWorkspaceLogoURL      string
	idpAddGoogleWorkspaceDomain       string
	idpAddGoogleWorkspaceClientID     string
	idpAddGoogleWorkspaceClientSecret string
)

func getIDPAddGoogleWorkspaceCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "google-workspace",
		Short: "add a Google Workspace identity provider to the current organization",
		Run:   getIDPAddGoogleWorkspaceCmdHandler(),
	}
}

func getIDPAddGoogleWorkspaceCmdHandler() func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		client, err := border0.NewClient()
		if err != nil {
			util.FailPretty("failed to get Border0 API client: %s", err)
		}

		reqBody := identityProvider{
			identityProviderSummary: identityProviderSummary{
				Name:    &idpAddGoogleWorkspaceName,
				Type:    &identityProviderTypeGoogleWorkspace,
				LogoURL: &idpAddGoogleWorkspaceLogoURL,
			},
			GoogleWorkspaceIdentityProviderConfiguration: &googleConfig{
				GoogleWorkspaceDomain: &idpAddGoogleWorkspaceDomain,
				ClientID:              &idpAddGoogleWorkspaceClientID,
				ClientSecret:          &idpAddGoogleWorkspaceClientSecret,
			},
		}

		var respBody addIdentityProviderResponse
		if err = client.Request(http.MethodPost, "organization/identity_provider", &respBody, reqBody); err != nil {
			util.FailPretty("failed to create new identity provider: %s", err)
		}

		fmt.Println(fmt.Sprintf("\n%s You may need to to configure your Google Workspace account to allow the javascript origin: %s", warningBanner, respBody.GoogleWorkspaceResponse.MustAllowJavascriptOrigin))
		fmt.Println(fmt.Sprintf("%s You may need to to configure your Google Workspace account to allow the redirect URL: %s\n", warningBanner, respBody.GoogleWorkspaceResponse.MustAllowRedirectURL))

		fmt.Println(fmt.Sprintf("New Google Workspace identity provider \"%s\" successfully added to your organization!", idpAddGoogleWorkspaceName))
	}
}
