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
	idpUpdateGoogleWorkspaceName         string
	idpUpdateGoogleWorkspaceDisplayName  string
	idpUpdateGoogleWorkspaceLogoURL      string
	idpUpdateGoogleWorkspaceDomain       string
	idpUpdateGoogleWorkspaceClientID     string
	idpUpdateGoogleWorkspaceClientSecret string
)

func getUpdateGoogleWorkspaceIdentityProviderCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "google-workspace",
		Short: "update a Google Workspace identity provider in the current organization",
		Run:   getIDPUpdateGoogleWorkspaceCmdHandler(),
	}
}

func getIDPUpdateGoogleWorkspaceCmdHandler() func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		client, err := border0.NewClient()
		if err != nil {
			util.FailPretty("failed to get Border0 API client: %s", err)
		}

		var logo *string
		if cmd.Flags().Changed("logo-url") {
			logo = &idpUpdateGoogleWorkspaceLogoURL
		}

		reqBody := identityProvider{
			identityProviderSummary: identityProviderSummary{
				Name:        &idpUpdateGoogleWorkspaceName,
				DisplayName: &idpUpdateGoogleWorkspaceDisplayName,
				Type:        &identityProviderTypeGoogleWorkspace,
				LogoURL:     logo,
			},
			GoogleWorkspaceIdentityProviderConfiguration: &googleConfig{
				GoogleWorkspaceDomain: &idpUpdateGoogleWorkspaceDomain,
				ClientID:              &idpUpdateGoogleWorkspaceClientID,
				ClientSecret:          &idpUpdateGoogleWorkspaceClientSecret,
			},
		}

		if err = client.Request(http.MethodPatch, "organization/identity_provider", nil, reqBody); err != nil {
			util.FailPretty("failed to update identity provider: %s", err)
		}

		fmt.Println(fmt.Sprintf("\nIdentity provider \"%s\" successfully updated!", idpUpdateGoogleWorkspaceName))
	}
}
