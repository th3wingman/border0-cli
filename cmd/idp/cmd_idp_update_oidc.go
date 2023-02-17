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
	idpUpdateOIDCName         string
	idpUpdateOIDCDisplayName  string
	idpUpdateOIDCLogoURL      string
	idpUpdateOIDCDiscoveryURL string
	idpUpdateOIDCClientID     string
	idpUpdateOIDCFlowType     string
	idpUpdateOIDCClientSecret string
)

func getIDPUpdateOIDCCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "oidc",
		Short: "update an OpenID Connect 1.0 identity provider in the current organization",
		Run:   getIDPUpdateOIDCCmdHandler(),
	}
}

func getIDPUpdateOIDCCmdHandler() func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		client, err := border0.NewClient()
		if err != nil {
			util.FailPretty("failed to get Border0 API client: %s", err)
		}

		var logo *string
		if cmd.Flags().Changed("logo-url") {
			logo = &idpUpdateOIDCLogoURL
		}

		reqBody := identityProvider{
			identityProviderSummary: identityProviderSummary{
				Name:        &idpUpdateOIDCName,
				DisplayName: &idpUpdateOIDCDisplayName,
				Type:        &identityProviderTypeOIDC,
				LogoURL:     logo,
			},
			OIDCIdentityProviderConfiguation: &oidcConfig{
				DiscoveryURL: &idpUpdateOIDCDiscoveryURL,
				ClientID:     &idpUpdateOIDCClientID,
				FlowType:     &idpUpdateOIDCFlowType,
				ClientSecret: &idpUpdateOIDCClientSecret,
			},
		}

		if err = client.Request(http.MethodPatch, "organization/identity_provider", nil, reqBody); err != nil {
			util.FailPretty("failed to update identity provider: %s", err)
		}

		fmt.Println(fmt.Sprintf("\nIdentity provider \"%s\" successfully updated!", idpUpdateOIDCName))
	}
}
