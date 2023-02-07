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
	idpAddOIDCName         string
	idpAddOIDCDisplayName  string
	idpAddOIDCLogoURL      string
	idpAddOIDCDiscoveryURL string
	idpAddOIDCClientID     string
	idpAddOIDCFlowType     string
	idpAddOIDCClientSecret string
)

func getIDPAddOIDCCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "oidc",
		Short: "add an OpenID Connect 1.0 identity provider to the current organization",
		Run:   getIDPAddOIDCCmdHandler(),
	}
}

func getIDPAddOIDCCmdHandler() func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		client, err := border0.NewClient()
		if err != nil {
			util.FailPretty("failed to get Border0 API client: %s", err)
		}

		if idpAddOIDCFlowType == "back_channel" && idpAddOIDCClientSecret == "" {
			util.FailPretty("flag client-secret must be provided when oidc-flow-type=\"back_channel\"")
		}

		reqBody := identityProvider{
			identityProviderSummary: identityProviderSummary{
				Name:        &idpAddOIDCName,
				DisplayName: &idpAddOIDCDisplayName,
				Type:        &identityProviderTypeOIDC,
				LogoURL:     &idpAddOIDCLogoURL,
			},
			OIDCIdentityProviderConfiguation: &oidcConfig{
				DiscoveryURL: &idpAddOIDCDiscoveryURL,
				ClientID:     &idpAddOIDCClientID,
				FlowType:     &idpAddOIDCFlowType,
				ClientSecret: &idpAddOIDCClientSecret,
			},
		}

		var respBody addIdentityProviderResponse
		if err = client.Request(http.MethodPost, "organization/identity_provider", &respBody, reqBody); err != nil {
			util.FailPretty("failed to create new identity provider: %s", err)
		}

		fmt.Println(fmt.Sprintf("\n%s You may need to configure your OpenID Connect 1.0 provider to allow the redirect URL: %s\n", warningBanner, respBody.OIDCResponse.MustAllowRedirectURL))
		fmt.Println(fmt.Sprintf("New OpenID Connect 1.0 identity provider \"%s\" successfully added to your organization!", idpAddOIDCName))
	}
}
