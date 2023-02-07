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
	idpUpdateOktaWorkforceName         string
	idpUpdateOktaWorkforceDisplayName  string
	idpUpdateOktaWorkforceLogoURL      string
	idpUpdateOktaWorkforceDomain       string
	idpUpdateOktaWorkforceClientID     string
	idpUpdateOktaWorkforceClientSecret string
)

func getUpdateOktaWorkforceIdentityProviderCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "okta-workforce",
		Short: "update an Okta Workforce identity provider in the current organization",
		Run:   getIDPUpdateOktaWorkforceCmdHandler(),
	}
}

func getIDPUpdateOktaWorkforceCmdHandler() func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		client, err := border0.NewClient()
		if err != nil {
			util.FailPretty("failed to get Border0 API client: %s", err)
		}

		var logo *string
		if cmd.Flags().Changed("logo-url") {
			logo = &idpUpdateOktaWorkforceLogoURL
		}

		reqBody := identityProvider{
			identityProviderSummary: identityProviderSummary{
				Name:        &idpUpdateOktaWorkforceName,
				DisplayName: &idpUpdateOktaWorkforceDisplayName,
				Type:        &identityProviderTypeOktaWorkforce,
				LogoURL:     logo,
			},
			OktaWorkforceIdentityProviderConfiguration: &oktaConfig{
				OktaDomain:   &idpUpdateOktaWorkforceDomain,
				ClientID:     &idpUpdateOktaWorkforceClientID,
				ClientSecret: &idpUpdateOktaWorkforceClientSecret,
			},
		}

		if err = client.Request(http.MethodPatch, "organization/identity_provider", nil, reqBody); err != nil {
			util.FailPretty("failed to update identity provider: %s", err)
		}

		fmt.Println(fmt.Sprintf("\nIdentity provider \"%s\" successfully updated!", idpUpdateOktaWorkforceName))
	}
}
