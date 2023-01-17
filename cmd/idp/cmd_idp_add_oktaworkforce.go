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
	idpAddOktaWorkforceName         string
	idpAddOktaWorkforceLogoURL      string
	idpAddOktaWorkforceDomain       string
	idpAddOktaWorkforceClientID     string
	idpAddOktaWorkforceClientSecret string
)

func getIDPAddOktaWorkforceCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "okta-workforce",
		Short: "add an Okta Workforce identity provider to the current organization",
		Run:   getIDPAddOktaWorkforceCmdHandler(),
	}
}

func getIDPAddOktaWorkforceCmdHandler() func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		client, err := border0.NewClient()
		if err != nil {
			util.FailPretty("failed to get Border0 API client: %s", err)
		}

		reqBody := identityProvider{
			identityProviderSummary: identityProviderSummary{
				Name:    &idpAddOktaWorkforceName,
				Type:    &identityProviderTypeOktaWorkforce,
				LogoURL: &idpAddOktaWorkforceLogoURL,
			},
			OktaWorkforceIdentityProviderConfiguration: &oktaConfig{
				OktaDomain:   &idpAddOktaWorkforceDomain,
				ClientID:     &idpAddOktaWorkforceClientID,
				ClientSecret: &idpAddOktaWorkforceClientSecret,
			},
		}

		var respBody addIdentityProviderResponse
		if err = client.Request(http.MethodPost, "organization/identity_provider", &respBody, reqBody); err != nil {
			util.FailPretty("failed to create new identity provider: %s", err)
		}

		fmt.Println(fmt.Sprintf("\n%s You may need to to configure your Okta Workforce account to allow the redirect URL: %s\n", warningBanner, respBody.OktaWorkforceResponse.MustAllowRedirectURL))
		fmt.Println(fmt.Sprintf("New Okta Workforce identity provider \"%s\" successfully added to your organization!", idpAddOktaWorkforceName))
	}
}
