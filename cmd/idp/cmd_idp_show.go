package idp

import (
	"encoding/json"
	"fmt"
	"net/http"

	border0 "github.com/borderzero/border0-cli/internal/http"
	"github.com/borderzero/border0-cli/internal/util"
	"github.com/jedib0t/go-pretty/table"
	"github.com/spf13/cobra"
)

var (
	// flags
	idpShowName       string
	idpShowJSONOutput bool
)

func getIDPShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "describe an identity provider for the current organization",
		Run:   getIDPShowCmdHandler(),
	}
}

func getIDPShowCmdHandler() func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		client, err := border0.NewClient()
		if err != nil {
			util.FailPretty("failed to get Border0 API client: %s", err)
		}

		var resp identityProvider
		if err = client.Request(http.MethodGet, fmt.Sprintf("organization/identity_provider/%s", idpShowName), &resp, nil); err != nil {
			util.FailPretty("failed to get identity provider: %s", err)
		}

		if idpShowJSONOutput {
			jsonBytes, err := json.Marshal(resp)
			if err != nil {
				util.FailPretty("failed to marshal response as json: %s", err)
			}

			fmt.Println(string(jsonBytes))
			return
		}

		tb := table.NewWriter()

		if resp.Name != nil {
			tb.AppendRow(table.Row{"Name", *resp.Name})
		}
		if resp.Type != nil {
			tb.AppendRow(table.Row{"Type", *resp.Type})
		}
		if resp.Enabled != nil {
			tb.AppendRow(table.Row{"Enabled", *resp.Enabled})
		}
		if resp.LogoURL != nil {
			tb.AppendRow(table.Row{"Logo URL", *resp.LogoURL})
		}

		if resp.Type != nil {
			switch *resp.Type {
			case identityProviderTypeOIDC:
				if resp.OIDCIdentityProviderConfiguation != nil {
					oidcConfig := resp.OIDCIdentityProviderConfiguation

					if oidcConfig.DiscoveryURL != nil {
						tb.AppendRow(table.Row{"Discovery URL", *oidcConfig.DiscoveryURL})
					}
					if oidcConfig.ClientID != nil {
						tb.AppendRow(table.Row{"Client ID", *oidcConfig.ClientID})
					}
					if oidcConfig.FlowType != nil {
						if *oidcConfig.FlowType == "back_channel" {
							if oidcConfig.ClientSecret != nil {
								tb.AppendRow(table.Row{"Client Secret", *oidcConfig.ClientSecret})
							}
						}
						tb.AppendRow(table.Row{"OIDC Flow Type", *oidcConfig.FlowType})
					}
				}
			case identityProviderTypeSAML:
				if resp.SAMLIdentityProviderConfiguration != nil {
					samlConfig := resp.SAMLIdentityProviderConfiguration

					if samlConfig.SignInURL != nil {
						tb.AppendRow(table.Row{"Sign In URL", *samlConfig.SignInURL})
					}
					if samlConfig.RequestSigning != nil {
						tb.AppendRow(table.Row{"Assertion Request Signing Enabled", *samlConfig.RequestSigning})
						if *samlConfig.RequestSigning {
							if samlConfig.RequestSigningAlgorithm != nil {
								tb.AppendRow(table.Row{"Assertion Request Signing Algorithm", *samlConfig.RequestSigningAlgorithm})
							}
							if samlConfig.RequestSigningDigestAlgorithm != nil {
								tb.AppendRow(table.Row{"Assertion Request Signing Digest Algorithm", *samlConfig.RequestSigningDigestAlgorithm})
							}
						}
					}
					if samlConfig.RequestProtocolBinding != nil {
						tb.AppendRow(table.Row{"Assertion Request Protocol Binding", *samlConfig.RequestProtocolBinding})
					}
					if samlConfig.RequestTemplate != nil && *samlConfig.RequestTemplate != "" {
						tb.AppendRow(table.Row{"Assertion Request Template", *samlConfig.RequestTemplate})
					}
					if samlConfig.X509SigningCertificate != nil {
						tb.AppendRow(table.Row{"Assertion Response Signing Certificate", *samlConfig.X509SigningCertificate})
					}
				}
			case identityProviderTypeOktaWorkforce:
				if resp.OktaWorkforceIdentityProviderConfiguration != nil {
					oktaConfig := resp.OktaWorkforceIdentityProviderConfiguration

					if oktaConfig.OktaDomain != nil {
						tb.AppendRow(table.Row{"Okta Domain", *oktaConfig.OktaDomain})
					}
					if oktaConfig.ClientID != nil {
						tb.AppendRow(table.Row{"Client ID", *oktaConfig.ClientID})
					}
					if oktaConfig.ClientSecret != nil {
						tb.AppendRow(table.Row{"Client Secret", *oktaConfig.ClientSecret})
					}
				}
			case identityProviderTypeGoogleWorkspace:
				if resp.GoogleWorkspaceIdentityProviderConfiguration != nil {
					googleConfig := resp.GoogleWorkspaceIdentityProviderConfiguration
					if googleConfig.GoogleWorkspaceDomain != nil {
						tb.AppendRow(table.Row{"Google Workspace Domain", *googleConfig.GoogleWorkspaceDomain})
					}
					if googleConfig.ClientID != nil {
						tb.AppendRow(table.Row{"Client ID", *googleConfig.ClientID})
					}
					if googleConfig.ClientSecret != nil {
						tb.AppendRow(table.Row{"Client Secret", *googleConfig.ClientSecret})
					}
				}
			}
		}

		fmt.Println(fmt.Sprintf("\n%s", tb.Render()))
	}
}
