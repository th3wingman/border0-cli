package idp

import (
	"fmt"
	"net/http"
	"os"

	border0 "github.com/borderzero/border0-cli/internal/http"
	"github.com/borderzero/border0-cli/internal/util"
	"github.com/spf13/cobra"
)

var (
	// flags
	idpAddSAMLName                          string
	idpAddSAMLLogoURL                       string
	idpAddSAMLSignInURL                     string
	idpAddSAMLCertificateFilename           string
	idpAddSAMLRequestSigning                bool
	idpAddSAMLRequestSigningAlgorithm       string
	idpAddSAMLRequestSigningDigestAlgorithm string
	idpAddSAMLRequestProtocolBinding        string
	idpAddSAMLRequestTemplateFilename       string
)

func getIDPAddSAMLCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "saml",
		Short: "add a SAML identity provider to the current organization",
		Run:   getIDPAddSAMLCmdHandler(),
	}
}

func getIDPAddSAMLCmdHandler() func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		client, err := border0.NewClient()
		if err != nil {
			util.FailPretty("failed to get Border0 API client: %s", err)
		}

		byt, err := os.ReadFile(idpAddSAMLCertificateFilename)
		if err != nil {
			util.FailPretty("failed to read file certificate file: %s", err)
		}
		cert := string(byt)

		var template string
		if idpAddSAMLRequestTemplateFilename != "" {
			byt, err := os.ReadFile(idpAddSAMLRequestTemplateFilename)
			if err != nil {
				util.FailPretty("failed to read file certificate file: %s", err)
			}
			template = string(byt)
		}

		reqBody := identityProvider{
			identityProviderSummary: identityProviderSummary{
				Name:    &idpAddSAMLName,
				Type:    &identityProviderTypeSAML,
				LogoURL: &idpAddSAMLLogoURL,
			},
			SAMLIdentityProviderConfiguration: &samlConfig{
				SignInURL:                     &idpAddSAMLSignInURL,
				X509SigningCertificate:        &cert,
				RequestSigning:                &idpAddSAMLRequestSigning,
				RequestSigningAlgorithm:       &idpAddSAMLRequestSigningAlgorithm,
				RequestSigningDigestAlgorithm: &idpAddSAMLRequestSigningDigestAlgorithm,
				RequestProtocolBinding:        &idpAddSAMLRequestProtocolBinding,
				RequestTemplate:               &template,
			},
		}

		var respBody addIdentityProviderResponse
		if err = client.Request(http.MethodPost, "organization/identity_provider", &respBody, reqBody); err != nil {
			util.FailPretty("failed to create new identity provider: %s", err)
		}

		fmt.Println(fmt.Sprintf("\n%s You may need to configure your SAML provider to allow the redirect URL: %s\n", warningBanner, respBody.SAMLResponse.MustAllowRedirectURL))
		if idpAddSAMLRequestSigning {
			fmt.Println(fmt.Sprintf("%s You may need to configure your SAML provider to accept assertion requests signed with the certificate found at: %s\n", warningBanner, respBody.SAMLResponse.RequestSigningCertificateURL))
		}

		fmt.Println(fmt.Sprintf("New SAML identity provider \"%s\" successfully added to your organization!", idpAddSAMLName))
	}
}
