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
	idpUpdateSAMLName                          string
	idpUpdateSAMLLogoURL                       string
	idpUpdateSAMLSignInURL                     string
	idpUpdateSAMLCertificateFilename           string
	idpUpdateSAMLRequestSigning                bool
	idpUpdateSAMLRequestSigningAlgorithm       string
	idpUpdateSAMLRequestSigningDigestAlgorithm string
	idpUpdateSAMLRequestProtocolBinding        string
	idpUpdateSAMLRequestTemplateFilename       string
)

func getIDPUpdateSAMLCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "saml",
		Short: "update a SAML identity provider in the current organization",
		Run:   getIDPUpdateSAMLCmdHandler(),
	}
}

func getIDPUpdateSAMLCmdHandler() func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		client, err := border0.NewClient()
		if err != nil {
			util.FailPretty("failed to get Border0 API client: %s", err)
		}

		var cert *string
		if idpUpdateSAMLCertificateFilename != "" {
			byt, err := os.ReadFile(idpUpdateSAMLCertificateFilename)
			if err != nil {
				util.FailPretty("failed to read file certificate file: %s", err)
			}
			strByt := string(byt)
			cert = &strByt
		}

		var template *string
		if idpUpdateSAMLRequestTemplateFilename != "" {
			byt, err := os.ReadFile(idpUpdateSAMLRequestTemplateFilename)
			if err != nil {
				util.FailPretty("failed to read file certificate file: %s", err)
			}
			strByt := string(byt)
			template = &strByt
		}

		var logo *string
		if cmd.Flags().Changed("logo-url") {
			logo = &idpUpdateSAMLLogoURL
		}

		reqBody := identityProvider{
			identityProviderSummary: identityProviderSummary{
				Name:    &idpUpdateSAMLName,
				Type:    &identityProviderTypeSAML,
				LogoURL: logo,
			},
			SAMLIdentityProviderConfiguration: &samlConfig{
				SignInURL:                     &idpUpdateSAMLSignInURL,
				X509SigningCertificate:        cert,
				RequestSigning:                &idpUpdateSAMLRequestSigning,
				RequestSigningAlgorithm:       &idpUpdateSAMLRequestSigningAlgorithm,
				RequestSigningDigestAlgorithm: &idpUpdateSAMLRequestSigningDigestAlgorithm,
				RequestProtocolBinding:        &idpUpdateSAMLRequestProtocolBinding,
				RequestTemplate:               template,
			},
		}

		if err = client.Request(http.MethodPatch, "organization/identity_provider", nil, reqBody); err != nil {
			util.FailPretty("failed to update identity provider: %s", err)
		}

		fmt.Println(fmt.Sprintf("\nIdentity provider \"%s\" successfully updated!", idpUpdateSAMLName))
	}
}
