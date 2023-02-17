package idp

import (
	"reflect"

	"github.com/spf13/cobra"
)

func getIDPUpdateCmdRoot() *cobra.Command {
	addIdentityProviderCmdRoot := &cobra.Command{
		Use:   "update",
		Short: "update an identity provider to the current organization",
	}

	// idp update oidc
	addCommandWithFlags(
		addIdentityProviderCmdRoot,
		getIDPUpdateOIDCCmd(),
		flag{name: "name", shorthand: "n", target: &idpUpdateOIDCName, kind: reflect.String, value: "", usage: "the name of the identity provider to update", require: true},
		flag{name: "display-name", shorthand: "m", target: &idpUpdateOIDCDisplayName, kind: reflect.String, value: "", usage: "the display name for the identity provider", require: false},
		flag{name: "logo-url", shorthand: "l", target: &idpUpdateOIDCLogoURL, kind: reflect.String, value: "", usage: "the url of the logo to be displayed on the organization's login page for the identity provider", require: false},

		flag{name: "discovery-url", shorthand: "d", target: &idpUpdateOIDCDiscoveryURL, kind: reflect.String, value: "", usage: "the url where the oidc provider's discovery document is hosted", require: false},
		flag{name: "client-id", shorthand: "i", target: &idpUpdateOIDCClientID, kind: reflect.String, value: "", usage: "the client id to present to the oidc identity provider", require: false},
		flag{name: "oidc-flow-type", shorthand: "f", target: &idpUpdateOIDCFlowType, kind: reflect.String, value: "", usage: "either \"front_channel\" or \"back_channel\"", require: false},
		flag{name: "client-secret", shorthand: "s", target: &idpUpdateOIDCClientSecret, kind: reflect.String, value: "", usage: "[required if changing flow type to \"back_channel\"] the client secret to present to the oidc identity provider", require: false},
	)

	// idp update saml
	addCommandWithFlags(
		addIdentityProviderCmdRoot,
		getIDPUpdateSAMLCmd(),
		flag{name: "name", shorthand: "n", target: &idpUpdateSAMLName, kind: reflect.String, value: "", usage: "the name of the identity provider to update", require: true},
		flag{name: "display-name", shorthand: "m", target: &idpUpdateSAMLDisplayName, kind: reflect.String, value: "", usage: "the display name for the identity provider", require: false},
		flag{name: "logo-url", shorthand: "l", target: &idpUpdateSAMLLogoURL, kind: reflect.String, value: "", usage: "the url of the logo to be displayed on the organization's login page for the identity provider", require: false},

		flag{name: "sign-in-url", shorthand: "u", target: &idpUpdateSAMLSignInURL, kind: reflect.String, value: "", usage: "sign-in URL for saml provider", require: false},
		flag{name: "certificate-filename", shorthand: "c", target: &idpUpdateSAMLCertificateFilename, kind: reflect.String, value: "", usage: "path to file from where to read x509 signing certificate", require: false},
		flag{name: "request-signing", shorthand: "s", target: &idpUpdateSAMLRequestSigning, kind: reflect.Bool, value: false, usage: "true if saml provider will expect signed requests", require: false},
		flag{name: "signing-algorithm", shorthand: "a", target: &idpUpdateSAMLRequestSigningAlgorithm, kind: reflect.String, value: "", usage: "algorithm border0 should use to sign requests (rsa-sha256 or rsa-sha1)", require: false},
		flag{name: "digest-algorithm", shorthand: "d", target: &idpUpdateSAMLRequestSigningDigestAlgorithm, kind: reflect.String, value: "", usage: "algorithm border0 should use for request signing digests (sha256 or sha1)", require: false},
		flag{name: "protocol-binding", shorthand: "p", target: &idpUpdateSAMLRequestProtocolBinding, kind: reflect.String, value: "", usage: "request protocol binding (flow) (HTTP-POST or HTTP-Redirect)", require: false},
		flag{name: "template-filename", shorthand: "t", target: &idpUpdateSAMLRequestTemplateFilename, kind: reflect.String, value: "", usage: "the url of the logo to be displayed on the organization's login page for the identity provider", require: false},
	)

	// idp update okta-workforce
	addCommandWithFlags(
		addIdentityProviderCmdRoot,
		getUpdateOktaWorkforceIdentityProviderCmd(),
		flag{name: "name", shorthand: "n", target: &idpUpdateOktaWorkforceName, kind: reflect.String, value: "", usage: "the name of the identity provider to update", require: true},
		flag{name: "display-name", shorthand: "m", target: &idpUpdateOktaWorkforceDisplayName, kind: reflect.String, value: "", usage: "the display name for the identity provider", require: false},
		flag{name: "logo-url", shorthand: "l", target: &idpUpdateOktaWorkforceLogoURL, kind: reflect.String, value: "", usage: "the url of the logo to be displayed on the organization's login page for the identity provider", require: false},

		flag{name: "okta-domain", shorthand: "d", target: &idpUpdateOktaWorkforceDomain, kind: reflect.String, value: "", usage: "the domain of your okta workforce account e.g. \"${namespace}.okta.com\"", require: false},
		flag{name: "client-id", shorthand: "i", target: &idpUpdateOktaWorkforceClientID, kind: reflect.String, value: "", usage: "the client id to present to the okta workforce identity provider", require: false},
		flag{name: "client-secret", shorthand: "s", target: &idpUpdateOktaWorkforceClientSecret, kind: reflect.String, value: "", usage: "the client secret to present to the okta workforce identity provider", require: false},
	)

	// idp update google-workspace
	addCommandWithFlags(
		addIdentityProviderCmdRoot,
		getUpdateGoogleWorkspaceIdentityProviderCmd(),
		flag{name: "name", shorthand: "n", target: &idpUpdateGoogleWorkspaceName, kind: reflect.String, value: "", usage: "the name of the identity provider to update", require: true},
		flag{name: "display-name", shorthand: "m", target: &idpUpdateGoogleWorkspaceDisplayName, kind: reflect.String, value: "", usage: "the display name for the identity provider", require: false},
		flag{name: "logo-url", shorthand: "l", target: &idpUpdateGoogleWorkspaceLogoURL, kind: reflect.String, value: "", usage: "the url of the logo to be displayed on the organization's login page for the identity provider", require: false},

		flag{name: "workspace-domain", shorthand: "d", target: &idpUpdateGoogleWorkspaceDomain, kind: reflect.String, value: "", usage: "the domain of your google workspace account", require: false},
		flag{name: "client-id", shorthand: "i", target: &idpUpdateGoogleWorkspaceClientID, kind: reflect.String, value: "", usage: "the client id to present to the google workspace identity provider", require: false},
		flag{name: "client-secret", shorthand: "s", target: &idpUpdateGoogleWorkspaceClientSecret, kind: reflect.String, value: "", usage: "the client secret to present to the google workspace identity provider", require: false},
	)

	return addIdentityProviderCmdRoot
}
