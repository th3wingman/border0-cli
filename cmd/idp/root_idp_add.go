package idp

import (
	"reflect"

	"github.com/spf13/cobra"
)

func getIDPAddCmdRoot() *cobra.Command {
	addIdentityProviderCmdRoot := &cobra.Command{
		Use:   "add",
		Short: "add an identity provider to the current organization",
	}

	// idp add oidc
	addCommandWithFlags(
		addIdentityProviderCmdRoot,
		getIDPAddOIDCCmd(),
		flag{name: "name", shorthand: "n", target: &idpAddOIDCName, kind: reflect.String, value: "", usage: "the name for the new identity provider", require: true},
		flag{name: "display-name", shorthand: "m", target: &idpAddOIDCDisplayName, kind: reflect.String, value: "", usage: "the display name for the new identity provider", require: false},
		flag{name: "logo-url", shorthand: "l", target: &idpAddOIDCLogoURL, kind: reflect.String, value: "", usage: "the url of the logo to be displayed on the organization's login page for the identity provider", require: false},

		flag{name: "discovery-url", shorthand: "d", target: &idpAddOIDCDiscoveryURL, kind: reflect.String, value: "", usage: "the url where the oidc provider's discovery document is hosted", require: true},
		flag{name: "client-id", shorthand: "i", target: &idpAddOIDCClientID, kind: reflect.String, value: "", usage: "the client id to present to the oidc identity provider", require: true},
		flag{name: "oidc-flow-type", shorthand: "f", target: &idpAddOIDCFlowType, kind: reflect.String, value: "back_channel", usage: "either \"front_channel\" or \"back_channel\"", require: false},
		flag{name: "client-secret", shorthand: "s", target: &idpAddOIDCClientSecret, kind: reflect.String, value: "", usage: "[required if oidc-flow-type=\"back_channel\"] the client secret to present to the oidc identity provider", require: false},
	)

	// idp add saml
	addCommandWithFlags(
		addIdentityProviderCmdRoot,
		getIDPAddSAMLCmd(),
		flag{name: "name", shorthand: "n", target: &idpAddSAMLName, kind: reflect.String, value: "", usage: "the name for the new identity provider", require: true},
		flag{name: "display-name", shorthand: "m", target: &idpAddSAMLDisplayName, kind: reflect.String, value: "", usage: "the display name for the new identity provider", require: false},
		flag{name: "logo-url", shorthand: "l", target: &idpAddSAMLLogoURL, kind: reflect.String, value: "", usage: "the url of the logo to be displayed on the organization's login page for the identity provider", require: false},

		flag{name: "sign-in-url", shorthand: "u", target: &idpAddSAMLSignInURL, kind: reflect.String, value: "", usage: "sign-in URL for saml provider", require: true},
		flag{name: "certificate-filename", shorthand: "c", target: &idpAddSAMLCertificateFilename, kind: reflect.String, value: "", usage: "path to file from where to read x509 signing certificate", require: true},
		flag{name: "request-signing", shorthand: "s", target: &idpAddSAMLRequestSigning, kind: reflect.Bool, value: true, usage: "true if saml provider will expect signed requests", require: false},
		flag{name: "signing-algorithm", shorthand: "a", target: &idpAddSAMLRequestSigningAlgorithm, kind: reflect.String, value: "rsa-sha256", usage: "algorithm border0 should use to sign requests (rsa-sha256 or rsa-sha1)", require: false},
		flag{name: "digest-algorithm", shorthand: "d", target: &idpAddSAMLRequestSigningDigestAlgorithm, kind: reflect.String, value: "sha256", usage: "algorithm border0 should use for request signing digests (sha256 or sha1)", require: false},
		flag{name: "protocol-binding", shorthand: "p", target: &idpAddSAMLRequestProtocolBinding, kind: reflect.String, value: "HTTP-Redirect", usage: "request protocol binding (flow) (HTTP-POST or HTTP-Redirect)", require: false},
		flag{name: "template-filename", shorthand: "t", target: &idpAddSAMLRequestTemplateFilename, kind: reflect.String, value: "", usage: "the url of the logo to be displayed on the organization's login page for the identity provider", require: false},
	)

	// idp add okta-workforce
	addCommandWithFlags(
		addIdentityProviderCmdRoot,
		getIDPAddOktaWorkforceCmd(),
		flag{name: "name", shorthand: "n", target: &idpAddOktaWorkforceName, kind: reflect.String, value: "", usage: "the name for the new identity provider", require: true},
		flag{name: "display-name", shorthand: "m", target: &idpAddOktaWorkforceDisplayName, kind: reflect.String, value: "", usage: "the display name for the new identity provider", require: false},
		flag{name: "logo-url", shorthand: "l", target: &idpAddOktaWorkforceLogoURL, kind: reflect.String, value: "", usage: "the url of the logo to be displayed on the organization's login page for the identity provider", require: false},

		flag{name: "okta-domain", shorthand: "d", target: &idpAddOktaWorkforceDomain, kind: reflect.String, value: "", usage: "the domain of your okta workforce account e.g. \"${namespace}.okta.com\"", require: true},
		flag{name: "client-id", shorthand: "i", target: &idpAddOktaWorkforceClientID, kind: reflect.String, value: "", usage: "the client id to present to the okta workforce identity provider", require: true},
		flag{name: "client-secret", shorthand: "s", target: &idpAddOktaWorkforceClientSecret, kind: reflect.String, value: "", usage: "the client secret to present to the okta workforce identity provider", require: true},
	)

	// idp add google-workspace
	addCommandWithFlags(
		addIdentityProviderCmdRoot,
		getIDPAddGoogleWorkspaceCmd(),
		flag{name: "name", shorthand: "n", target: &idpAddGoogleWorkspaceName, kind: reflect.String, value: "", usage: "the name for the new identity provider", require: true},
		flag{name: "display-name", shorthand: "m", target: &idpAddGoogleWorkspaceDisplayName, kind: reflect.String, value: "", usage: "the display name for the new identity provider", require: false},
		flag{name: "logo-url", shorthand: "l", target: &idpAddGoogleWorkspaceLogoURL, kind: reflect.String, value: "", usage: "the url of the logo to be displayed on the organization's login page for the identity provider", require: false},

		flag{name: "workspace-domain", shorthand: "d", target: &idpAddGoogleWorkspaceDomain, kind: reflect.String, value: "", usage: "the domain of your google workspace account", require: true},
		flag{name: "client-id", shorthand: "i", target: &idpAddGoogleWorkspaceClientID, kind: reflect.String, value: "", usage: "the client id to present to the google workspace identity provider", require: true},
		flag{name: "client-secret", shorthand: "s", target: &idpAddGoogleWorkspaceClientSecret, kind: reflect.String, value: "", usage: "the client secret to present to the google workspace identity provider", require: true},
	)

	return addIdentityProviderCmdRoot
}
