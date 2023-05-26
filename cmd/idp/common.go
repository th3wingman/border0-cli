package idp

import (
	"fmt"
	"reflect"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// constants (not declared const because need to take their address)
var (
	identityProviderTypeGlobalGoogle    = "google"
	identityProviderTypeGlobalGithub    = "github"
	identityProviderTypeGlobalMicrosoft = "microsoft"
	identityProviderTypeOIDC            = "oidc"
	identityProviderTypeSAML            = "saml"
	identityProviderTypeOktaWorkforce   = "okta-workforce"
	identityProviderTypeGoogleWorkspace = "google-workspace"

	warningBanner = color.New(color.FgYellow).Sprint("[WARNING]")
)

type oidcConfig struct {
	DiscoveryURL *string `json:"discovery_url,omitempty"`
	ClientID     *string `json:"client_id,omitempty"`
	FlowType     *string `json:"oidc_flow_type,omitempty"`
	ClientSecret *string `json:"client_secret,omitempty"`
}

type oktaConfig struct {
	OktaDomain   *string `json:"okta_domain,omitempty"`
	ClientID     *string `json:"client_id,omitempty"`
	ClientSecret *string `json:"client_secret,omitempty"`
}

type googleConfig struct {
	GoogleWorkspaceDomain *string `json:"google_workspace_domain,omitempty"`
	ClientID              *string `json:"client_id,omitempty"`
	ClientSecret          *string `json:"client_secret,omitempty"`
}

type samlConfig struct {
	SignInURL                     *string `json:"sign_in_url,omitempty"`
	X509SigningCertificate        *string `json:"signing_certificate,omitempty"`
	RequestSigning                *bool   `json:"request_signing_enabled,omitempty"`
	RequestSigningAlgorithm       *string `json:"request_signing_algorithm,omitempty"`
	RequestSigningDigestAlgorithm *string `json:"request_signing_digest_algorithm,omitempty"`
	RequestProtocolBinding        *string `json:"request_protocol_binding,omitempty"`
	RequestTemplate               *string `json:"request_template,omitempty"`
}

type identityProviderSummary struct {
	Name        *string `json:"name,omitempty"`
	DisplayName *string `json:"display_name,omitempty"`
	Type        *string `json:"type,omitempty"`
	Enabled     *bool   `json:"enabled,omitempty"`
	LogoURL     *string `json:"logo_url,omitempty"`
}

type identityProvider struct {
	identityProviderSummary // inherit summary fields

	OIDCIdentityProviderConfiguation             *oidcConfig   `json:"oidc_configuration,omitempty"`
	SAMLIdentityProviderConfiguration            *samlConfig   `json:"saml_configuration,omitempty"`
	OktaWorkforceIdentityProviderConfiguration   *oktaConfig   `json:"okta_workforce_configuration,omitempty"`
	GoogleWorkspaceIdentityProviderConfiguration *googleConfig `json:"google_workspace_configuration,omitempty"`
}

type addIdentityProviderResponse struct {
	OIDCResponse            *oidcResponse            `json:"oidc_response,omitempty"`
	SAMLResponse            *samlResponse            `json:"saml_response,omitempty"`
	OktaWorkforceResponse   *oktaWorkforceResponse   `json:"okta_workforce_response,omitempty"`
	GoogleWorkspaceResponse *googleWorkspaceResponse `json:"google_workspace_response,omitempty"`
}

type oidcResponse struct {
	MustAllowRedirectURL string `json:"must_allow_redirect_url"`
}

type samlResponse struct {
	MustAllowRedirectURL         string `json:"must_allow_redirect_url"`
	RequestSigningCertificateURL string `json:"request_signing_certificate_url"`
}

type oktaWorkforceResponse struct {
	MustAllowRedirectURL string `json:"must_allow_redirect_url"`
}

type googleWorkspaceResponse struct {
	MustAllowRedirectURL      string `json:"must_allow_redirect_url"`
	MustAllowJavascriptOrigin string `json:"must_allow_javascript_origin"`
}

type toggleStatusRequest struct {
	Name   string `json:"name"`
	Global bool   `json:"global"`
	Enable bool   `json:"enable"`
}

type listIdentityProviderResponse struct {
	List []identityProviderSummary `json:"list"`
}

type flag struct {
	name      string
	shorthand string
	target    interface{}
	kind      reflect.Kind
	value     interface{}
	usage     string
	require   bool
}

func addCommandWithFlags(
	parent *cobra.Command,
	child *cobra.Command,
	flags ...flag,
) {
	set := child.Flags()

	for i, f := range flags {
		if f.name == "" {
			panic(fmt.Sprintf("flag at index %d has no name", i))
		}

		// assert flag has a non nil target
		if f.target == nil {
			panic(fmt.Sprintf("flag %s was given a nil target", f.name))
		}
		// assert flag has a non nil value
		if f.value == nil {
			panic(fmt.Sprintf("flag %s was given a nil value", f.name))
		}

		usage := f.usage
		if f.require {
			usage = fmt.Sprintf("[required] %s", usage)
		}

		switch f.kind {
		case reflect.Bool:
			// ensure target is pointer to string
			target, ok := f.target.(*bool)
			if !ok {
				panic(fmt.Sprintf("flag %s is of type bool but target was not a pointer to bool", f.name))
			}
			// ensure value is bool
			value, ok := f.value.(bool)
			if !ok {
				panic(fmt.Sprintf("flag %s is of type bool but value was not a bool", f.name))
			}
			set.BoolVarP(target, f.name, f.shorthand, value, usage)
		case reflect.String:
			// ensure target is pointer to string
			target, ok := f.target.(*string)
			if !ok {
				panic(fmt.Sprintf("flag %s is of type string but target was not a pointer to string", f.name))
			}
			// ensure value is string
			value, ok := f.value.(string)
			if !ok {
				panic(fmt.Sprintf("flag %s is of type string but value was not a string", f.name))
			}

			set.StringVarP(target, f.name, f.shorthand, value, usage)
		default:
			panic(fmt.Sprintf("flag %s was given an unhandled kind %s", f.name, f.kind.String()))
		}

		if f.require {
			if err := child.MarkFlagRequired(f.name); err != nil {
				panic(fmt.Sprintf("failed to mark flag %s as required: %s", f.name, err))
			}
		}
	}

	parent.AddCommand(child)
}

func countTrueValues(b ...bool) uint {
	trueValues := uint(0)
	for _, val := range b {
		if val {
			trueValues++
		}
	}
	return trueValues
}
