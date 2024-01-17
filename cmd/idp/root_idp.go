package idp

import (
	"reflect"

	"github.com/spf13/cobra"
)

func GetIDPCmdRoot() *cobra.Command {
	identityProviderCmdRoot := &cobra.Command{
		Use:   "idp",
		Short: "manage identity providers for an organization",
	}

	// idp add
	addCommandWithFlags(
		identityProviderCmdRoot,
		getIDPAddCmdRoot(),
	)

	// idp update
	addCommandWithFlags(
		identityProviderCmdRoot,
		getIDPUpdateCmdRoot(),
	)

	// idp enable
	addCommandWithFlags(
		identityProviderCmdRoot,
		getIDPEnableCmd(),
		flag{name: "name", shorthand: "n", target: &idpEnableName, kind: reflect.String, value: "", usage: "[required if no other flags provided] the name of the identity provider to enable", require: false},
		flag{name: "google", target: &idpEnableGoogle, kind: reflect.Bool, value: false, usage: "true if enabling the google global provider", require: false},
		flag{name: "github", target: &idpEnableGithub, kind: reflect.Bool, value: false, usage: "true if enabling the github global provider", require: false},
		flag{name: "microsoft", target: &idpEnableMicrosoft, kind: reflect.Bool, value: false, usage: "true if enabling the microsoft global provider", require: false},
		flag{name: "email-code", target: &idpEnableEmailCode, kind: reflect.Bool, value: false, usage: "true if enabling the email code global provider", require: false},
	)

	// idp disable
	addCommandWithFlags(
		identityProviderCmdRoot,
		getIDPDisableCmd(),
		flag{name: "name", shorthand: "n", target: &idpDisableName, kind: reflect.String, value: "", usage: "[required if no other flags provided] the name of the identity provider to disable", require: false},
		flag{name: "google", target: &idpDisableGoogle, kind: reflect.Bool, value: false, usage: "true if disabling the google global provider", require: false},
		flag{name: "github", target: &idpDisableGithub, kind: reflect.Bool, value: false, usage: "true if disabling the github global provider", require: false},
		flag{name: "microsoft", target: &idpDisableMicrosoft, kind: reflect.Bool, value: false, usage: "true if disabling the email code global provider", require: false},
		flag{name: "email-code", target: &idpDisableEmailCode, kind: reflect.Bool, value: false, usage: "true if enabling the email code global provider", require: false},
	)

	// idp remove
	addCommandWithFlags(
		identityProviderCmdRoot,
		getIDPRemoveCmd(),
		flag{name: "name", shorthand: "n", target: &idpRemoveName, kind: reflect.String, value: "", usage: "the name of the identity provider to remove", require: true},
	)

	// idp list
	addCommandWithFlags(
		identityProviderCmdRoot,
		getIDPListCmd(),
		flag{name: "json", shorthand: "j", target: &idpListJSONOutput, kind: reflect.Bool, value: false, usage: "true for json output instead of pretty-printed table", require: false},
	)

	// idp show
	addCommandWithFlags(
		identityProviderCmdRoot,
		getIDPShowCmd(),
		flag{name: "name", shorthand: "n", target: &idpShowName, kind: reflect.String, value: "", usage: "the name of the identity provider to show", require: true},
		flag{name: "json", shorthand: "j", target: &idpShowJSONOutput, kind: reflect.Bool, value: false, usage: "true for json output instead of pretty-printed table", require: false},
	)

	return identityProviderCmdRoot
}
