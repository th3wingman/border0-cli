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
	idpDisableName      string
	idpDisableGoogle    bool
	idpDisableGithub    bool
	idpDisableMicrosoft bool
	idpDisableEmailCode bool
)

func getIDPDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable",
		Short: "disable an identity provider for an organization",
		Run:   getIDPDisableCmdHandler(),
	}
}

func getIDPDisableCmdHandler() func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		client, err := border0.NewClient()
		if err != nil {
			util.FailPretty("failed to get Border0 API client: %s", err)
		}

		globals := countTrueValues(idpDisableGoogle, idpDisableGithub, idpDisableMicrosoft, idpDisableEmailCode)
		isGlobal := globals > 0

		if (idpDisableName != "" && isGlobal) || (idpDisableName == "" && !isGlobal) || (globals > 1) {
			cmd.Help()
			util.FailPretty("one (and only one) of --google, --github, --microsoft, --email-code, or --name must set")
		}

		if idpDisableGoogle {
			idpDisableName = identityProviderTypeGlobalGoogle
		}
		if idpDisableGithub {
			idpDisableName = identityProviderTypeGlobalGithub
		}
		if idpDisableMicrosoft {
			idpDisableName = identityProviderTypeGlobalMicrosoft
		}
		if idpDisableEmailCode {
			idpDisableName = identityProviderTypeGlobalEmailCode
		}

		reqBody := &toggleStatusRequest{
			Name:   idpDisableName,
			Global: isGlobal,
			Enable: false,
		}

		if err = client.Request(http.MethodPut, "organization/identity_provider_status", nil, reqBody); err != nil {
			util.FailPretty("failed to disable identity provider status: %s", err)
		}

		fmt.Println(fmt.Sprintf("\nSuccessfully disabled identity provider \"%s\" for your organization!", idpDisableName))
	}
}
