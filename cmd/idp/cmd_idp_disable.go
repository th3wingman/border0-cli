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
	idpDisableName   string
	idpDisableGoogle bool
	idpDisableGithub bool
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

		if (idpDisableName != "" && (idpDisableGoogle || idpDisableGithub)) ||
			(idpDisableName == "" && !idpDisableGoogle && !idpDisableGithub) ||
			(idpDisableGoogle && idpDisableGithub) {
			cmd.Help()
			util.FailPretty("one (and only one) of --google, --github, or --name must set")
		}

		if idpDisableGoogle {
			idpDisableName = identityProviderTypeGlobalGoogle
		}
		if idpDisableGithub {
			idpDisableName = identityProviderTypeGlobalGithub
		}

		reqBody := &toggleStatusRequest{
			Name:   idpDisableName,
			Global: idpDisableGoogle || idpDisableGithub,
			Enable: false,
		}

		if err = client.Request(http.MethodPut, "organization/identity_provider_status", nil, reqBody); err != nil {
			util.FailPretty("failed to disable identity provider status: %s", err)
		}

		fmt.Println(fmt.Sprintf("\nSuccessfully disabled identity provider \"%s\" for your organization!", idpDisableName))
	}
}
