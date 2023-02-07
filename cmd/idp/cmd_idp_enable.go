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
	idpEnableName   string
	idpEnableGoogle bool
	idpEnableGithub bool
)

func getIDPEnableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "enable",
		Short: "enable an identity provider for an organization",
		Run:   getIDPEnableCmdHandler(),
	}
}

func getIDPEnableCmdHandler() func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		client, err := border0.NewClient()
		if err != nil {
			util.FailPretty("failed to get Border0 API client: %s", err)
		}

		if (idpEnableName != "" && (idpEnableGoogle || idpEnableGithub)) ||
			(idpEnableName == "" && !idpEnableGoogle && !idpEnableGithub) ||
			(idpEnableGoogle && idpEnableGithub) {
			cmd.Help()
			util.FailPretty("one (and only one) of --google, --github, or --name must set")
		}

		if idpEnableGoogle {
			idpEnableName = identityProviderTypeGlobalGoogle
		}
		if idpEnableGithub {
			idpEnableName = identityProviderTypeGlobalGithub
		}

		reqBody := &toggleStatusRequest{
			Name:   idpEnableName,
			Global: idpEnableGoogle || idpEnableGithub,
			Enable: true,
		}

		if err = client.Request(http.MethodPut, "organization/identity_provider_status", nil, reqBody); err != nil {
			util.FailPretty("failed to enable identity provider status: %s", err)
		}

		fmt.Println(fmt.Sprintf("\nSuccessfully enabled identity provider \"%s\" for your organization!", idpEnableName))
	}
}
