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
	idpRemoveName string
)

func getIDPRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove",
		Short: "remove an identity provider from an organization",
		Run:   getIDPRemoveCmdHandler(),
	}
}

func getIDPRemoveCmdHandler() func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		client, err := border0.NewClient()
		if err != nil {
			util.FailPretty("failed to get Border0 API client: %s", err)
		}
		if err = client.Request(http.MethodDelete, fmt.Sprintf("organization/identity_provider/%s", idpRemoveName), nil, nil); err != nil {
			util.FailPretty("failed to remove identity provider: %s", err)
		}
		fmt.Println(fmt.Sprintf("\nIdentity provider \"%s\" successfully removed from your organization!", idpRemoveName))
	}
}
