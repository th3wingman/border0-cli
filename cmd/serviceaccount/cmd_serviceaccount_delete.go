package serviceaccount

import (
	"fmt"
	"net/http"

	border0 "github.com/borderzero/border0-cli/internal/http"

	"github.com/borderzero/border0-cli/internal/util"
	"github.com/spf13/cobra"
)

func getServiceAccountDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete",
		Short: "delete a service account in an organization",
		Run:   getServiceAccountDeleteCmdHandler(),
	}
}

func getServiceAccountDeleteCmdHandler() func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		client, err := border0.NewClient()
		if err != nil {
			util.FailPretty("failed to get Border0 API client: %s", err)
		}

		if name == "" {
			util.FailPretty("name is a required flag")
		}

		if err = client.Request(http.MethodDelete, fmt.Sprintf("organizations/iam/service_accounts/%s", name), nil, nil); err != nil {
			util.FailPretty("failed to delete service account %s: %s", name, err)
		}

		fmt.Printf("service account %s deleted successfully!\n", name)
	}
}
