package serviceaccount

import (
	"encoding/json"
	"fmt"
	"net/http"

	border0 "github.com/borderzero/border0-cli/internal/http"
	"github.com/jedib0t/go-pretty/table"

	"github.com/borderzero/border0-cli/internal/util"
	"github.com/spf13/cobra"
)

var (
	serviceAccountShowCmd = &cobra.Command{
		Use:   "show",
		Short: "describe a service account in an organization",
	}
)

func getServiceAccountShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "describe a service account in an organization",
		Run:   getServiceAccountShowCmdHandler(),
	}
}

func getServiceAccountShowCmdHandler() func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		client, err := border0.NewClient()
		if err != nil {
			util.FailPretty("failed to get Border0 API client: %s", err)
		}

		if name == "" {
			util.FailPretty("name is a required flag")
		}

		var resp serviceAccountSummary
		if err = client.Request(http.MethodGet, fmt.Sprintf("organizations/iam/service_accounts/%s", name), &resp, nil); err != nil {
			util.FailPretty("failed to get service account: %s", err)
		}

		if jsonOutput {
			jsonBytes, err := json.Marshal(resp)
			if err != nil {
				util.FailPretty("failed to marshal response as json: %s", err)
			}
			fmt.Println(string(jsonBytes))
			return
		}

		serviceAccountTable := table.NewWriter()
		serviceAccountTable.AppendRow(table.Row{"Name", resp.Name})
		serviceAccountTable.AppendRow(table.Row{"Role", resp.Role})
		serviceAccountTable.AppendRow(table.Row{"Active", resp.Active})
		serviceAccountTable.AppendRow(table.Row{"Description", resp.Description})
		serviceAccountTable.AppendRow(table.Row{"Created At", resp.CreatedAt})
		serviceAccountTable.AppendRow(table.Row{"Updated At", resp.UpdatedAt})
		fmt.Println(serviceAccountTable.Render())
	}
}
