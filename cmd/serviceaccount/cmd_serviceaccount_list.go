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

func getServiceAccountListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "list service accounts in an organization",
		Run:   getServiceAccountListCmdHandler(),
	}
}

func getServiceAccountListCmdHandler() func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		client, err := border0.NewClient()
		if err != nil {
			util.FailPretty("failed to get Border0 API client: %s", err)
		}

		type serviceAccountList struct {
			List  []serviceAccountSummary `json:"list"`
			Items int                     `json:"items"`
		}

		var resp serviceAccountList
		if err = client.Request(http.MethodGet, "organizations/iam/service_accounts", &resp, nil); err != nil {
			util.FailPretty("failed to list service accounts: %s", err)
		}

		if jsonOutput {
			jsonBytes, err := json.Marshal(resp)
			if err != nil {
				util.FailPretty("failed to marshal response as json: %s", err)
			}
			fmt.Println(string(jsonBytes))
			return
		}

		serviceAccountsTable := table.NewWriter()
		serviceAccountsTable.AppendHeader(table.Row{"Name", "Role", "Active", "Description", "Created At", "Updated At"})

		for _, sacc := range resp.List {
			serviceAccountsTable.AppendRow(table.Row{sacc.Name, sacc.Role, sacc.Active, sacc.Description, sacc.CreatedAt, sacc.UpdatedAt})
		}

		if serviceAccountsTable.Length() > 0 {
			fmt.Println(serviceAccountsTable.Render())
		} else {
			fmt.Println("no service accounts to show")
		}
	}
}
