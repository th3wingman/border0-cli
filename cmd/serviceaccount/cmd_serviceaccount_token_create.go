package serviceaccount

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	border0 "github.com/borderzero/border0-cli/internal/http"
	"github.com/jedib0t/go-pretty/table"

	"github.com/borderzero/border0-cli/internal/util"
	"github.com/spf13/cobra"
)

func getServiceAccountTokenCreateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "create",
		Short: "create a service account token in an organization",
		Run:   getServiceAccountTokenCreateCmdHandler(),
	}
}

func getServiceAccountTokenCreateCmdHandler() func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		client, err := border0.NewClient()
		if err != nil {
			util.FailPretty("failed to get Border0 API client: %s", err)
		}

		if name == "" {
			util.FailPretty("service-account-name is a required flag")
		}
		if tokenName == "" {
			util.FailPretty("token-name is a required flag")
		}

		req := struct {
			Name      string `json:"name"`
			ExpiresAt int64  `json:"expires_at"`
		}{
			Name: tokenName,
		}

		if lifetimeDays != 0 {
			req.ExpiresAt = time.Now().Add(time.Duration(lifetimeDays) * time.Hour * 24).Unix()
		}

		var resp tokenSummary
		if err = client.Request(http.MethodPost, fmt.Sprintf("organizations/iam/service_accounts/%s/tokens", name), &resp, req); err != nil {
			util.FailPretty("failed to create service account token: %s", err)
		}

		if jsonOutput {
			jsonBytes, err := json.Marshal(resp)
			if err != nil {
				util.FailPretty("failed to marshal response as json: %s", err)
			}
			fmt.Println(string(jsonBytes))
			return
		}

		exp := resp.ExpiresAt
		if exp == "" {
			exp = "never expires"
		}

		serviceAccountTokenTable := table.NewWriter()
		serviceAccountTokenTable.AppendHeader(table.Row{"ID", "Name", "Expires At"})
		serviceAccountTokenTable.AppendRow(table.Row{resp.ID, resp.Name, exp})
		fmt.Println(serviceAccountTokenTable.Render())
		fmt.Printf("\nToken: %s\n", resp.Token)
	}
}
