package idp

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	border0 "github.com/borderzero/border0-cli/internal/http"
	"github.com/borderzero/border0-cli/internal/util"
	"github.com/jedib0t/go-pretty/table"
	"github.com/spf13/cobra"
)

var (
	// flags
	idpListJSONOutput bool
)

func getIDPListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "list identity providers for the current organization",
		Run:   getIDPListCmdHandler(),
	}
}

func getIDPListCmdHandler() func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		client, err := border0.NewClient()
		if err != nil {
			util.FailPretty("failed to get Border0 API client: %s", err)
		}

		type idpList struct {
			List []identityProviderSummary `json:"list"`
		}

		var resp idpList

		if err = client.Request(http.MethodGet, "organization/identity_providers", &resp, nil); err != nil {
			util.FailPretty("failed to list identity providers: %s", err)
		}

		if idpListJSONOutput {
			jsonBytes, err := json.Marshal(resp)
			if err != nil {
				util.FailPretty("failed to marshal response as json: %s", err)
			}

			fmt.Println(string(jsonBytes))
			return
		}

		// init global providers table
		global := table.NewWriter()
		global.AppendHeader(table.Row{"Name", "Enabled"})

		// init custom providers table
		custom := table.NewWriter()
		custom.AppendHeader(table.Row{"Name", "DisplayName", "Type", "Enabled"})

		for _, provider := range resp.List {
			if provider.Enabled != nil && provider.LogoURL != nil && provider.Name != nil && provider.Type != nil {
				if *provider.Type == "global" {
					global.AppendRow(table.Row{*provider.Name, *provider.Enabled})
					continue
				}
				custom.AppendRow(table.Row{*provider.Name, *provider.DisplayName, *provider.Type, *provider.Enabled})
			} else {
				// better than panic or empty fields
				log.Println(fmt.Sprintf("%s Some fields for an identity provider were unexpectedly empty, contact support@border0.com", warningBanner))
			}
		}

		if global.Length() > 0 {
			fmt.Println("\nGlobal:")
			fmt.Println(global.Render())
		}

		if custom.Length() > 0 {
			fmt.Println("\nCustom:")
			fmt.Println(custom.Render())
		}
	}
}
