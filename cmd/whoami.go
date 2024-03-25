/*
Copyright © 2020 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARR    ANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	"strings"

	"github.com/borderzero/border0-cli/internal"
	"github.com/borderzero/border0-cli/internal/api"
	"github.com/jedib0t/go-pretty/table"

	"github.com/spf13/cobra"
)

// whoamiCmd represents the whoami command
var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "show authenticated identity details",

	RunE: func(cmd *cobra.Command, args []string) error {
		border0API := api.NewAPI(api.WithVersion(internal.Version))
		details, err := border0API.Whoami(cmd.Context())
		if err != nil {
			return fmt.Errorf("failed to get authenticated identity details: %v", err)
		}

		ta := table.NewWriter()

		ta.AppendRow(table.Row{"ORGANIZATION", details["organization"]})
		ta.AppendRow(table.Row{"IDENTITY TYPE", details["type"]})
		ta.AppendRow(table.Row{"IDENTITY NAME", details["name"]})
		ta.AppendRow(table.Row{"IDENTITY ID", details["id"]})
		ta.AppendRow(table.Row{"IDENTITY ROLE", details["role"]})

		delete(details, "organization")
		delete(details, "type")
		delete(details, "name")
		delete(details, "id")
		delete(details, "role")

		for k, v := range details {
			ta.AppendRow(table.Row{strings.ToUpper(strings.ReplaceAll(k, "_", " ")), v})
		}
		ta.SetStyle(table.StyleLight)
		fmt.Printf("%s\n", ta.Render())

		return nil
	},
}

func init() {
	rootCmd.AddCommand(whoamiCmd)
}
