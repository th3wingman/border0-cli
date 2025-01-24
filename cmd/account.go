/*
Copyright © 2020 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-cli/internal/http"
	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

// accountCmd represents the account command
var accountCmd = &cobra.Command{
	Use:   "account",
	Short: "Create a new account or see account information.",
}

var listOrgs = &cobra.Command{
	Use:   "list-orgs",
	Short: "List all organizations your user belongs to",
	Run: func(cmd *cobra.Command, args []string) {
		client, err := http.NewClient()
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		_, userID, err := http.GetUserID()
		if err != nil {
			log.Fatalf("error: %v", err)
		}
		account := models.Account{}
		err = client.Request("GET", "user/"+*userID, &account, nil)
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		orgs := []models.Organization{}
		err = client.Request("GET", "organizations/list", &orgs, nil)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error: %v", err))
		}

		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		t := table.NewWriter()
		t.AppendHeader(table.Row{"Name", "Current"})

		blue := color.New(color.FgBlue)

		for _, org := range orgs {
			currentOrg := "No"
			if org.ID == account.Organization.ID {
				currentOrg = "Yes"
			}
			row := table.Row{
				org.Subdomain + " " + blue.Sprintf("[%s]", org.Name),
				currentOrg,
			}
			t.AppendRow(row)
		}
		t.SetStyle(table.StyleLight)
		fmt.Printf("%s\n", t.Render())
	},
}

var switchOrg = &cobra.Command{
	Use:   "switch-org",
	Short: "Switch to a different organization",
	Run: func(cmd *cobra.Command, args []string) {
		form := models.SwitchOrgRequest{OrgName: orgName}

		client, err := http.NewClient()
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		val := &models.SwitchOrgResponse{}

		err = client.Request("POST", "organizations/switch", val, &form)

		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("Switching to organization: %s\n", val.OrgName)

		// create dir if not exists
		configPath := filepath.Dir(http.TokenFilePath())
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			if err := os.Mkdir(configPath, 0700); err != nil {
				log.Fatalf("failed to create directory %s : %s", configPath, err)
			}
		}

		f, err := os.Create(http.TokenFilePath())
		if err != nil {
			log.Fatal(err)
		}

		if err := os.Chmod(http.TokenFilePath(), 0600); err != nil {
			log.Fatal(err)
		}

		defer f.Close()
		_, err = f.WriteString(fmt.Sprintf("%s\n", val.Token))
		if err != nil {
			log.Fatal(err)
		}
	},
}

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new account",
	Run: func(cmd *cobra.Command, args []string) {
		err := http.Register(name, email, password)
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		fmt.Println("Congratulation! your account has been created. Please check your email.")
		fmt.Println("Please complete the account registration by following the confirmation link in your email.")
		fmt.Println("After that login with login --email '<EMAIL>' --password '*****'")
	},
}

var showCmd = &cobra.Command{
	Use:   "show",
	Short: "Show account information",
	Run: func(cmd *cobra.Command, args []string) {
		_, userID, err := http.GetUserID()
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		client, err := http.NewClient()
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		account := models.Account{}
		err = client.Request("GET", "user/"+*userID, &account, nil)
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		t := table.NewWriter()
		t.AppendRow(table.Row{"Name", account.Name})
		t.AppendRow(table.Row{"Email", account.Email})
		t.AppendRow(table.Row{"User ID", account.UserID})
		t.AppendRow(table.Row{"SSH Username", account.SshUsername})
		t.AppendRow(table.Row{"SSH Key", splitLongLines(account.SshKey, 80)})
		t.SetStyle(table.StyleLight)
		fmt.Printf("%s\n", t.Render())
	},
}

func init() {

	createCmd.Flags().StringVarP(&email, "email", "e", "", "your email address")
	createCmd.Flags().StringVarP(&name, "name", "n", "", "your name")
	createCmd.Flags().StringVarP(&password, "password", "p", "", "your pasword")
	createCmd.MarkFlagRequired("email")
	createCmd.MarkFlagRequired("name")
	createCmd.MarkFlagRequired("password")
	createCmd.Flags().MarkHidden("sshkey")

	switchOrg.Flags().StringVarP(&orgName, "name", "", "", "organization name")
	switchOrg.MarkFlagRequired("name")

	accountCmd.AddCommand(createCmd)
	accountCmd.AddCommand(showCmd)
	accountCmd.AddCommand(listOrgs)
	accountCmd.AddCommand(switchOrg)
	rootCmd.AddCommand(accountCmd)
}
