package cmd

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/borderzero/border0-cli/cmd/idp"
	"github.com/borderzero/border0-cli/internal/api/models"
	border0_http "github.com/borderzero/border0-cli/internal/http"
	"github.com/jedib0t/go-pretty/table"
	"github.com/spf13/cobra"
)

var defaultDomain bool

var organizationCmd = &cobra.Command{
	Use:   "organization",
	Short: "organization related commands",
}

var organizationShowCmd = &cobra.Command{
	Use:   "show",
	Short: "show organization info",
	Run: func(cmd *cobra.Command, args []string) {

		client, err := border0_http.NewClient()
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		org := models.Organization{}
		err = client.Request(http.MethodGet, "organization", &org, nil)
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		t := table.NewWriter()
		t.AppendRow(table.Row{"Name", org.Name})
		t.AppendRow(table.Row{"Subdomain", org.Subdomain + "." + domainSuffix})
		t.AppendRow(table.Row{"ID", org.ID})
		t.AppendRow(table.Row{"Certificate Authority", org.Certificates["mtls_certificate"]})
		t.AppendRow(table.Row{"SSH Authority", org.Certificates["ssh_public_key"]})
		t.SetStyle(table.StyleLight)
		fmt.Printf("%s\n", t.Render())

	},
}

var domainCmd = &cobra.Command{
	Use:   "domain",
	Short: "manage organization domains",
}

var domainListCmd = &cobra.Command{
	Use:   "list",
	Short: "list organization domains",
	Run: func(cmd *cobra.Command, args []string) {

		client, err := border0_http.NewClient()
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		domains := []models.Domain{}
		err = client.Request(http.MethodGet, "organizations/customdomains", &domains, nil)
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		t := table.NewWriter()
		t.AppendHeader(table.Row{"Name", "Default"})

		for _, domain := range domains {
			if domain.Default {
				t.AppendRow(table.Row{domain.Domain, "✔"})
			} else {
				t.AppendRow(table.Row{domain.Domain, ""})
			}
		}

		t.SetStyle(table.StyleLight)
		fmt.Printf("%s\n", t.Render())

	},
}

var domainAddCmd = &cobra.Command{
	Use:   "add [domain]",
	Short: "Add organization domain",
	Args:  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	Run: func(cmd *cobra.Command, args []string) {

		client, err := border0_http.NewClient()
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		domain := models.Domain{
			Domain: args[0],
		}

		err = client.Request(http.MethodPost, "organizations/customdomains", &domain, domain)
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		t := table.NewWriter()
		t.AppendRow(table.Row{"Domain", domain.Domain})
		if domain.Default {
			t.AppendRow(table.Row{"Default", "✔"})
		} else {
			t.AppendRow(table.Row{"Default", ""})
		}
		t.SetStyle(table.StyleLight)
		fmt.Printf("%s\n", t.Render())
	},
}

var domainRemoveCmd = &cobra.Command{
	Use:               "remove [domain]",
	Short:             "Remove organization domain",
	Args:              cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	ValidArgsFunction: autocompleteDomain,
	Run: func(cmd *cobra.Command, args []string) {

		client, err := border0_http.NewClient()
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		domain := models.Domain{
			Domain: args[0],
		}

		err = client.Request(http.MethodDelete, "organizations/customdomains", &domain, domain)
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		fmt.Printf("Domain %s successfully removed\n", args[0])
	},
}

var domainUpdateCmd = &cobra.Command{
	Use:               "update [domain]",
	Short:             "Update organization domain",
	Args:              cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	ValidArgsFunction: autocompleteDomain,
	Run: func(cmd *cobra.Command, args []string) {

		client, err := border0_http.NewClient()
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		domain := models.Domain{
			Domain:  args[0],
			Default: defaultDomain,
		}

		err = client.Request(http.MethodPut, "organizations/customdomains", &domain, domain)
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		t := table.NewWriter()
		t.AppendRow(table.Row{"Domain", domain.Domain})
		if domain.Default {
			t.AppendRow(table.Row{"Default", "✔"})
		} else {
			t.AppendRow(table.Row{"Default", ""})
		}
		t.SetStyle(table.StyleLight)
		fmt.Printf("%s\n", t.Render())
	},
}

func autocompleteDomain(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	var domainNames []string

	client, err := border0_http.NewClient()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	domains := []models.Domain{}
	err = client.Request(http.MethodGet, "organizations/customdomains", &domains, nil)
	if err != nil {
		log.Fatalf(fmt.Sprintf("Error: %v", err))
	}

	for _, d := range domains {
		if strings.HasPrefix(d.Domain, toComplete) {
			domainNames = append(domainNames, d.Domain)
		}
	}

	return domainNames, cobra.ShellCompDirectiveNoFileComp
}

func init() {
	organizationCmd.AddCommand(organizationShowCmd)
	organizationCmd.AddCommand(domainCmd)
	organizationCmd.AddCommand(idp.GetIDPCmdRoot())
	domainCmd.AddCommand(domainListCmd)
	domainCmd.AddCommand(domainAddCmd)
	domainCmd.AddCommand(domainRemoveCmd)
	domainCmd.AddCommand(domainUpdateCmd)
	rootCmd.AddCommand(organizationCmd)

	domainUpdateCmd.Flags().BoolVarP(&defaultDomain, "default", "d", false, "set domain as default domain for organization")
	domainAddCmd.Flags().BoolVarP(&defaultDomain, "default", "d", false, "set domain as default domain for organization")
}
