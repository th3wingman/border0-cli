package cmd

import (
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/borderzero/border0-cli/cmd/idp"
	"github.com/borderzero/border0-cli/internal/api/models"
	border0_http "github.com/borderzero/border0-cli/internal/http"
	"github.com/jedib0t/go-pretty/table"
	"github.com/spf13/cobra"
)

var (
	defaultDomain               bool
	notificationType            string
	notificationEnabled         bool
	notificationWebhookUrl      string
	notificationEmailRecipients []string
	notificationEvents          []string
)

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

		if !cmd.Flags().Changed("default") {
			log.Fatalf("error: --default flag is required")
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

func autocompleteNotification(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	var notificationNames []string

	client, err := border0_http.NewClient()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	notifications := []models.Notification{}
	err = client.Request(http.MethodGet, "organizations/notifications", &notifications, nil)
	if err != nil {
		log.Fatalf(fmt.Sprintf("Error: %v", err))
	}

	for _, notification := range notifications {
		if strings.HasPrefix(notification.Name, toComplete) {
			notificationNames = append(notificationNames, notification.Name)
		}
	}

	return notificationNames, cobra.ShellCompDirectiveNoFileComp
}

var notificationCmd = &cobra.Command{
	Use:   "notification",
	Short: "manage organization notifications",
}

var notificationListCmd = &cobra.Command{
	Use:   "list",
	Short: "list organization notifications",
	Run: func(cmd *cobra.Command, args []string) {
		client, err := border0_http.NewClient()
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		notifications := []models.Notification{}
		err = client.Request(http.MethodGet, "organizations/notifications", &notifications, nil)
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		t := table.NewWriter()
		t.AppendHeader(table.Row{"Name", "Type", "Enabled"})

		for _, notification := range notifications {
			var enabled string
			if notification.Enabled {
				enabled = "✔"
			} else {
				enabled = ""
			}
			t.AppendRow(table.Row{notification.Name, notification.Type, enabled})
		}

		t.SetStyle(table.StyleLight)
		fmt.Printf("%s\n", t.Render())

	},
}

var notificationShowCmd = &cobra.Command{
	Use:               "show [name]",
	Short:             "Show organization notification",
	Args:              cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	ValidArgsFunction: autocompleteNotification,
	Run: func(cmd *cobra.Command, args []string) {
		client, err := border0_http.NewClient()
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		var notification models.Notification
		err = client.Request(http.MethodGet, "organizations/notifications/"+args[0], &notification, nil)
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		t := table.NewWriter()
		var enabled string
		if notification.Enabled {
			enabled = "✔"
		} else {
			enabled = ""
		}
		t.AppendRow(table.Row{"Name", notification.Name})
		t.AppendRow(table.Row{"Type", notification.Type})
		t.AppendRow(table.Row{"Enabled", enabled})
		switch notification.Type {
		case "webhook":
			t.AppendRow(table.Row{"Webhook URL", notification.WebhookURL})
		case "email":
			t.AppendRow(table.Row{"Email Recipients", strings.Join(notification.EmailRecipients, "\n")})
		}
		t.AppendRow(table.Row{"Events", strings.Join(notification.Events, "\n")})

		t.SetStyle(table.StyleLight)
		fmt.Printf("%s\n", t.Render())
	},
}

var notificationAddCmd = &cobra.Command{
	Use:   "add [name]",
	Short: "Add organization notification",
	Args:  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	Run: func(cmd *cobra.Command, args []string) {
		client, err := border0_http.NewClient()
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		var slugRegex = regexp.MustCompile(`(^[a-z0-9-]+$)`)

		if !slugRegex.MatchString(args[0]) {
			log.Fatalf("name must contains only lowercase letters, numbers and dashes")
		}

		if len(notificationEvents) == 0 {
			log.Fatalf("error: notification events must be specified")
		}

		for _, event := range notificationEvents {
			if event != "login-success" && event != "login-failure" && event != "audit-evetns" {
				log.Fatalf("error: notification event must be any of login-success, login-failure or audit-events")
			}
		}

		notification := models.Notification{
			Name:    args[0],
			Type:    notificationType,
			Enabled: notificationEnabled,
			Events:  notificationEvents,
		}

		switch notification.Type {
		case "email":
			notification.EmailRecipients = notificationEmailRecipients
		case "webhook":
			notification.WebhookURL = notificationWebhookUrl
		default:
			log.Fatalf("error: notification type must be email or webhook")
		}

		err = client.Request(http.MethodPost, "organizations/notifications", &notification, notification)
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		t := table.NewWriter()
		var enabled string
		if notification.Enabled {
			enabled = "✔"
		} else {
			enabled = ""
		}
		t.AppendRow(table.Row{"Name", notification.Name})
		t.AppendRow(table.Row{"Type", notification.Type})
		t.AppendRow(table.Row{"Enabled", enabled})
		switch notification.Type {
		case "webhook":
			t.AppendRow(table.Row{"Webhook URL", notification.WebhookURL})
		case "email":
			t.AppendRow(table.Row{"Email Recipients", strings.Join(notification.EmailRecipients, "\n")})
		}
		t.AppendRow(table.Row{"Events", strings.Join(notification.Events, "\n")})

		t.SetStyle(table.StyleLight)
		fmt.Printf("%s\n", t.Render())
	},
}

var notificationRemoveCmd = &cobra.Command{
	Use:               "remove [name]",
	Short:             "Remove organization notification",
	Args:              cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	ValidArgsFunction: autocompleteNotification,
	Run: func(cmd *cobra.Command, args []string) {
		client, err := border0_http.NewClient()
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		err = client.Request(http.MethodDelete, "organizations/notifications/"+args[0], nil, nil)
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		fmt.Printf("Notification %s successfully removed\n", args[0])
	},
}

var notificationUpdateCmd = &cobra.Command{
	Use:               "update [name]",
	Short:             "Update organization notification",
	Args:              cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	ValidArgsFunction: autocompleteNotification,
	Run: func(cmd *cobra.Command, args []string) {
		client, err := border0_http.NewClient()
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		var notification models.Notification
		var notificationUpdate models.NotificationUpdate

		if cmd.Flags().Changed("enabled") {
			notificationUpdate.Enabled = &notificationEnabled
		}

		if len(notificationEvents) > 0 {
			notificationUpdate.Events = notificationEvents
		}

		if len(notificationEmailRecipients) > 0 {
			notificationUpdate.EmailRecipients = notificationEmailRecipients
		}

		if notificationWebhookUrl != "" {
			notificationUpdate.WebhookURL = &notificationWebhookUrl
		}

		err = client.Request(http.MethodPut, "organizations/notifications/"+args[0], &notification, notificationUpdate)
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		t := table.NewWriter()
		var enabled string
		if notification.Enabled {
			enabled = "✔"
		} else {
			enabled = ""
		}
		t.AppendRow(table.Row{"Name", notification.Name})
		t.AppendRow(table.Row{"Type", notification.Type})
		t.AppendRow(table.Row{"Enabled", enabled})
		switch notification.Type {
		case "webhook":
			t.AppendRow(table.Row{"Webhook URL", notification.WebhookURL})
		case "email":
			t.AppendRow(table.Row{"Email Recipients", strings.Join(notification.EmailRecipients, "\n")})
		}
		t.AppendRow(table.Row{"Events", strings.Join(notification.Events, "\n")})

		t.SetStyle(table.StyleLight)
		fmt.Printf("%s\n", t.Render())
	},
}

func init() {
	organizationCmd.AddCommand(organizationShowCmd)
	organizationCmd.AddCommand(domainCmd)
	organizationCmd.AddCommand(idp.GetIDPCmdRoot())
	organizationCmd.AddCommand(notificationCmd)

	domainCmd.AddCommand(domainListCmd)
	domainCmd.AddCommand(domainAddCmd)
	domainCmd.AddCommand(domainRemoveCmd)
	domainCmd.AddCommand(domainUpdateCmd)

	notificationCmd.AddCommand(notificationListCmd)
	notificationCmd.AddCommand(notificationShowCmd)
	notificationCmd.AddCommand(notificationAddCmd)
	notificationCmd.AddCommand(notificationRemoveCmd)
	notificationCmd.AddCommand(notificationUpdateCmd)

	rootCmd.AddCommand(organizationCmd)

	domainUpdateCmd.Flags().BoolVarP(&defaultDomain, "default", "d", false, "set domain as default domain for organization")
	domainAddCmd.Flags().BoolVarP(&defaultDomain, "default", "d", false, "set domain as default domain for organization")

	notificationAddCmd.Flags().StringVarP(&notificationType, "type", "t", "", "notification type (webhook or email)")
	notificationAddCmd.Flags().BoolVarP(&notificationEnabled, "enabled", "e", true, "notification enabled")
	notificationAddCmd.Flags().StringVarP(&notificationWebhookUrl, "webhook-url", "u", "", "webhook url")
	notificationAddCmd.Flags().StringSliceVarP(&notificationEmailRecipients, "email-recipient", "r", []string{}, "email recipients, can be specified multiple times")
	notificationAddCmd.Flags().StringSliceVarP(&notificationEvents, "events", "v", []string{}, "notification events, can be specified multiple times (login-success, login-failure, audit-events)")

	notificationUpdateCmd.Flags().BoolVarP(&notificationEnabled, "enabled", "e", true, "notification enabled")
	notificationUpdateCmd.Flags().StringVarP(&notificationWebhookUrl, "webhook-url", "u", "", "webhook url")
	notificationUpdateCmd.Flags().StringSliceVarP(&notificationEmailRecipients, "email-recipient", "r", []string{}, "email recipients, can be specified multiple times")
	notificationUpdateCmd.Flags().StringSliceVarP(&notificationEvents, "events", "v", []string{}, "notification events, can be specified multiple times (login-success, login-failure, audit-events)")
}
