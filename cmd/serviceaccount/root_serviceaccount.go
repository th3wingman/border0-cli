package serviceaccount

import (
	"github.com/spf13/cobra"
)

func GetServiceAccountCmdRoot() *cobra.Command {
	svcAccountShowCmd := getServiceAccountShowCmd()
	svcAccountShowCmd.Flags().StringVarP(&name, "name", "n", "", "service account name")
	svcAccountShowCmd.Flags().BoolVarP(&jsonOutput, "json", "j", false, "print json output")

	svcAccountListCmd := getServiceAccountListCmd()
	svcAccountListCmd.Flags().BoolVarP(&jsonOutput, "json", "j", false, "print json output")

	svcAccountCreateCmd := getServiceAccountCreateCmd()
	svcAccountCreateCmd.Flags().StringVarP(&name, "name", "n", "", "service account name")
	svcAccountCreateCmd.Flags().StringVarP(&description, "description", "d", "", "service account description")
	svcAccountCreateCmd.Flags().StringVarP(&role, "role", "r", "", "service account role e.g. 'client', 'member', 'admin'")
	svcAccountCreateCmd.Flags().BoolVarP(&jsonOutput, "json", "j", false, "print json output")

	svcAccountUpdateCmd := getServiceAccountUpdateCmd()
	svcAccountUpdateCmd.Flags().StringVarP(&name, "name", "n", "", "service account name")
	svcAccountUpdateCmd.Flags().StringVarP(&description, "description", "d", "", "service account description")
	svcAccountUpdateCmd.Flags().StringVarP(&role, "role", "r", "", "service account role e.g. 'client', 'member', 'admin'")
	svcAccountUpdateCmd.Flags().StringVarP(&active, "active", "a", "", "service account status (true for active, false for inactive)")
	svcAccountUpdateCmd.Flags().BoolVarP(&jsonOutput, "json", "j", false, "print json output")

	svcAccountDeleteCmd := getServiceAccountDeleteCmd()
	svcAccountDeleteCmd.Flags().StringVarP(&name, "name", "n", "", "service account name")

	serviceAccountCmdRoot := &cobra.Command{
		Use:   "service-account",
		Short: "manage service accounts for an organization",
	}
	serviceAccountCmdRoot.AddCommand(
		svcAccountShowCmd,
		svcAccountListCmd,
		svcAccountCreateCmd,
		svcAccountUpdateCmd,
		svcAccountDeleteCmd,
		GetServiceAccountTokenCmdRoot(),
	)
	return serviceAccountCmdRoot
}
