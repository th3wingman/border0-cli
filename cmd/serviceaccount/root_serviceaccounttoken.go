package serviceaccount

import (
	"github.com/spf13/cobra"
)

func GetServiceAccountTokenCmdRoot() *cobra.Command {
	svcAccountTokenCreateCmd := getServiceAccountTokenCreateCmd()
	svcAccountTokenCreateCmd.Flags().StringVarP(&name, "service-account-name", "s", "", "service account name")
	svcAccountTokenCreateCmd.Flags().StringVarP(&tokenName, "token-name", "t", "cli-token", "service account token name")
	svcAccountTokenCreateCmd.Flags().IntVarP(&lifetimeDays, "lifetime-days", "d", 365, "service account token lifetime days (0 for no expiry)")
	svcAccountTokenCreateCmd.Flags().BoolVarP(&jsonOutput, "json", "j", false, "print json output")

	serviceAccountTokenCmdRoot := &cobra.Command{
		Use:   "token",
		Short: "manage service account tokens for an organization",
	}
	serviceAccountTokenCmdRoot.AddCommand(
		svcAccountTokenCreateCmd,
	)
	return serviceAccountTokenCmdRoot
}
