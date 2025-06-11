package users

import "github.com/spf13/cobra"

var (
	RootCmd = &cobra.Command{
		Use:   "users",
		Short: "Manage users in the system",
		Long:  "This command allows you to manage users in the system, including creating, updating, and deleting user accounts.",
	}
)

func init() {
	userAddCmd.Flags().StringP("email", "e", "", "Email of the user (required)")
	userAddCmd.Flags().StringP("first-name", "f", "", "First name of the user (required)")
	userAddCmd.Flags().StringP("last-name", "l", "", "Last name of the user (required)")
	userAddCmd.MarkFlagRequired("email")
	userAddCmd.MarkFlagRequired("first-name")
	userAddCmd.MarkFlagRequired("last-name")

	RootCmd.AddCommand(userAddCmd)
}
