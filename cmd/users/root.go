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
	RootCmd.AddCommand(newUserAddCmd())
	RootCmd.AddCommand(updateUserCmd())
}
