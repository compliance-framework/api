package cmd

import "github.com/spf13/cobra"

func newBootstrapCMD() *cobra.Command {
	var (
		privateKeyPath string
		publicKeyPath  string
		bitSize        int
		force          bool
	)

	bootstrap := &cobra.Command{
		Use:   "bootstrap",
		Short: "Initialize JWT signing key files for API startup",
		RunE: func(cmd *cobra.Command, args []string) error {
			privateKeyPath, publicKeyPath = resolveJWTKeyPathsForBootstrap(privateKeyPath, publicKeyPath)

			action, err := runJWTBootstrap(privateKeyPath, publicKeyPath, bitSize, force)
			if err != nil {
				return err
			}

			cmd.Printf(
				"JWT bootstrap complete (action=%s, private=%s, public=%s)\n",
				action,
				privateKeyPath,
				publicKeyPath,
			)

			return nil
		},
	}

	bootstrap.Flags().StringVar(&privateKeyPath, "private-key", "", "Path to the JWT private key file")
	bootstrap.Flags().StringVar(&publicKeyPath, "public-key", "", "Path to the JWT public key file")
	bootstrap.Flags().IntVar(&bitSize, "bit-size", defaultJWTKeyBitSize, "RSA key size in bits")
	bootstrap.Flags().BoolVar(&force, "force", false, "Regenerate key files even when they already exist")

	return bootstrap
}
