package cmd

import (
	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:          "certctl",
		Short:        "certctl is a certificate management tool",
		Long:         `A tool to manage certificates with ease`,
		SilenceUsage: true,
	}
)

func init() {
	rootCmd.AddCommand(fetchCmd)
	rootCmd.AddCommand(showCmd)
	rootCmd.AddCommand(signCmd)
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(gencaCmd)
	rootCmd.AddCommand(generateCmd)
}

func Execute() error {
	return rootCmd.Execute()
}
