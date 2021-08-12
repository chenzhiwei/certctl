package cmd

import (
	"github.com/goduang/glog"
	"github.com/spf13/cobra"
)

var (
	verbosity int
	rootCmd   = &cobra.Command{
		Use:          "certctl",
		Short:        "certctl is a certificate management tool",
		Long:         `A tool to manage certificates with ease`,
		SilenceUsage: true,
		PersistentPreRun: func(_ *cobra.Command, _ []string) {
			glog.InitLogs(verbosity)
			go glog.Flush()
		},
	}
)

func init() {
	rootCmd.PersistentFlags().IntVarP(&verbosity, "verbosity", "v", 0, "the log verbosity")

	rootCmd.AddCommand(fetchCmd)
	rootCmd.AddCommand(showCmd)
	rootCmd.AddCommand(signCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(generateCmd)
}

func Execute() error {
	return rootCmd.Execute()
}
