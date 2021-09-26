package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

const (
	cCommit  = "master"
	cVersion = "latest"
)

var (
	buildCommit  = cCommit
	buildVersion = cVersion
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "print the version number of certctl",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("certctl build commit: ", buildCommit)
		fmt.Println("certctl build version:", buildVersion)
	},
}
