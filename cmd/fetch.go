package cmd

import (
	"errors"

	"github.com/spf13/cobra"
)

var (
	chain bool
	file  string

	fetchCmd = &cobra.Command{
		Use:   "fetch url",
		Short: "Fetch the certificate from url",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := runFetch(args); err != nil {
				return err
			}
			return nil
		},
	}
)

func init() {
	fetchCmd.Flags().BoolVar(&chain, "chain", true, "fetch certificate chain")
	fetchCmd.Flags().StringVar(&file, "file", "", "save the fetched certificate to a file")
}

func runFetch(args []string) error {
	url := args[0]
	if url == "" {
		return errors.New("something went wrong")
	}

	return nil
}
