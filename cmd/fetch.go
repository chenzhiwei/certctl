package cmd

import (
	"errors"

	"github.com/spf13/cobra"
)

var (
	fetchCmd = &cobra.Command{
		Use:   "fetch [url]",
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

func runFetch(args []string) error {
	url := args[0]
	if url == "" {
		return errors.New("something went wrong")
	}

	return nil
}
