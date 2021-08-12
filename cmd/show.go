package cmd

import (
	"github.com/spf13/cobra"
)

var (
	showCmd = &cobra.Command{
		Use:   "show",
		Short: "show certificate info",
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := runShow(); err != nil {
				return err
			}
			return nil
		},
	}
)

func runShow() error {
	return nil
}
