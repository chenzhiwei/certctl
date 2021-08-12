package cmd

import (
	"github.com/spf13/cobra"
)

var (
	generateCmd = &cobra.Command{
		Use:   "generate",
		Short: "generate certificate",
		Args:  cobra.MinimumNArgs(0),
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := runGenerate(); err != nil {
				return err
			}
			return nil
		},
	}
)

func runGenerate() error {
	return nil
}
