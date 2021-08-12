package cmd

import (
	"github.com/spf13/cobra"
)

var (
	signCmd = &cobra.Command{
		Use:   "sign",
		Short: "sign certificate",
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := runSign(); err != nil {
				return err
			}
			return nil
		},
	}
)

func runSign() error {
	return nil
}
