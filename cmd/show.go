package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/chenzhiwei/certctl/pkg/cert"
	"github.com/spf13/cobra"
)

var (
	showCmd = &cobra.Command{
		Use:   "show",
		Short: "show certificate info",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := runShow(args); err != nil {
				return err
			}
			return nil
		},
	}
)

func runShow(args []string) error {
	file := args[0]
	bytes, err := os.ReadFile(file)
	if err != nil {
		return err
	}

	result, err := cert.GetCertOrRequestInfo(bytes)
	if err != nil {
		return err
	}

	writer := tabwriter.NewWriter(os.Stdout, 0, 8, 1, '\t', tabwriter.AlignRight)
	for _, info := range result {
		for k, v := range info {
			fmt.Fprintf(writer, "%s\t%s\n", k, v)
		}
	}

	writer.Flush()

	return nil
}
