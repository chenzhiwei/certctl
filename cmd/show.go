package cmd

import (
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/chenzhiwei/certctl/pkg/cert"
	"github.com/spf13/cobra"
)

var (
	showCmd = &cobra.Command{
		Use:   "show cert-or-csr-filepath or - from stdin",
		Short: "Show certificate or certificate request info",
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
	data, err := os.ReadFile(file)
	if err != nil {
		if file == "-" {
			data, err = io.ReadAll(os.Stdin)
		} else {
			return err
		}
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("Failed to parse certificate or csr")
	}

	var result []map[string]string

	if block.Type == cert.CertReqBlockType {
		result, err = cert.GetCertRequestInfo(data)
		if err != nil {
			return err
		}
	} else if block.Type == cert.CertBlockType {
		result, err = cert.GetCertInfo(data)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("Unsupported type: %s", block.Type)
	}

	writer := tabwriter.NewWriter(os.Stdout, 0, 8, 1, '\t', tabwriter.AlignRight)
	for _, info := range result {
		for k, v := range info {
			fmt.Fprintf(writer, "%s\t%s\n", k, v)
		}
	}

	writer.Flush()

	// a certificate/request can contain too many tings, no need to reinvent the wheel
	if block.Type == cert.CertReqBlockType {
		fmt.Printf("\nCheck more info with: openssl req -noout -text -in %s\n", file)
	} else if block.Type == cert.CertBlockType {
		fmt.Printf("\nCheck more info with: openssl x509 -noout -text -in %s\n", file)
	}

	return nil
}
