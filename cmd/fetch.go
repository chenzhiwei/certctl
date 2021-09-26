package cmd

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/chenzhiwei/certctl/pkg/cert"
	"github.com/spf13/cobra"
)

var (
	noout bool
	file  string

	fetchCmd = &cobra.Command{
		Use:   "fetch url",
		Short: "fetch the certificate from url",
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
	fetchCmd.Flags().BoolVar(&noout, "noout", false, "do not print the certificate info")
	fetchCmd.Flags().StringVar(&file, "file", "", "save the certificate to a file")
}

func runFetch(args []string) error {
	s := args[0]
	if s == "" {
		return errors.New("something went wrong")
	}

	if !strings.Contains(s, "://") {
		s = "https://" + s
	}

	u, err := url.Parse(s)
	if err != nil {
		return err
	}

	if u.Scheme == "http" {
		return errors.New("can't fetch certificate with http")
	}

	host := u.Host
	if !strings.Contains(host, ":") && u.Scheme == "https" {
		host = host + ":443"
	}

	certBytes, err := cert.FetchCert(host)
	if err != nil {
		return err
	}

	if file != "" {
		if err := os.WriteFile(file, certBytes, 0644); err != nil {
			return err
		}
	}

	if !noout {
		result, err := cert.GetCertInfo(certBytes)
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
	}

	return nil
}
