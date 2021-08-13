package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/chenzhiwei/certctl/pkg/cert"
)

var (
	size        int
	days        int
	san         string
	subject     string
	keyUsage    string
	extKeyUsage string
	keyfile     string
	certfile    string

	generateCmd = &cobra.Command{
		Use:   "generate",
		Short: "generate certificate",
		Args:  cobra.MaximumNArgs(0),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := runGenerate(); err != nil {
				return err
			}
			return nil
		},
	}
)

func init() {
	generateCmd.Flags().StringVar(&subject, "subject", "", "the certificate subject")
	generateCmd.Flags().StringVar(&san, "san", "", "the certificate subject alternate names")
	generateCmd.Flags().StringVar(&keyUsage, "usage", "", "the certificate key usage")
	generateCmd.Flags().StringVar(&extKeyUsage, "extusage", "", "the certificate extended key usage")
	generateCmd.Flags().IntVar(&days, "days", 365, "the certificate validation period")
	generateCmd.Flags().IntVar(&size, "size", 2048, "the certificate RSA private key size")
	generateCmd.Flags().StringVar(&keyfile, "key", "certctl.key", "the output key file")
	generateCmd.Flags().StringVar(&certfile, "cert", "certctl.crt", "the output cert file")

	generateCmd.Flags().SortFlags = false
}

func runGenerate() error {
	duration := time.Hour * 24 * time.Duration(days)

	certInfo, err := cert.NewCertInfo(duration, subject, san, keyUsage, extKeyUsage)
	if err != nil {
		return err
	}

	certByte, keyByte, err := cert.NewCACertKey(certInfo, size)
	if err != nil {
		return err
	}

	if err := os.WriteFile(keyfile, keyByte, 0600); err != nil {
		return err
	}
	fmt.Printf("Writing new private key to '%s'\n", keyfile)

	if err := os.WriteFile(certfile, certByte, 0644); err != nil {
		return err
	}
	fmt.Printf("Writing new certificate to '%s'\n", certfile)

	return nil
}
