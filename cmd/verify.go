package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	crtCAFile   string
	crtKeyFile  string
	crtCertFile string

	verifyCmd = &cobra.Command{
		Use:   "verify",
		Short: "Verify certificate keypair and CA",
		Args:  cobra.MaximumNArgs(0),
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := runVerify(); err != nil {
				return err
			}
			return nil
		},
	}
)

func init() {
	verifyCmd.Flags().StringVar(&crtCAFile, "ca", "", "the CA certificate file")
	verifyCmd.Flags().StringVar(&crtKeyFile, "key", "", "the certificate file")
	verifyCmd.Flags().StringVar(&crtCertFile, "cert", "", "the private key file")

	verifyCmd.Flags().SortFlags = false
	verifyCmd.MarkFlagRequired("cert")
}

func runVerify() error {
	certBytes, err := os.ReadFile(crtCertFile)
	if err != nil {
		return err
	}

	if crtCAFile == "" && crtKeyFile == "" {
		return fmt.Errorf("unable to verify, please provide --ca and/or --key")
	}

	if crtCAFile != "" {
		caBytes, err := os.ReadFile(crtCAFile)
		if err != nil {
			return err
		}

		roots := x509.NewCertPool()
		ok := roots.AppendCertsFromPEM(caBytes)
		if !ok {
			return fmt.Errorf("unable to parse CA certificate")
		}

		block, _ := pem.Decode(certBytes)
		if block == nil {
			return fmt.Errorf("unable to parse certificate PEM")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("unable to parse certificate: %w\n", err)
		}

		opts := x509.VerifyOptions{
			Roots: roots,
		}

		if _, err := cert.Verify(opts); err != nil {
			return fmt.Errorf("unable to verify certificate: %w", err)
		} else {
			fmt.Println("Verified OK: the certificate matches CA")
		}
	}

	if crtKeyFile != "" {
		keyBytes, err := os.ReadFile(crtKeyFile)
		if err != nil {
			return err
		}

		if _, err := tls.X509KeyPair(certBytes, keyBytes); err != nil {
			return err
		} else {
			fmt.Println("Verified OK: the certificate matches private key")
		}
	}

	return nil
}
