package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/chenzhiwei/certctl/pkg/cert"
)

var (
	certSize        int
	certDays        int
	certIsCA        bool
	certSan         string
	certSubject     string
	certKeyUsage    string
	certExtKeyUsage string
	certKeyfile     string
	certCertfile    string
	caKeyfile       string
	caCertfile      string

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

func init() {
	signCmd.Flags().BoolVar(&certIsCA, "is-ca", false, "the signed certificate is CA cert or not")
	signCmd.Flags().StringVar(&certSubject, "subject", "", "the certificate subject")
	signCmd.Flags().StringVar(&certSan, "san", "", "the certificate subject alternate name")
	signCmd.Flags().StringVar(&certKeyUsage, "usage", "", "the certificate key usage")
	signCmd.Flags().StringVar(&certExtKeyUsage, "extKeyUsage", "", "the certificate extendedn key usage")
	signCmd.Flags().IntVar(&certDays, "days", 365, "the certificate validation period")
	signCmd.Flags().IntVar(&certSize, "size", 2048, "the certificate RSA private key size")
	signCmd.Flags().StringVar(&certKeyfile, "key", "certctl-signed.key", "the output key file")
	signCmd.Flags().StringVar(&certCertfile, "cert", "certctl-signed.crt", "the output cert file")
	signCmd.Flags().StringVar(&caKeyfile, "ca-key", "", "the ca key file to sign certificate")
	signCmd.Flags().StringVar(&caCertfile, "ca-cert", "", "the ca cert file to sign certificate")

	signCmd.Flags().SortFlags = false
}

func runSign() error {
	caKeyBytes, err := os.ReadFile(caKeyfile)
	if err != nil {
		return err
	}
	caKey, err := cert.ParseKey(caKeyBytes)
	if err != nil {
		return err
	}

	caCertBytes, err := os.ReadFile(caCertfile)
	if err != nil {
		return err
	}
	caCert, err := cert.ParseCert(caCertBytes)
	if err != nil {
		return err
	}

	duration := time.Hour * 24 * time.Duration(certDays)
	certInfo, err := cert.NewCertInfo(duration, certSubject, certSan, certKeyUsage, certExtKeyUsage, certIsCA)
	if err != nil {
		return err
	}

	certBytes, keyBytes, err := cert.NewSignedCertKey(caCert, caKey, certInfo, certSize)
	if err != nil {
		return err
	}

	if err := os.WriteFile(certKeyfile, keyBytes, 0600); err != nil {
		return err
	}
	fmt.Printf("Writing new private key to '%s'\n", certKeyfile)

	if err := os.WriteFile(certCertfile, certBytes, 0644); err != nil {
		return err
	}
	fmt.Printf("Writing new certificate to '%s'\n", certCertfile)
	return nil
}
