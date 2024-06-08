package cmd

import (
	"crypto/tls"
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
	certCAKeyfile   string
	certCACertfile  string

	signLong string = `Sign a certificate with CA certificate.

Examples:
  # Sign a certificate with CA certificate
  certctl sign --ca-key ca.key --ca-cert ca.crt \
      --subject "CN=anycorp.com" \
      --san anycorp.com,www.anycorp.com,localhost,127.0.0.1 \
      --key anycorp.com.key --cert anycorp.com.crt \
      --usage digitalSignature,keyEncipherment \
      --extusage serverAuth,clientAuth \
      --days 730 --size 2048

The list of key usages are:
  * digitalSignature
  * contentCommitment
  * keyEncipherment
  * dataEncipherment
  * keyAgreement
  * keyCertSign
  * cRLSign
  * encipherOnly
  * decipherOnly

The list of extended key usages are:
  * any
  * serverAuth
  * clientAuth
  * codeSigning
  * emailProtection
  * IPSECEndSystem
  * IPSECTunnel
  * IPSECUser
  * timeStamping
  * OCSPSigning
  * netscapeServerGatedCrypto
  * microsoftServerGatedCrypto
  * microsoftCommercialCodeSigning
  * microsoftKernelCodeSigning
`

	signCmd = &cobra.Command{
		Use:   "sign",
		Short: "Sign certificate with CA",
		Long:  signLong,
		Args:  cobra.MaximumNArgs(0),
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := runSign(); err != nil {
				return err
			}
			return nil
		},
	}
)

func init() {
	signCmd.Flags().BoolVar(&certIsCA, "is-ca", false, "the signed certificate is CA cert or not(Immediate CA)")
	signCmd.Flags().StringVar(&certSubject, "subject", "", "the certificate subject")
	signCmd.Flags().StringVar(&certSan, "san", "", "the certificate subject alternate name")
	signCmd.Flags().StringVar(&certKeyUsage, "usage", "", "the certificate key usage")
	signCmd.Flags().StringVar(&certExtKeyUsage, "extusage", "", "the certificate extended key usage")
	signCmd.Flags().IntVar(&certDays, "days", 365, "the certificate validation period")
	signCmd.Flags().IntVar(&certSize, "size", 2048, "the certificate RSA private key size")
	signCmd.Flags().StringVar(&certKeyfile, "key", "certctl-signed.key", "the output key file")
	signCmd.Flags().StringVar(&certCertfile, "cert", "certctl-signed.crt", "the output cert file")
	signCmd.Flags().StringVar(&certCAKeyfile, "ca-key", "", "the ca key file to sign certificate")
	signCmd.Flags().StringVar(&certCACertfile, "ca-cert", "", "the ca cert file to sign certificate")

	signCmd.Flags().SortFlags = false
	signCmd.MarkFlagRequired("subject")
	signCmd.MarkFlagRequired("ca-key")
	signCmd.MarkFlagRequired("ca-cert")
}

func runSign() error {
	caKeyBytes, err := os.ReadFile(certCAKeyfile)
	if err != nil {
		return err
	}
	caKey, err := cert.ParseKey(caKeyBytes)
	if err != nil {
		return err
	}

	caCertBytes, err := os.ReadFile(certCACertfile)
	if err != nil {
		return err
	}
	caCert, err := cert.ParseCert(caCertBytes)
	if err != nil {
		return err
	}

	// return error if it is an invalid CA keypair
	if _, err := tls.X509KeyPair(caCertBytes, caKeyBytes); err != nil {
		return fmt.Errorf("Failed to verify Certificate and Key: %w", err)
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
