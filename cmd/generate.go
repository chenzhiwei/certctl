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

	generateLong string = `Generate Root CA certificate or self-signed certificate.

Examples:
  # Generate Root CA certificate
  certctl generate --subject "C=CN/ST=Beijing/L=Haidian/O=Any Corp/CN=Root-CA" --key ca.key --cert ca.crt \
      --usage cRLSign,keyCertSign,digitalSignature --extusage serverAuth,clientAuth --days 36500 --size 4096

  # Generate self-signed certificate
  certctl generate --subject "C=CN/ST=Beijing/L=Haidian/O=Any Corp/CN=any.com" --key any.com.key --cert any.com.crt \
      --san "any.com,*.any.com,localhost,127.0.0.1" --days 730 --size 4096

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

	generateCmd = &cobra.Command{
		Use:   "generate",
		Short: "generate CA or self-signed certificate",
		Long:  generateLong,
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
	generateCmd.MarkFlagRequired("subject")
}

func runGenerate() error {
	duration := time.Hour * 24 * time.Duration(days)

	certInfo, err := cert.NewCertInfo(duration, subject, san, keyUsage, extKeyUsage, true)
	if err != nil {
		return err
	}

	certBytes, keyBytes, err := cert.NewCACertKey(certInfo, size)
	if err != nil {
		return err
	}

	if err := os.WriteFile(keyfile, keyBytes, 0600); err != nil {
		return err
	}
	fmt.Printf("Writing new private key to '%s'\n", keyfile)

	if err := os.WriteFile(certfile, certBytes, 0644); err != nil {
		return err
	}
	fmt.Printf("Writing new certificate to '%s'\n", certfile)

	return nil
}
