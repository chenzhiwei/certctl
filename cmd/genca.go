package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/chenzhiwei/certctl/pkg/cert"
)

var (
	caSize        int
	caDays        int
	caSubject     string
	caSan         string
	caKeyUsage    string
	caExtKeyUsage string
	caNoDefaults  bool
	caKeyfile     string
	caCertfile    string

	gencaLong string = `Generate Root CA certificate.

Examples:
  # Generate Root CA certificate
  certctl genca --subject "C=CN/ST=Beijing/L=Haidian/O=Any Corp/CN=Root CA" \
      --key ca.key --cert ca.crt \
      --days 36500 --size 2048

  # Set Key Usages and Extended Key usages manaully
  certctl genca --subject "C=CN/ST=Beijing/L=Haidian/O=Any Corp/CN=Root CA" \
      --nodefault \
      --key ca.key --cert ca.crt \
      --san "root.com,*.root.com,localhost,127.0.0.1" \
      --ku digitalSignature,keyCertSign --eku serverAuth \
      --days 36500 --size 2048

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

	gencaCmd = &cobra.Command{
		Use:     "genca",
		Aliases: []string{"generate-ca", "create-ca"},
		Short:   "Generate Root CA certificate",
		Long:    gencaLong,
		Args:    cobra.MaximumNArgs(0),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := runGenerateCA(); err != nil {
				return err
			}
			return nil
		},
	}
)

func init() {
	gencaCmd.Flags().StringVar(&caSubject, "subject", "", "the certificate subject")
	gencaCmd.Flags().StringVar(&caSan, "san", "", "the certificate subject alternate names")
	gencaCmd.Flags().StringVar(&caKeyUsage, "ku", "", "the certificate key usage")
	gencaCmd.Flags().StringVar(&caExtKeyUsage, "eku", "", "the certificate extended key usage")
	gencaCmd.Flags().IntVar(&caDays, "days", 365, "the certificate validation period")
	gencaCmd.Flags().IntVar(&caSize, "size", 2048, "the certificate RSA private key size")
	gencaCmd.Flags().BoolVar(&caNoDefaults, "nodefault", false, "do not set any default vaules")
	gencaCmd.Flags().StringVar(&caKeyfile, "key", "certctl.key", "the output key file")
	gencaCmd.Flags().StringVar(&caCertfile, "cert", "certctl.crt", "the output cert file")

	gencaCmd.Flags().SortFlags = false
	gencaCmd.MarkFlagRequired("subject")
}

func runGenerateCA() error {
	duration := time.Hour * 24 * time.Duration(caDays)

	if !caNoDefaults {
		caKeyUsage = "cRLSign,keyCertSign,digitalSignature"
		caExtKeyUsage = ""
	}

	certInfo, err := cert.NewCertInfo(duration, caSubject, caSan, caKeyUsage, caExtKeyUsage, true)
	if err != nil {
		return err
	}

	certBytes, keyBytes, err := cert.NewCertKey(certInfo, caSize)
	if err != nil {
		return err
	}

	if err := os.WriteFile(caKeyfile, keyBytes, 0600); err != nil {
		return err
	}
	fmt.Printf("Writing new private key to '%s'\n", caKeyfile)

	if err := os.WriteFile(caCertfile, certBytes, 0644); err != nil {
		return err
	}
	fmt.Printf("Writing new certificate to '%s'\n", caCertfile)

	return nil
}
