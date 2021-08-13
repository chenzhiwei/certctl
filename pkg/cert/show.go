package cert

import (
	"crypto/x509"
	"fmt"
	"strings"
)

var kuMap = map[x509.KeyUsage]string{
	x509.KeyUsageDigitalSignature:  "Digital Signature",
	x509.KeyUsageContentCommitment: "Non Repudiation",
	x509.KeyUsageKeyEncipherment:   "Key Encipherment",
	x509.KeyUsageDataEncipherment:  "Data Encipherment",
	x509.KeyUsageKeyAgreement:      "Key Agreement",
	x509.KeyUsageCertSign:          "Certificate Sign",
	x509.KeyUsageCRLSign:           "CRL Sign",
	x509.KeyUsageEncipherOnly:      "Encipher Only",
	x509.KeyUsageDecipherOnly:      "Decipher Only",
}

var ekuMap = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                            "ANY",
	x509.ExtKeyUsageServerAuth:                     "TLS Web Server Authentication",
	x509.ExtKeyUsageClientAuth:                     "TLS Web Client Authentication",
	x509.ExtKeyUsageCodeSigning:                    "Code Signing",
	x509.ExtKeyUsageEmailProtection:                "Email Protection",
	x509.ExtKeyUsageIPSECEndSystem:                 "IPSec End System",
	x509.ExtKeyUsageIPSECTunnel:                    "IPSec Tunnel",
	x509.ExtKeyUsageIPSECUser:                      "IPsec User",
	x509.ExtKeyUsageTimeStamping:                   "Time Stamping",
	x509.ExtKeyUsageOCSPSigning:                    "OCSP Signing",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      "Netscape Server Gated Crypto",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "Microsoft Server Gated Crypto",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "Microsoft Commercial Code Signing",
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "1.3.6.1.4.1.311.61.1.1",
}

func GetCertInfo(certByte []byte) ([]map[string]string, error) {
	cert, err := ParseCert(certByte)
	if err != nil {
		return nil, err
	}

	var result []map[string]string

	serialNumber := formatSerial(cert.SerialNumber)

	if cert.Subject.CommonName != "" {
		result = append(result, map[string]string{
			"Common Name": cert.Subject.CommonName,
		})
	}
	if len(cert.Subject.Country) > 0 {
		result = append(result, map[string]string{
			"Country": strings.Join(cert.Subject.Country, ", "),
		})
	}
	if len(cert.Subject.Province) > 0 {
		result = append(result, map[string]string{
			"Province": strings.Join(cert.Subject.Province, ", "),
		})
	}
	if len(cert.Subject.Locality) > 0 {
		result = append(result, map[string]string{
			"Locality": strings.Join(cert.Subject.Locality, ", "),
		})
	}
	if len(cert.Subject.Organization) > 0 {
		result = append(result, map[string]string{
			"Organization": strings.Join(cert.Subject.Organization, ", "),
		})
	}

	var san []string
	if len(cert.DNSNames) > 0 {
		san = cert.DNSNames
	}
	if len(cert.IPAddresses) > 0 {
		for _, ip := range cert.IPAddresses {
			san = append(san, ip.String())
		}
	}
	result = append(result, map[string]string{
		"Alternative Name": strings.Join(san, ", "),
	})

	result = append(result, map[string]string{
		"Is CA": fmt.Sprint(cert.IsCA),
	})
	result = append(result, map[string]string{
		"Serial Number": serialNumber,
	})
	result = append(result, map[string]string{
		"Effective Date": cert.NotBefore.String(),
	})
	result = append(result, map[string]string{
		"Expiration Date": cert.NotAfter.String(),
	})

	if cert.KeyUsage != 0 {
		var ku []string
		for key, value := range kuMap {
			n := key & cert.KeyUsage
			if n == key {
				ku = append(ku, value)
			}
		}

		result = append(result, map[string]string{
			"Key Usage": strings.Join(ku, ", "),
		})
	}
	if len(cert.ExtKeyUsage) > 0 {
		var eku []string
		for _, e := range cert.ExtKeyUsage {
			// handle and ignore unknown EKU
			for key, value := range ekuMap {
				if key == e {
					eku = append(eku, value)
					break
				}
			}
		}

		result = append(result, map[string]string{
			"Extended Key Usage": strings.Join(eku, ", "),
		})
	}

	return result, nil
}
