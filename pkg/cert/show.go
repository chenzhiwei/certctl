package cert

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

var kuActionToString = map[x509.KeyUsage]string{
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

var ekuActionToString = map[x509.ExtKeyUsage]string{
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

func GetCertOrRequestInfo(bytes []byte) ([]map[string]string, error) {
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, fmt.Errorf("Failed to parse certificate or csr")
	}
	if block.Type == CertReqBlockType {
		return GetCertRequestInfo(bytes)
	} else {
		return GetCertInfo(bytes)
	}
}

func GetCertRequestInfo(bytes []byte) ([]map[string]string, error) {
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, fmt.Errorf("Failed to parse certificate request")
	}
	if block.Type != CertReqBlockType {
		return nil, fmt.Errorf("Not a Certificate Request")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse certificate request")
	}

	var result []map[string]string
	if csr.Subject.String() != "" {
		result = append(result, map[string]string{
			"Subject": csr.Subject.String(),
		})
	}

	var san []string
	if len(csr.DNSNames) > 0 {
		san = csr.DNSNames
	}
	if len(csr.IPAddresses) > 0 {
		for _, ip := range csr.IPAddresses {
			san = append(san, ip.String())
		}
	}
	if len(san) > 0 {
		result = append(result, map[string]string{
			"Alternative Name": strings.Join(san, ", "),
		})
	}

	return result, nil
}

func GetCertInfo(certBytes []byte) ([]map[string]string, error) {
	certs, err := ParseCerts(certBytes)
	if err != nil {
		return nil, err
	}

	var result []map[string]string

	index := 1
	for _, cert := range certs {
		if len(certs) > 1 {
			result = append(result, map[string]string{
				"\n==================": fmt.Sprintf("Certificate Number %d", index),
			})
			index = index + 1
		}
		if cert.Subject.String() != cert.Issuer.String() {
			result = append(result, map[string]string{
				"Issuer": cert.Issuer.String(),
			})
		}

		if cert.Subject.String() != "" {
			result = append(result, map[string]string{
				"Subject": cert.Subject.String(),
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
		if len(san) > 0 {
			result = append(result, map[string]string{
				"Alternative Name": strings.Join(san, ", "),
			})
		}

		result = append(result, map[string]string{
			"Is CA": fmt.Sprint(cert.IsCA),
		})

		result = append(result, map[string]string{
			"Serial Number": formatSerial(cert.SerialNumber),
		})
		result = append(result, map[string]string{
			"Effective Date": cert.NotBefore.String(),
		})
		result = append(result, map[string]string{
			"Expiration Date": cert.NotAfter.String(),
		})

		if cert.KeyUsage != 0 {
			var ku []string
			for key, value := range kuActionToString {
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
				for key, value := range ekuActionToString {
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
	}

	return result, nil
}
