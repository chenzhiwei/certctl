package cert

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

const (
	CertBlockType       = "CERTIFICATE"
	CertReqBlockType    = "CERTIFICATE REQUEST"
	ECKEYBlockType      = "EC PRIVATE KEY"
	RSAKeyBlockType     = "RSA PRIVATE KEY"
	PrivateKeyBlockType = "PRIVATE KEY"
)

var kuStringToAction = map[string]x509.KeyUsage{
	"digitalSignature":  x509.KeyUsageDigitalSignature,
	"contentCommitment": x509.KeyUsageContentCommitment,
	"keyEncipherment":   x509.KeyUsageKeyEncipherment,
	"dataEncipherment":  x509.KeyUsageDataEncipherment,
	"keyAgreement":      x509.KeyUsageKeyAgreement,
	"keyCertSign":       x509.KeyUsageCertSign,
	"certSign":          x509.KeyUsageCertSign, // fault tolerant
	"cRLSign":           x509.KeyUsageCRLSign,
	"encipherOnly":      x509.KeyUsageEncipherOnly,
	"decipherOnly":      x509.KeyUsageDecipherOnly,
}

var ekuStringToAction = map[string]x509.ExtKeyUsage{
	"any":                            x509.ExtKeyUsageAny,
	"serverAuth":                     x509.ExtKeyUsageServerAuth,
	"clientAuth":                     x509.ExtKeyUsageClientAuth,
	"codeSigning":                    x509.ExtKeyUsageCodeSigning,
	"emailProtection":                x509.ExtKeyUsageEmailProtection,
	"IPSECEndSystem":                 x509.ExtKeyUsageIPSECEndSystem,
	"IPSECTunnel":                    x509.ExtKeyUsageIPSECTunnel,
	"IPSECUser":                      x509.ExtKeyUsageIPSECUser,
	"timeStamping":                   x509.ExtKeyUsageTimeStamping,
	"OCSPSigning":                    x509.ExtKeyUsageOCSPSigning,
	"netscapeServerGatedCrypto":      x509.ExtKeyUsageNetscapeServerGatedCrypto,
	"microsoftServerGatedCrypto":     x509.ExtKeyUsageMicrosoftServerGatedCrypto,
	"microsoftCommercialCodeSigning": x509.ExtKeyUsageMicrosoftCommercialCodeSigning,
	"microsoftKernelCodeSigning":     x509.ExtKeyUsageMicrosoftKernelCodeSigning,
}

type CertInfo struct {
	SerialNumber *big.Int
	IsCA         bool
	Subject      *pkix.Name
	DNSNames     []string
	IPAddrs      []net.IP
	Duration     time.Duration
	KeyUsage     x509.KeyUsage
	ExtKeyUsage  []x509.ExtKeyUsage
}

func NewCertInfo(duration time.Duration, sub, san, usage, extUsage string, isCA bool) (*CertInfo, error) {
	certInfo := &CertInfo{}

	serialNumber, err := getSerialNumber()
	if err != nil {
		return nil, err
	}
	certInfo.SerialNumber = serialNumber

	certInfo.IsCA = isCA

	subject, err := getSubject(sub)
	if err != nil {
		return nil, err
	}
	certInfo.Subject = subject

	keyUsage, err := getKeyUsage(usage)
	if err != nil {
		return nil, err
	}
	certInfo.KeyUsage = keyUsage

	extKeyUsage, err := getExtKeyUsage(extUsage)
	if err != nil {
		return nil, err
	}
	certInfo.ExtKeyUsage = extKeyUsage

	certInfo.Duration = duration
	certInfo.DNSNames, certInfo.IPAddrs = getDNSNamesAndIPAddrs(san)

	return certInfo, nil
}

func ParseCerts(certBytes []byte) ([]*x509.Certificate, error) {
	var blocks []byte
	rest := certBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, fmt.Errorf("Failed to parse certificate")
		}
		blocks = append(blocks, block.Bytes...)

		if len(rest) == 0 {
			break
		}
	}

	certs, err := x509.ParseCertificates(blocks)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse certificate: %w", err)
	}

	return certs, nil
}

func ParseCert(certBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certBytes)
	if block == nil {
		return nil, fmt.Errorf("Failed to parse certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse certificate: %w", err)
	}

	return cert, nil
}

func ParseKey(keyBytes []byte) (interface{}, error) {
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("Failed to parse private key")
	}

	var key interface{}
	var err error
	if block.Type == RSAKeyBlockType {
		// Public-Key Cryptography Standard
		// for RSA only
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	} else if block.Type == ECKEYBlockType {
		// for EC only
		key, err = x509.ParseECPrivateKey(block.Bytes)
	} else {
		// for all algorithms
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, fmt.Errorf("Failed to parse public key: %w", err)
	}

	return key, nil
}

func appendEKU(ekus []x509.ExtKeyUsage, eku x509.ExtKeyUsage) []x509.ExtKeyUsage {
	found := false
	for _, e := range ekus {
		if e == eku {
			found = true
			break
		}
	}

	if !found {
		return append(ekus, eku)
	}

	return ekus
}

func getSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}

// s: /C=/ST=/L=/O=/CN=
func getSubject(subject string) (*pkix.Name, error) {
	name := &pkix.Name{}
	ss := strings.Split(subject, "/")
	var country []string
	var province []string
	var locality []string
	var organization []string
	for _, s := range ss {
		info := strings.Split(s, "=")
		if len(info) == 2 {
			key := strings.TrimSpace(info[0])
			val := strings.TrimSpace(info[1])
			switch key {
			case "C":
				if val == "" {
					fmt.Println("No value provided for Subject Attribute C, skipped")
				} else {
					country = append(country, val)
				}
			case "ST":
				if val == "" {
					fmt.Println("No value provided for Subject Attribute ST, skipped")
				} else {
					province = append(province, val)
				}
			case "L":
				if val == "" {
					fmt.Println("No value provided for Subject Attribute L, skipped")
				} else {
					locality = append(locality, val)
				}
			case "O":
				if val == "" {
					fmt.Println("No value provided for Subject Attribute O, skipped")
				} else {
					organization = append(organization, val)
				}
			case "CN":
				name.CommonName = val
			}
		}
	}

	if len(country) > 0 {
		name.Country = country
	}
	if len(province) > 0 {
		name.Province = province
	}
	if len(locality) > 0 {
		name.Locality = locality
	}
	if len(organization) > 0 {
		name.Organization = organization
	}

	if name.CommonName == "" {
		return nil, fmt.Errorf("No Common Name specified in subject")
	}

	return name, nil
}

func getKeyUsage(usage string) (x509.KeyUsage, error) {
	var keyUsage x509.KeyUsage
	usages := strings.Split(usage, ",")

	invalid := false
	var invalidKeyUsages []string

	for _, key := range usages {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}

		isInvalidKey := true
		for k, v := range kuStringToAction {
			if strings.ToLower(key) == strings.ToLower(k) {
				isInvalidKey = false
				keyUsage |= v
				break
			}
		}

		if isInvalidKey {
			invalid = true
			invalidKeyUsages = append(invalidKeyUsages, key)
		}
	}

	if invalid {
		return 0, fmt.Errorf("Invalid keyUsage: %s", strings.Join(invalidKeyUsages, ","))
	}

	return keyUsage, nil
}

func getExtKeyUsage(usage string) ([]x509.ExtKeyUsage, error) {
	var extKeyUsages []x509.ExtKeyUsage
	usages := strings.Split(usage, ",")

	invalid := false
	var invalidExtKeyUsages []string

	for _, key := range usages {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}

		isInvalidKey := true
		for k, v := range ekuStringToAction {
			if strings.ToLower(key) == strings.ToLower(k) {
				isInvalidKey = false
				extKeyUsages = appendEKU(extKeyUsages, v)
				break
			}
		}

		if isInvalidKey {
			invalid = true
			invalidExtKeyUsages = append(invalidExtKeyUsages, key)
		}
	}

	if invalid {
		return nil, fmt.Errorf("Invalid ExtKeyUsage: %s", strings.Join(invalidExtKeyUsages, ","))
	}

	return extKeyUsages, nil
}

func getDNSNamesAndIPAddrs(s string) ([]string, []net.IP) {
	var dnsNames []string
	var ips []net.IP

	s = strings.ToLower(s)
	hosts := strings.Split(s, ",")
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		host = strings.TrimLeft(host, "ip:")
		host = strings.TrimLeft(host, "dns:")
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		if ip := net.ParseIP(host); ip != nil {
			if !containsIP(ips, ip) {
				ips = append(ips, ip)
			}
		} else {
			if !containString(dnsNames, host) {
				dnsNames = append(dnsNames, host)
			}
		}
	}

	return dnsNames, ips
}

func containString(elements []string, element string) bool {
	for _, item := range elements {
		if element == item {
			return true
		}
	}
	return false
}

func containsIP(elements []net.IP, element net.IP) bool {
	for _, item := range elements {
		if element.String() == item.String() {
			return true
		}
	}
	return false
}

func formatSerial(serial *big.Int) string {
	if serial.String() == "0" {
		return "0"
	}

	b := serial.Bytes()
	buf := make([]byte, 0, 3*len(b))
	x := buf[1*len(b) : 3*len(b)]
	hex.Encode(x, b)
	for i := 0; i < len(x); i += 2 {
		buf = append(buf, x[i], x[i+1], ':')
	}
	return string(buf[:len(buf)-1])
}
