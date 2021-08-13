package cert

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

var keyUsageMap = map[string]x509.KeyUsage{
	"digitalSignature":  x509.KeyUsageDigitalSignature,
	"contentCommitment": x509.KeyUsageContentCommitment,
	"keyEncipherment":   x509.KeyUsageKeyEncipherment,
	"dataEncipherment":  x509.KeyUsageDataEncipherment,
	"keyAgreement":      x509.KeyUsageKeyAgreement,
	"certSign":          x509.KeyUsageCertSign,
	"cRLSign":           x509.KeyUsageCRLSign,
	"encipherOnly":      x509.KeyUsageEncipherOnly,
	"decipherOnly":      x509.KeyUsageDecipherOnly,
}

type AltNames struct {
	DNSNames []string
	IPAddrs  []net.IP
}

func NewCACertKey(duration time.Duration, sub, san, usage string, bits int) ([]byte, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := getSerialNumber()
	if err != nil {
		return nil, nil, err
	}

	subject, err := getSubject(sub)
	if err != nil {
		return nil, nil, err
	}

	keyUsage, err := getKeyUsage(usage)
	if err != nil {
		return nil, nil, err
	}
	keyUsage |= x509.KeyUsageCertSign

	now := time.Now()
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               *subject,
		NotBefore:             now.UTC(),
		NotAfter:              now.Add(duration).UTC(),
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	altNames := getAltNames(san)
	if len(altNames.IPAddrs) != 0 {
		template.IPAddresses = altNames.IPAddrs
	}
	if len(altNames.DNSNames) != 0 {
		template.DNSNames = altNames.DNSNames
	} else {
		template.DNSNames = []string{strings.ToLower(subject.CommonName)}
	}

	certDERBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}

	certBuffer := bytes.Buffer{}
	if err := pem.Encode(&certBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: certDERBytes}); err != nil {
		return nil, nil, err
	}

	keyBuffer := bytes.Buffer{}
	if err := pem.Encode(&keyBuffer, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		return nil, nil, err
	}

	return certBuffer.Bytes(), keyBuffer.Bytes(), err
}

func getAltNames(s string) *AltNames {
	s = strings.ToLower(s)
	altNames := &AltNames{}
	hosts := strings.Split(s, ",")
	for _, host := range hosts {
		if host == "" {
			continue
		}
		if ip := net.ParseIP(host); ip != nil {
			if !containsIP(altNames.IPAddrs, ip) {
				altNames.IPAddrs = append(altNames.IPAddrs, ip)
			}
		} else {
			if !containString(altNames.DNSNames, host) {
				altNames.DNSNames = append(altNames.DNSNames, host)
			}
		}
	}

	return altNames
}

func getSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}

// s: /C=/S=/L=/O=/CN=
func getSubject(subject string) (*pkix.Name, error) {
	name := &pkix.Name{}
	ss := strings.Split(subject, "/")
	for _, s := range ss {
		info := strings.Split(s, "=")
		if len(info) == 2 {
			switch info[0] {
			case "C":
				name.Country = []string{info[1]}
			case "S":
				name.Province = []string{info[1]}
			case "L":
				name.Locality = []string{info[1]}
			case "O":
				name.Organization = []string{info[1]}
			case "CN":
				name.CommonName = info[1]
			}
		}
	}

	if name.CommonName == "" {
		return nil, fmt.Errorf("No Common Name specified in subject")
	}

	return name, nil
}

func getKeyUsage(usage string) (x509.KeyUsage, error) {
	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// RSA subject keys should have the KeyEncipherment
	keyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	elements := strings.Split(usage, ",")
	for _, e := range elements {
		if e == "" {
			continue
		}
		invalid := true
		for key := range keyUsageMap {
			if e == key {
				invalid = false
				break
			}
		}

		if invalid {
			return 0, fmt.Errorf("Invalid keyUsage: %s", e)
		}

		keyUsage |= keyUsageMap[e]
	}

	return keyUsage, nil
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
