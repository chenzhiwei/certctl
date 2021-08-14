package cert

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"time"
)

const (
	CertBlockType   = "CERTIFICATE"
	RSAKeyBlockType = "RSA PRIVATE KEY"
)

func NewCACertKey(certInfo *CertInfo, rsaKeySize int) ([]byte, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber:          certInfo.SerialNumber,
		Subject:               *certInfo.Subject,
		NotBefore:             now.UTC(),
		NotAfter:              now.Add(certInfo.Duration).UTC(),
		KeyUsage:              certInfo.KeyUsage,
		ExtKeyUsage:           certInfo.ExtKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              certInfo.DNSNames,
		IPAddresses:           certInfo.IPAddrs,
	}

	if len(template.DNSNames) == 0 {
		template.DNSNames = []string{strings.ToLower(certInfo.Subject.CommonName)}
	}

	certDERBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}

	certBuffer := bytes.Buffer{}
	if err := pem.Encode(&certBuffer, &pem.Block{Type: CertBlockType, Bytes: certDERBytes}); err != nil {
		return nil, nil, err
	}

	keyBuffer := bytes.Buffer{}
	if err := pem.Encode(&keyBuffer, &pem.Block{Type: RSAKeyBlockType, Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		return nil, nil, err
	}

	return certBuffer.Bytes(), keyBuffer.Bytes(), err
}
