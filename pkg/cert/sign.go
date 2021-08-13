package cert

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"time"
)

func NewSignedCertKey(caCert *x509.Certificate, caKey crypto.Signer, certInfo *CertInfo, rsaKeySize int, isCA bool) ([]byte, []byte, error) {
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
		IsCA:                  isCA,
		DNSNames:              certInfo.DNSNames,
		IPAddresses:           certInfo.IPAddrs,
	}

	if len(template.DNSNames) == 0 {
		template.DNSNames = []string{strings.ToLower(certInfo.Subject.CommonName)}
	}

	certDERBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, key.Public(), caKey)
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
