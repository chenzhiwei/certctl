package cert

import (
	"bytes"
	"crypto/tls"
	"encoding/pem"
)

func FetchCert(addr string) ([]byte, error) {
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates

	var buf bytes.Buffer
	for _, crt := range certs {
		b := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: crt.Raw,
		})

		buf.Write(b)
	}

	return buf.Bytes(), nil
}
