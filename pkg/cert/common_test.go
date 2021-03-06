package cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"reflect"
	"testing"
)

func TestNewCertInfo(t *testing.T) {
	var tests = []struct {
		subject  string
		san      string
		usage    string
		extUsage string
		expect   *CertInfo
	}{
		{
			subject:  "CN=root-ca/C=CN/ST=Beijing/L=Haidian/O=Root Inc",
			san:      "localhost,127.0.0.1,1.1.1.1,china.com",
			usage:    "cRLSign",
			extUsage: "",
			expect: &CertInfo{
				Subject: &pkix.Name{
					CommonName:   "root-ca",
					Country:      []string{"CN"},
					Province:     []string{"Beijing"},
					Locality:     []string{"Haidian"},
					Organization: []string{"Root Inc"},
				},
				DNSNames:    []string{"localhost", "china.com"},
				IPAddrs:     []net.IP{net.IPv4(127, 0, 0, 1), net.IPv4(1, 1, 1, 1)},
				KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			},
		},
		{
			subject:  " CN= root-ca/ C =CN / ST = Beijing  / L= Haidian/ O = Root Inc  ",
			san:      "DNS:localhost,IP: 127.0.0.1  , DNS: localhost,IP:1.1.1.1,  china.com, 127.0.0.1",
			usage:    "cRLSign  , keyCertSign  ",
			extUsage: " clientAuth  ,serverAuth  ",
			expect: &CertInfo{
				Subject: &pkix.Name{
					CommonName:   "root-ca",
					Country:      []string{"CN"},
					Province:     []string{"Beijing"},
					Locality:     []string{"Haidian"},
					Organization: []string{"Root Inc"},
				},
				DNSNames:    []string{"localhost", "china.com"},
				IPAddrs:     []net.IP{net.IPv4(127, 0, 0, 1), net.IPv4(1, 1, 1, 1)},
				KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			},
		},
		{
			subject:  " CN= root-ca/ C = / ST = Beijing  / L= Haidian/ O = Root Inc /O=Union Inc ",
			san:      "DNS:localhost,IP: 127.0.0.1  , DNS: localhost,IP:1.1.1.1,  china.com, 127.0.0.1",
			usage:    "cRLSign  , keyCertSign  ",
			extUsage: " clientAuth  ,serverAuth  ",
			expect: &CertInfo{
				Subject: &pkix.Name{
					CommonName:   "root-ca",
					Province:     []string{"Beijing"},
					Locality:     []string{"Haidian"},
					Organization: []string{"Root Inc", "Union Inc"},
				},
				DNSNames:    []string{"localhost", "china.com"},
				IPAddrs:     []net.IP{net.IPv4(127, 0, 0, 1), net.IPv4(1, 1, 1, 1)},
				KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			},
		},
		{
			subject:  " CN= Root-CA/ C = / ST = Beijing  / L= Haidian/ O = Root Inc /O=Union Inc ",
			usage:    "cRLSign  , keyCertSign  ",
			extUsage: " clientAuth  ,serverAuth  ",
			expect: &CertInfo{
				Subject: &pkix.Name{
					CommonName:   "Root-CA",
					Province:     []string{"Beijing"},
					Locality:     []string{"Haidian"},
					Organization: []string{"Root Inc", "Union Inc"},
				},
				DNSNames:    []string{"root-ca"},
				KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			},
		},
		{
			subject:  " CN= 192.168.122.10/ C = / ST = Beijing  / L= Haidian/ O = Root Inc /O=Union Inc ",
			usage:    "cRLSign  , keyCertSign  ",
			extUsage: " clientAuth  ,serverAuth  ",
			expect: &CertInfo{
				Subject: &pkix.Name{
					CommonName:   "192.168.122.10",
					Province:     []string{"Beijing"},
					Locality:     []string{"Haidian"},
					Organization: []string{"Root Inc", "Union Inc"},
				},
				DNSNames:    nil, // either nil or remove this assignment
				IPAddrs:     []net.IP{net.IPv4(192, 168, 122, 10)},
				KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			},
		},
	}

	for _, test := range tests {
		certInfo, err := NewCertInfo(0, test.subject, test.san, test.usage, test.extUsage, true)
		if err != nil {
			t.Errorf("something wrong")
		}

		if !reflect.DeepEqual(certInfo.Subject, test.expect.Subject) {
			t.Errorf("failed NewCertInfo.Subject:\n\tactual: %v\n\texpect: %v\n", certInfo.Subject, test.expect.Subject)
		}

		if !reflect.DeepEqual(certInfo.DNSNames, test.expect.DNSNames) {
			t.Errorf("failed NewCertInfo.DNSNames:\n\tactual: %v\n\texpect: %v\n", certInfo.DNSNames, test.expect.DNSNames)
		}

		if !reflect.DeepEqual(certInfo.IPAddrs, test.expect.IPAddrs) {
			t.Errorf("failed NewCertInfo.IPAddrs:\n\tactual: %v\n\texpect: %v\n", certInfo.IPAddrs, test.expect.IPAddrs)
		}

		if !reflect.DeepEqual(certInfo.KeyUsage, test.expect.KeyUsage) {
			t.Errorf("failed NewCertInfo.KeyUsage:\n\tactual: %v\n\texpect: %v\n", certInfo.KeyUsage, test.expect.KeyUsage)
		}

		if !reflect.DeepEqual(certInfo.ExtKeyUsage, test.expect.ExtKeyUsage) {
			t.Errorf("failed NewCertInfo.ExtKeyUsage:\n\tactual: %v\n\texpect: %v\n", certInfo.ExtKeyUsage, test.expect.ExtKeyUsage)
		}
	}
}
