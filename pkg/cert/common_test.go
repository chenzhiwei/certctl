package cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"reflect"
	"slices"
	"testing"
)

func TestNewCertInfo(t *testing.T) {
	var tests = []struct {
		subject  string
		san      string
		usage    string
		extUsage string
		isCA     bool
		expect   *CertInfo
	}{
		{
			subject:  "CN=root-ca/C=CN/ST=Beijing/L=Haidian/O=Root Inc",
			san:      "localhost,127.0.0.1,1.1.1.1,china.com",
			usage:    "cRLSign,keyCertSign,digitalSignature",
			extUsage: "",
			isCA:     true,
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
				KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
				ExtKeyUsage: []x509.ExtKeyUsage{},
			},
		},
		{
			subject:  "  CN  =  root-ca /C =CN  /ST  =   Beijing/L  =	Haidian/O=	Root Inc	",
			san:      "localhost,127.0.0.1,1.1.1.1,china.com",
			usage:    "cRLSign,keyCertSign,digitalSignature",
			extUsage: "",
			isCA:     true,
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
				KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
				ExtKeyUsage: []x509.ExtKeyUsage{},
			},
		},
		{
			subject:  "CN=china/C=CN/ST=Beijing/L=Haidian/O=China Inc",
			san:      "DNS:localhost,IP: 127.0.0.1  , DNS: localhost,IP:1.1.1.1,  china.com, 127.0.0.1",
			usage:    "digitalSignature  , keyEncipherment  ",
			extUsage: " clientAuth  ,serverAuth  ",
			isCA:     false,
			expect: &CertInfo{
				Subject: &pkix.Name{
					CommonName:   "china",
					Country:      []string{"CN"},
					Province:     []string{"Beijing"},
					Locality:     []string{"Haidian"},
					Organization: []string{"China Inc"},
				},
				DNSNames:    []string{"localhost", "china.com"},
				IPAddrs:     []net.IP{net.IPv4(127, 0, 0, 1), net.IPv4(1, 1, 1, 1)},
				KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			},
		},
		{
			subject:  " CN= china/ C =CN / ST = Beijing  / L= Haidian/ O = China Inc  ",
			san:      "DNS:localhost,IP: 127.0.0.1  , DNS: localhost,IP:1.1.1.1,  china.com, 127.0.0.1",
			usage:    "digitalSignature  , keyEncipherment  ",
			extUsage: " clientAuth  ,serverAuth  ",
			isCA:     false,
			expect: &CertInfo{
				Subject: &pkix.Name{
					CommonName:   "china",
					Country:      []string{"CN"},
					Province:     []string{"Beijing"},
					Locality:     []string{"Haidian"},
					Organization: []string{"China Inc"},
				},
				DNSNames:    []string{"localhost", "china.com"},
				IPAddrs:     []net.IP{net.IPv4(127, 0, 0, 1), net.IPv4(1, 1, 1, 1)},
				KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			},
		},
		{
			subject:  " CN= Union/ C = / ST = Beijing  / L= Haidian/ O = Root Inc /O=Union Inc ",
			san:      "192.168.122.10",
			usage:    " , keyCertSign  ",
			extUsage: " clientAuth  ,serverAuth  ",
			isCA:     false,
			expect: &CertInfo{
				Subject: &pkix.Name{
					CommonName:   "Union",
					Province:     []string{"Beijing"},
					Locality:     []string{"Haidian"},
					Organization: []string{"Root Inc", "Union Inc"},
				},
				DNSNames:    nil, // either nil or remove this assignment
				IPAddrs:     []net.IP{net.IPv4(192, 168, 122, 10)},
				KeyUsage:    x509.KeyUsageCertSign,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			},
		},
	}

	for _, test := range tests {
		certInfo, err := NewCertInfo(0, test.subject, test.san, test.usage, test.extUsage, test.isCA)
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

		if !slices.Equal(certInfo.ExtKeyUsage, test.expect.ExtKeyUsage) {
			t.Errorf("failed NewCertInfo.ExtKeyUsage:\n\tactual: %v\n\texpect: %v\n", certInfo.ExtKeyUsage, test.expect.ExtKeyUsage)
		}
	}
}
