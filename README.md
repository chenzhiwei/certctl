# certctl

certctl is a certificate utility tool, it can:

1. Generate Root CA certificate
2. Generate self-signed certificate
3. Sign certificate or Immediate CA with Root CA certificate
4. Show certificate or certificate signing request info
5. Fetch certificate from an HTTPS URL
6. Verify if a certificate matches the private key or CA certificate

## Download

```
curl -LO https://github.com/chenzhiwei/certctl/releases/latest/download/certctl
chmod +x certctl
./certctl version
sudo mv certctl /usr/local/bin/
```

## Generate certificate

### Generate Root CA certificate

```
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

certctl help genca
```

### Generate self-signed Certificate

```
# Generate self-signed certificate
certctl generate --subject "C=CN/ST=Beijing/L=Haidian/O=Any Corp/CN=any.com" \
    --san "any.com,*.any.com,localhost,127.0.0.1" \
    --key any.com.key --cert any.com.crt \
    --days 730 --size 2048

# Set Key Usages and Extended Key usages manaully
certctl generate --subject "C=CN/ST=Beijing/L=Haidian/O=Any Corp/CN=Root CA" \
    --nodefault --ku digitalSignature,keyCertSign --eku serverAuth \
    --san "any.com,*.any.com,localhost,127.0.0.1" \
    --key any.com.key --cert any.com.crt \
    --days 730 --size 2048

certctl help generate
```

### Sign a certificate with CA

```
# Sign a certificate with CA certificate
certctl sign --ca-key ca.key --ca-cert ca.crt \
    --subject "CN=anycorp.com" \
    --san anycorp.com,www.anycorp.com,localhost,127.0.0.1 \
    --key anycorp.com.key --cert anycorp.com.crt \
    --usage digitalSignature,keyEncipherment \
    --extusage serverAuth,clientAuth \
    --days 730 --size 2048

certctl help sign
```

A full list a key usages are:

* digitalSignature
* contentCommitment
* keyEncipherment
* dataEncipherment
* keyAgreement
* keyCertSign
* cRLSign
* encipherOnly
* decipherOnly

A full list of extended key usages are:

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


## Show certificate/csr from file

```
certctl show cert-filepath.crt
certctl show csr-filepath.csr
```

## Fetch certificate from URL

```
certctl fetch 192.168.122.10:8443
certctl fetch https://pkg.go.dev/io
certctl fetch golang.org
certctl fetch golang.org --file golang.org.crt --noout
```

## Verify certificate with private key and/or CA certificate

```
certctl verify --cert domain.crt --ca ca.crt
certctl verify --cert domain.crt --key domain.key
certctl verify --cert domain.crt --key domain.key --ca ca.crt
```
