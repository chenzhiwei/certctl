# certctl

Manage certificates with ease.

## Download

```
wget -O certctl https://github.com/chenzhiwei/certctl/releases/latest/download/certctl
chmod +x certctl
./certctl version
sudo mv certctl /usr/local/bin/
```

## Generate CA or Self-signed certificate

```
certctl generate --subject "C=CN/ST=Beijing/L=Haidian/O=Any Corp/CN=Any Root" \
    --key ca.key --cert ca.crt --days 36500 --size 4096

certctl generate --subject "C=CN/ST=Beijing/L=Haidian/O=Any Corp/CN=anycorp.com" \
    --san *.anycorp.com,localhost,127.0.0.1 \
    --key anycorp.com.key --cert anycorp.com.crt --days 365 --size 4096

certctl generate --subject "C=CN/ST=Beijing/L=Haidian/O=Any Corp/CN=anycorp.com" \
    --san *.anycorp.com,localhost,127.0.0.1 \
    --key anycorp.com.key --cert anycorp.com.crt --days 365 --size 4096 \
    --usage digitalSignature,keyEncipherment \
    --extusage serverAuth,clientAuth,emailProtection

certctl help generate
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

## Sign certificate with CA

```
certctl sign --ca-key ca.key --ca-cert ca.crt --subject "CN=my.anycorp.com" \
    --san www.my.anycorp.com,localhost,127.0.0.1 \
    --key my.anycorp.com.key --cert my.anycorp.com.crt

certctl sign --ca-key ca.key --ca-cert ca.crt --is-ca \
    --subject "CN=my.anycorp.com" \
    --key my.anycorp.com.key --cert my.anycorp.com.crt \
    --usage digitalSignature,keyEncipherment,keyCertSign \
    --extusage serverAuth,codeSigning

certctl help sign
```

## Show certificate/csr from file

```
certctl show cert-filepath.crt
certctl show csr-filepath.csr
```
