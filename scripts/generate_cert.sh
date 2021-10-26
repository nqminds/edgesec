#!/bin/sh

set -e

[ -z "$1" ] && echo "Host not specified!" && exit 1

rm -rf cert
mkdir cert
cd cert
mkdir CA
cd CA
openssl genrsa -out CA.key -des3 2048
openssl req -x509 -sha256 -new -nodes -days 3650 -key CA.key -out CA.pem

mkdir server
cd server

cat > server.ext <<EOF
authorityKeyIdentifier = keyid,issuer
basicConstraints = CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = $1
#IP.1 = $2
EOF

openssl genrsa -out server.encrypted.key -des3 2048
openssl req -new -key server.encrypted.key -out server.csr
openssl x509 -req -in server.csr -CA ../CA.pem -CAkey ../CA.key -CAcreateserial -days 3650 -sha256 -extfile server.ext -out server.crt
openssl rsa -in server.encrypted.key -out server.key