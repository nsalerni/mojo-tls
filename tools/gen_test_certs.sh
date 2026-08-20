#!/bin/bash
# Generates the test certificate corpus into build/certs (idempotent):
#   ca.pem/ca.key            a throwaway test CA
#   server.pem/server.key    CA-signed, SAN localhost + 127.0.0.1
#   wronghost.pem/.key       CA-signed, SAN otherhost.example only
#   selfsigned.pem/.key      not signed by the CA
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$ROOT/build/certs"
mkdir -p "$DIR"
[ -f "$DIR/selfsigned.pem" ] && { echo "certs up to date: $DIR"; exit 0; }

openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 365 \
  -keyout "$DIR/ca.key" -out "$DIR/ca.pem" \
  -subj "/CN=mojo-tls test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1

issue() { # name subject san
  openssl req -newkey rsa:2048 -sha256 -nodes \
    -keyout "$DIR/$1.key" -out "$DIR/$1.csr" -subj "$2" >/dev/null 2>&1
  openssl x509 -req -sha256 -days 365 -in "$DIR/$1.csr" \
    -CA "$DIR/ca.pem" -CAkey "$DIR/ca.key" -CAcreateserial \
    -out "$DIR/$1.pem" -extfile <(printf "subjectAltName=%s\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n" "$3") >/dev/null 2>&1
  rm -f "$DIR/$1.csr"
}

issue server "/CN=localhost" "DNS:localhost,IP:127.0.0.1"
issue wronghost "/CN=otherhost.example" "DNS:otherhost.example"

openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 365 \
  -keyout "$DIR/selfsigned.key" -out "$DIR/selfsigned.pem" \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1

echo "generated test certs in $DIR"
