#!/bin/bash
# Generates the test certificate corpus into build/certs (idempotent):
#   ca.pem/ca.key            a throwaway test CA
#   server.pem/server.key    CA-signed, SAN localhost + 127.0.0.1
#   wronghost.pem/.key       CA-signed, SAN otherhost.example only
#   selfsigned.pem/.key      not signed by the CA
#   client_intermediate.pem/.key  intermediate CA signed by the root
#   client.pem/client.key    client authentication leaf
#   client-chain.pem         client leaf followed by its intermediate CA
#   client-encrypted.key     encrypted form of the client private key
#   other_ca.pem/.key        a second throwaway test CA
#   untrusted_client.pem/.key  signed by the second CA
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$ROOT/build/certs"
mkdir -p "$DIR"

required=(
  ca.pem ca.key server.pem server.key wronghost.pem wronghost.key
  selfsigned.pem selfsigned.key client.pem client.key client-chain.pem
  client_intermediate.pem client_intermediate.key client-encrypted.key
  other_ca.pem other_ca.key untrusted_client.pem untrusted_client.key
)
up_to_date=true
for file in "${required[@]}"; do
  if [ ! -f "$DIR/$file" ]; then
    up_to_date=false
    break
  fi
done
if [ "$up_to_date" = true ]; then
  echo "certs up to date: $DIR"
  exit 0
fi

make_ca() { # name subject
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 365 \
    -keyout "$DIR/$1.key" -out "$DIR/$1.pem" \
    -subj "$2" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
}

issue() { # name subject ca_name extended_key_usage [subject_alt_name]
  openssl req -newkey rsa:2048 -sha256 -nodes \
    -keyout "$DIR/$1.key" -out "$DIR/$1.csr" -subj "$2" >/dev/null 2>&1
  openssl x509 -req -sha256 -days 365 -in "$DIR/$1.csr" \
    -CA "$DIR/$3.pem" -CAkey "$DIR/$3.key" -CAcreateserial \
    -out "$DIR/$1.pem" -extfile <(
      printf "keyUsage=critical,digitalSignature,keyEncipherment\n"
      printf "extendedKeyUsage=%s\n" "$4"
      printf "basicConstraints=critical,CA:FALSE\n"
      if [ -n "${5:-}" ]; then
        printf "subjectAltName=%s\n" "$5"
      fi
    ) >/dev/null 2>&1
  rm -f "$DIR/$1.csr"
}

issue_intermediate() { # name subject ca_name
  openssl req -newkey rsa:2048 -sha256 -nodes \
    -keyout "$DIR/$1.key" -out "$DIR/$1.csr" -subj "$2" >/dev/null 2>&1
  openssl x509 -req -sha256 -days 365 -in "$DIR/$1.csr" \
    -CA "$DIR/$3.pem" -CAkey "$DIR/$3.key" -CAcreateserial \
    -out "$DIR/$1.pem" -extfile <(
      printf "basicConstraints=critical,CA:TRUE,pathlen:0\n"
      printf "keyUsage=critical,keyCertSign,cRLSign\n"
    ) >/dev/null 2>&1
  rm -f "$DIR/$1.csr"
}

make_ca ca "/CN=mojo-tls test CA"
make_ca other_ca "/CN=mojo-tls untrusted test CA"

issue server "/CN=localhost" ca serverAuth "DNS:localhost,IP:127.0.0.1"
issue wronghost "/CN=otherhost.example" ca serverAuth "DNS:otherhost.example"
issue_intermediate client_intermediate "/CN=mojo-tls client intermediate" ca
issue client "/CN=mojo-tls test client" client_intermediate clientAuth
cat "$DIR/client.pem" "$DIR/client_intermediate.pem" > "$DIR/client-chain.pem"
openssl pkey -in "$DIR/client.key" -aes-256-cbc \
  -passout pass:mojo-tls-test-only -out "$DIR/client-encrypted.key" \
  >/dev/null 2>&1
issue untrusted_client "/CN=mojo-tls untrusted client" other_ca clientAuth

openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 365 \
  -keyout "$DIR/selfsigned.key" -out "$DIR/selfsigned.pem" \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1

echo "generated test certs in $DIR"
