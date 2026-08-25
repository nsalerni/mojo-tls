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
  malformed_nul.pem malformed_nul.key malformed_lf.pem malformed_lf.key
  malformed_high.pem malformed_high.key malformed_ip.pem malformed_ip.key
  oversized_san_value.pem oversized_san_value.key
  empty_san.pem empty_san.key
  too_many_sans.pem too_many_sans.key
  too_many_san_bytes.pem too_many_san_bytes.key
  typed_sans_v1
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

issue server "/CN=localhost" ca serverAuth \
  "DNS:localhost,DNS:service.example.test,IP:127.0.0.1,IP:2001:db8::1,URI:spiffe://example.test/server,email:server@example.test,RID:1.2.3.4"
issue wronghost "/CN=otherhost.example" ca serverAuth "DNS:otherhost.example"
issue_intermediate client_intermediate "/CN=mojo-tls client intermediate" ca
issue client "/CN=mojo-tls test client" client_intermediate clientAuth \
  "DNS:client.example.test,IP:192.0.2.44,IP:2001:db8::44,URI:spiffe://example.test/client,email:client@example.test"
cat "$DIR/client.pem" "$DIR/client_intermediate.pem" > "$DIR/client-chain.pem"
openssl pkey -in "$DIR/client.key" -aes-256-cbc \
  -passout pass:mojo-tls-test-only -out "$DIR/client-encrypted.key" \
  >/dev/null 2>&1
issue untrusted_client "/CN=mojo-tls untrusted client" other_ca clientAuth

issue malformed_nul "/CN=embedded NUL test" ca serverAuth \
  "DNS:malformed.example"
issue malformed_lf "/CN=embedded LF test" ca serverAuth \
  "DNS:linefeed.example"
issue malformed_high "/CN=high byte test" ca serverAuth \
  "DNS:highbyte.example"
issue malformed_ip "/CN=invalid IP length test" ca serverAuth "DNS:abcde"
oversized_uri_prefix="spiffe://example.test/"
oversized_uri_padding_length=$((4097 - ${#oversized_uri_prefix}))
printf -v oversized_uri_padding '%*s' "$oversized_uri_padding_length" ''
oversized_uri_padding=${oversized_uri_padding// /a}
issue oversized_san_value "/CN=oversized SAN value test" ca serverAuth \
  "URI:${oversized_uri_prefix}${oversized_uri_padding}"
openssl req -newkey rsa:2048 -sha256 -nodes \
  -keyout "$DIR/empty_san.key" -out "$DIR/empty_san.csr" \
  -subj "/CN=empty SAN test" >/dev/null 2>&1
openssl x509 -req -sha256 -days 365 -in "$DIR/empty_san.csr" \
  -CA "$DIR/ca.pem" -CAkey "$DIR/ca.key" -CAcreateserial \
  -out "$DIR/empty_san.pem" -extfile <(
    printf "2.5.29.17=DER:30:00\n"
    printf "keyUsage=critical,digitalSignature,keyEncipherment\n"
    printf "extendedKeyUsage=serverAuth\n"
    printf "basicConstraints=critical,CA:FALSE\n"
  ) >/dev/null 2>&1
rm -f "$DIR/empty_san.csr"

many_sans="DNS:localhost"
for index in $(seq 1 256); do
  many_sans+=",DNS:name${index}.example.test"
done
issue too_many_sans "/CN=SAN count test" ca serverAuth "$many_sans"

printf -v long_path '%*s' 4050 ''
long_path=${long_path// /a}
many_uri_sans="URI:spiffe://example.test/1/$long_path"
for index in $(seq 2 17); do
  many_uri_sans+=",URI:spiffe://example.test/${index}/$long_path"
done
issue too_many_san_bytes "/CN=SAN byte count test" ca serverAuth \
  "$many_uri_sans"

openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 365 \
  -keyout "$DIR/selfsigned.key" -out "$DIR/selfsigned.pem" \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1

openssl x509 -in "$DIR/malformed_nul.pem" -outform DER \
  -out "$DIR/malformed_nul.der"
openssl x509 -in "$DIR/malformed_lf.pem" -outform DER \
  -out "$DIR/malformed_lf.der"
openssl x509 -in "$DIR/malformed_high.pem" -outform DER \
  -out "$DIR/malformed_high.der"
openssl x509 -in "$DIR/malformed_ip.pem" -outform DER \
  -out "$DIR/malformed_ip.der"
python3 - "$DIR" <<'PY'
import ssl
import sys
from pathlib import Path

directory = Path(sys.argv[1])


def patch(name: str, old: bytes, new: bytes) -> None:
    der_path = directory / f"{name}.der"
    data = der_path.read_bytes()
    if data.count(old) != 1 or len(old) != len(new):
        raise RuntimeError(f"unexpected {name} certificate encoding")
    data = data.replace(old, new)
    (directory / f"{name}.pem").write_text(
        ssl.DER_cert_to_PEM_cert(data), encoding="ascii"
    )
    der_path.unlink()


patch("malformed_nul", b"malformed.example", b"malformed\x00example")
patch("malformed_lf", b"linefeed.example", b"linefeed\nexample")
patch("malformed_high", b"highbyte.example", b"highbyte\x80example")
patch("malformed_ip", b"\x82\x05abcde", b"\x87\x05abcde")
PY

: > "$DIR/typed_sans_v1"

echo "generated test certs in $DIR"
