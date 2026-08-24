# mojo-tls

[![CI](https://github.com/nsalerni/mojo-tls/actions/workflows/ci.yml/badge.svg)](https://github.com/nsalerni/mojo-tls/actions/workflows/ci.yml)
[![TLS compliance](https://img.shields.io/endpoint?url=https%3A%2F%2Fnsalerni.github.io%2Fmojo-tls%2Fcompliance-badge.json)](https://nsalerni.github.io/mojo-tls/COMPLIANCE.html)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

**[📋 Compliance report](https://nsalerni.github.io/mojo-tls/COMPLIANCE.html)** ([Markdown](COMPLIANCE.md)). Every CI run regenerates it against CPython's `ssl` module on the other end of a live connection.

TLS for **Mojo 1.0**: client and server handshakes, SNI with hostname
verification, ALPN on both roles, and strict certificate verification,
wrapped around [mojo-net](https://github.com/nsalerni/mojo-net)'s
`TCPStream`. `TLSStream` conforms to both `IOStream` and `ReadinessStream`,
so protocol layers can use blocking helpers or drive partial encrypted I/O
with the same Poller used for plain sockets.

## Quick start

The [blocking TLS client example](examples/blocking_tls_client.mojo) connects
to a local CPython TLS server. It trusts only the generated test CA, verifies
the server certificate for `localhost`, negotiates the documented
`mojo-tls-echo/1` ALPN token, and checks an exact request and response. It does
not use the external network.

```sh
python3 tools/fetch_deps.py
pixi run blocking-example
```

The client copies the verified peer certificate before closing the stream.
That snapshot owns its DER bytes, so it remains valid after the connection
closes. Verification comes from the CA and hostname checks in the handshake,
not from the presence of certificate bytes.

The [non-blocking TLS echo example](examples/nonblocking_tls_echo.mojo) drives
a verified client and server on one Poller. It demonstrates SNI, hostname
verification, h2 ALPN negotiation, non-blocking handshake progress, and
partial encrypted I/O over a loopback connection.

```sh
pixi run example
```

Clients can present a certificate when a service requires mutual TLS:

```mojo
from net import TCPStream
from tls import TLSContext

def main() raises:
    var context = TLSContext.client(
        ca_file="service-ca.pem",
        cert_chain_pem="client-chain.pem",
        key_pem="client.key",
        alpn=["h2"],
    )
    var tcp = TCPStream.connect("service.example", 443)
    var stream = context.connect(tcp^, "service.example")
```

The certificate chain and key must be configured together. mojo-tls checks
that they match while it builds the context, before opening a connection.
Private keys must be unencrypted. Encrypted keys fail without prompting for a
passphrase.

Servers can require a client certificate signed by a configured CA:

```mojo
var context = TLSContext.server(
    "server-chain.pem",
    "server.key",
    client_ca_file="client-ca.pem",
    require_client_cert=True,
    alpn=["h2"],
)
```

`client_ca_file` and `require_client_cert=True` must be provided together.
The default server configuration does not request a client certificate.

After a handshake, `TLSStream.peer_certificate()` returns an owned snapshot of
the peer's leaf certificate:

```mojo
var peer = stream.peer_certificate()
if not peer or not peer.value().verified:
    raise Error("verified peer certificate required")
var identity = peer.value().copy()
# Compare identity.leaf_der with an allowed certificate.
```

`leaf_der` contains the exact leaf certificate bytes and remains valid after
the stream closes. It does not include the certificate chain. `verified` is
true only when this connection required peer verification and OpenSSL accepted
the certificate. Certificate presence alone does not establish trust.

On a verifying client, `matched_name` is the certificate name that OpenSSL
matched during hostname verification. It is empty for server-side client
certificates and connections that did not perform a hostname check. The
package does not log certificate bytes or identity fields.

## How it works

The protocol logic everywhere else in this family is pure Mojo; the
cryptography deliberately is not. Nobody serious reimplements TLS, so
mojo-tls binds libssl (from the conda-forge `openssl` package) through a
small C shim (`shim/mojotls_shim.c`). OpenSSL's server-side ALPN selection
requires a C callback, which Mojo cannot provide. The shim hosts that
callback and flattens the context/handshake/read/write surface into plain
functions loaded with `dlopen`. `tools/build_shim.sh` compiles it with
the environment's C compiler; the test and compliance tasks run it
automatically.

For event loops, set the TCP stream non-blocking and use
`TLSContext.start_connect()` or `start_accept()`. Each
`TLSHandshake.advance()` call either completes or reports whether libssl needs
readability or writability. The finished `TLSStream` preserves the same
direction through `wants_read()` and `wants_write()` whenever `read()` or
`write_some()` raises the typed would-block error.

Verification is strict by default, matching modern CPython: full chain
validation with X.509 strict checks, and RFC 6125 hostname verification
whenever SNI is given. TLS 1.2 is the floor.

## Verification

Every behavior is checked against CPython's `ssl` module live on the
other end of the connection, in both roles:

- TLS 1.3 and (server-capped) 1.2 negotiation, with bulk transfer
  through the record layer
- ALPN agreement, plus both RFC 7301 no-overlap behaviors: our server
  sends the fatal alert, and our client tolerates a server that proceeds
  without a protocol
- chain and hostname verification, with a generated bad-certificate
  corpus (self-signed, wrong hostname) that both implementations must
  reject for the same reasons
- client certificate presentation and server-side verification under TLS 1.2
  and TLS 1.3, with trusted chains and rejection of missing certificates,
  untrusted chains, server-only certificates, mismatched keys, and encrypted
  keys
- owned peer leaf certificates, verification status, and matched hostnames in
  both roles under TLS 1.2 and TLS 1.3
- non-blocking handshake progress, an 8 MiB partial-I/O exchange, and a bounded
  WANT_WRITE backpressure probe against CPython TLS peers

Current results: [COMPLIANCE.md](COMPLIANCE.md).

```sh
python3 tools/fetch_deps.py   # standalone checkout: fetch mojo-net source
pixi run test                 # unit tests (builds the shim + cert corpus)
pixi run compliance           # differential vs CPython ssl; rewrites COMPLIANCE.md
```

## Status

Built for [grpc-mojo](https://github.com/nsalerni/grpc-mojo), which uses it
for secure HTTP/2 and gRPC transports. Structured certificate name access and
session resumption remain; see [ROADMAP.md](ROADMAP.md).

## License

[Apache-2.0](LICENSE). Not affiliated with Modular or the OpenSSL
project; "Mojo" is a trademark of Modular Inc.
