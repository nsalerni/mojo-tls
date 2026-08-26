# mojo-tls

[![CI](https://github.com/nsalerni/mojo-tls/actions/workflows/ci.yml/badge.svg)](https://github.com/nsalerni/mojo-tls/actions/workflows/ci.yml)
[![TLS compliance](https://img.shields.io/endpoint?url=https%3A%2F%2Fnsalerni.github.io%2Fmojo-tls%2Fcompliance-badge.json)](https://nsalerni.github.io/mojo-tls/COMPLIANCE.html)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

TLS 1.2 and TLS 1.3 for **Mojo 1.0**: client and server handshakes, SNI,
hostname verification, ALPN, and certificate verification over
[mojo-net](https://github.com/nsalerni/mojo-net)'s `TCPStream`.

**[Compliance report](https://nsalerni.github.io/mojo-tls/COMPLIANCE.html)**
([Markdown](COMPLIANCE.md)) is regenerated on every CI run.

## Install

```sh
curl -fsSL https://pixi.sh/install.sh | sh
git clone https://github.com/nsalerni/mojo-tls.git
cd mojo-tls
pixi install
python3 tools/fetch_deps.py
pixi run test
```

`fetch_deps.py` clones mojo-net into `.deps/`. A conda recipe lives in
[`recipe/`](recipe/).

## Example

A blocking client against a local CPython TLS server (no external network):

```sh
pixi run blocking-example
```

Non-blocking client and server on one `Poller`:

```sh
pixi run example
```

Client:

```mojo
from net import TCPStream
from tls import TLSContext

def main() raises:
    var context = TLSContext.client(
        ca_file="service-ca.pem",
        alpn=["h2"],
    )
    var tcp = TCPStream.connect("service.example", 443)
    var stream = context.connect(tcp^, "service.example")
```

Server that requires a client certificate:

```mojo
var context = TLSContext.server(
    "server-chain.pem",
    "server.key",
    client_ca_file="client-ca.pem",
    require_client_cert=True,
    alpn=["h2"],
)
```

Certificate chain and key are configured together. Private keys must be
unencrypted. After the handshake, `stream.peer_certificate()` returns an owned
leaf snapshot; check `verified` before trusting identity fields.

See [examples/README.md](examples/README.md).

## How it works

Cryptography stays in libssl (conda-forge `openssl`) through a small C shim
(`shim/mojotls_shim.c`). OpenSSL's server ALPN callback cannot be written in
Mojo, so the shim hosts it. Verification is on by default (strict X.509,
RFC 6125 hostname checks when SNI is set). TLS 1.2 is the floor.

`TLSContext.start_connect()` / `start_accept()` drive non-blocking handshakes.
The finished `TLSStream` implements both `IOStream` and `ReadinessStream`.

## Concurrency

Handshake and record-layer I/O are blocking on one stream, or readiness-driven
through `start_connect` / `start_accept` and `Poller`. There is no thread pool.
One handshake advances on the thread that calls `advance()`. Scale-out is
several processes, not an in-process async runtime.

## Compliance

Live checks against CPython's `ssl` module in both roles. Current results:
[COMPLIANCE.md](COMPLIANCE.md).

```sh
pixi run compliance
```

## Related packages

[mojo-net](https://github.com/nsalerni/mojo-net) ·
[mojo-http2](https://github.com/nsalerni/mojo-http2) ·
[grpc-mojo](https://github.com/nsalerni/grpc-mojo)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Session resumption is tracked in
[ROADMAP.md](ROADMAP.md).

## License

[Apache-2.0](LICENSE). Not affiliated with Modular or the OpenSSL project;
"Mojo" is a trademark of Modular Inc.
