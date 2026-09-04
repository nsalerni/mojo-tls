# Roadmap

Shipped work lives in [CHANGELOG.md](CHANGELOG.md).

## Open

Nothing currently in scope is waiting on a local API. TLS 1.3 session
tickets shipped in 0.3.1; a ticket resumes the handshake only and never
sends 0-RTT application data.

## Blocked

Nothing currently in scope is waiting on a Mojo language feature. Client
certificates, SNI, ALPN, hostname verification, and readiness-driven
handshakes already ship. HTTP/3 and QUIC are different protocols, not TLS
extensions of this stream.

## Scope

Cryptography stays in libssl. This package is a small, verified stream on top
of that library: `IOStream` and `ReadinessStream`, with verification on by
default.
