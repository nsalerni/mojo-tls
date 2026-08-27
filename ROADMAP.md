# Roadmap

Shipped work lives in [CHANGELOG.md](CHANGELOG.md).

## Open

These are not blocked on Mojo 1.0 or another package:

- TLS 1.3 session tickets, so reconnecting clients can resume with a PSK
  and skip the full certificate handshake. A ticket does not by itself
  send 0-RTT application data. OpenSSL already exposes the session APIs;
  this package has not wired ticket store/resume yet. Verify with CPython
  `session_reused` checks and handshake-count assertions once it lands.

## Blocked

Nothing currently in scope is waiting on a Mojo language feature. Client
certificates, SNI, ALPN, hostname verification, and readiness-driven
handshakes already ship. HTTP/3 and QUIC are different protocols, not TLS
extensions of this stream.

## Scope

Cryptography stays in libssl. This package is a small, verified stream on top
of that library: `IOStream` and `ReadinessStream`, with verification on by
default.
