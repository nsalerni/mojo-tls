# Roadmap

Shipped work lives in [CHANGELOG.md](CHANGELOG.md).

## Open

- TLS 1.3 session tickets, so reconnecting clients can skip a round trip.
  Verified by CPython `session_reused` checks and handshake-count assertions.

## Scope

Cryptography stays in libssl. This package is a small, verified stream on top
of that library: `IOStream` and `ReadinessStream`, with verification on by
default.
