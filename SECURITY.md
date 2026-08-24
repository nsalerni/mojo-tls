# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately via
[GitHub security advisories](https://github.com/nsalerni/mojo-tls/security/advisories/new)
rather than public issues. You should receive a response within a week.

## Scope notes

mojo-tls uses OpenSSL for TLS 1.2 and TLS 1.3 through a small C shim. Client
connections verify certificate chains and hostnames by default. The package
also supports SNI, ALPN, non-blocking handshakes, and partial encrypted I/O.

Servers can require a client certificate and verify it against a configured
CA. `TLSStream.peer_certificate()` returns an owned copy of the peer leaf
certificate with its verification status. Certificate presence alone is not
authentication. Authorization code must require `verified` before it trusts
the DER bytes or matched hostname.

Certificates can contain personal or workload identity data. The package does
not log them. Applications should avoid logging or retaining certificate bytes
unless their policy requires it. An exact DER allowlist also needs an overlap
period when certificates rotate.

TLS session resumption is unsupported. The project has not had an external
security review. See [ROADMAP.md](ROADMAP.md) for the remaining work.
