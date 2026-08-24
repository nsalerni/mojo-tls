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
CA. `TLSStream` does not expose the verified peer certificate identity yet, so
callers cannot make certificate-specific authorization decisions. TLS session
resumption is also unsupported. The project has not had an external security
review. See [ROADMAP.md](ROADMAP.md) for the remaining work.
