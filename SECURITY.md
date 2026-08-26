# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately via
[GitHub security advisories](https://github.com/nsalerni/mojo-tls/security/advisories/new)
rather than public issues. You should receive a response within a week.

## Scope

mojo-tls uses OpenSSL for TLS 1.2 and TLS 1.3 through a small C shim. Clients
verify certificate chains and hostnames by default. Servers can require a
client certificate.

`TLSStream.peer_certificate()` returns an owned leaf snapshot.
Certificate presence is not authentication; require `verified` before trusting
identity fields. The package does not log certificates.

TLS session resumption is unsupported. The project has not had an external
security review. See [ROADMAP.md](ROADMAP.md).
