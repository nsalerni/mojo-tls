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

TLS session resumption uses TLS 1.3 tickets for the handshake only. Early
data (0-RTT) is disabled. Encrypted PEM keys are rejected without a
passphrase prompt on both the client identity path and server context
construction. An IPv4 or IPv6 literal as the connect name verifies IP
SANs and does not send SNI. An empty connect name still skips hostname
verification (the chain is verified when `verify=True`).

`$MOJO_TLS_SHIM` loads a caller-supplied shared library; treat that path
as a trust boundary. Cipher-suite, OCSP, and CRL policy stay with the
OpenSSL build. The project has not had an external security review. See
[ROADMAP.md](ROADMAP.md).
