# Roadmap

Same rule as the rest of the family: nothing lands without a differential
check against a reference implementation. Here the reference is CPython's
`ssl` module on the other end of a live connection.

## 1. Structured certificate names

Expose subject alternative names as typed DNS, URI, email, and IP values.
The current API returns the complete leaf certificate as DER and the hostname
matched by client verification, without guessing at authorization policy.

## 2. Session resumption

TLS 1.3 session tickets, so reconnecting clients skip a round trip.
Verified by CPython session-reuse checks (`session_reused` on the
reference side) and handshake-count assertions.

## Completed foundation

`TLSStream.peer_certificate()` copies the peer leaf certificate out of libssl.
The snapshot records whether this connection verified the certificate and the
certificate name matched by client hostname verification. CPython peers check
the exact DER bytes in both roles under TLS 1.2 and TLS 1.3. A missing client
certificate and verification-disabled connections have explicit results.

`TLSContext.server` can require a client certificate signed by a configured
CA. CPython clients verify acceptance of a trusted chain and rejection of
missing, untrusted, and wrong-purpose certificates. The client CA and required
flag must be configured together.

`TLSContext.client` can present a certificate chain and private key. A strict
CPython server checks the successful readiness-driven handshake and rejects
missing, untrusted, and wrong-purpose identities. Both mojo-tls and CPython
reject a mismatched certificate and key before any connection is opened.

`TLSHandshake` advances client and server handshakes one readiness event at a
time. `TLSStream` implements mojo-net's `ReadinessStream`, preserving
WANT_READ and WANT_WRITE so a Poller can drive encrypted partial I/O. CPython
peers verify a full 8 MiB exchange and bounded backpressure behavior.

## Deliberate scope

The cryptography stays in libssl, permanently. Reimplementing TLS
primitives is how implementations end up in CVE databases; the value this
package adds is a small, verified, trait-conforming stream on top of the
library everything else already trusts.
