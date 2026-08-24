# Roadmap

Same rule as the rest of the family: nothing lands without a differential
check against a reference implementation. Here the reference is CPython's
`ssl` module on the other end of a live connection.

## 1. Server-side client certificate verification

`TLSContext.server` needs an explicit client CA and a required-client option.
It will be checked against CPython clients with trusted, missing, untrusted,
and wrong-purpose certificates. Peer identity access will follow separately
so applications can make authorization decisions.

## 2. Session resumption

TLS 1.3 session tickets, so reconnecting clients skip a round trip.
Verified by CPython session-reuse checks (`session_reused` on the
reference side) and handshake-count assertions.

## Completed foundation

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
