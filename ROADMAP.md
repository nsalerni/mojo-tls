# Roadmap

Same rule as the rest of the family: nothing lands without a differential
check against a reference implementation. Here the reference is CPython's
`ssl` module on the other end of a live connection.

## 1. Client certificates (mTLS)

The shim and libssl already support it; the API does not expose it.
`TLSContext.client` grows cert/key parameters and `TLSContext.server`
grows a required-client-CA option. Verified by mutual-auth handshakes
against CPython in both roles, including the rejection paths (no client
cert offered, untrusted client cert).

## 2. Session resumption

TLS 1.3 session tickets, so reconnecting clients skip a round trip.
Verified by CPython session-reuse checks (`session_reused` on the
reference side) and handshake-count assertions.

## 3. Non-blocking TLS

`TLSStream` over a non-blocking `TCPStream`, surfacing the typed
would-block error so mojo-net's `Poller` can drive TLS connections in an
event loop. This is what a concurrent TLS server needs. Verified by the
same readiness differentials mojo-net uses, run through the TLS layer.

## Deliberate scope

The cryptography stays in libssl, permanently. Reimplementing TLS
primitives is how implementations end up in CVE databases; the value this
package adds is a small, verified, trait-conforming stream on top of the
library everything else already trusts.
