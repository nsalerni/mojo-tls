# Changelog

## Unreleased

- Shortened the README and added contributor, issue, and pull-request
  templates.

## 0.3.0 - 2026-08-25

- Added a local blocking client example with CA, hostname, ALPN, certificate,
  request, and response checks.
- Added differential checks for clean `close_notify` EOF and truncated TLS
  transports against CPython clients and servers.
- Added owned DNS, URI, email, and IP subject alternative names to peer
  certificate snapshots.
- Added bounded parsing that rejects ASCII control bytes, DEL, invalid IP
  lengths, empty extensions, oversized values, and certificates with more
  than 256 names.
- Added CPython comparisons for server and client certificate names under TLS
  1.2 and TLS 1.3.

## 0.2.4 - 2026-08-24

- Added owned peer leaf certificate snapshots to `TLSStream`, including the
  connection's verification status and matched hostname.
- Added CPython checks for peer certificate identity in both roles under TLS
  1.2 and TLS 1.3, plus no-certificate and verification-disabled cases.
- Added required server-side client certificate verification against a
  configured CA, with strict X.509 checks and safe paired configuration.
- Added live CPython client checks under TLS 1.2 and TLS 1.3 for trusted and
  missing identities, plus TLS 1.3 checks for untrusted and wrong-purpose
  identities.
- Added client certificate presentation with construction-time certificate
  and key validation.
- Client certificate chains may include intermediate certificates. Encrypted
  private keys fail without an interactive prompt.
- Added differential checks against CPython for trusted chains and rejected
  missing, untrusted, wrong-purpose, mismatched, and encrypted-key
  configurations.

## 0.2.3 - 2026-08-22

- Prevented reset TLS peers from terminating Linux servers with SIGPIPE.

## 0.2.2 - 2026-08-22

- Isolated each libssl operation from errors left by another TLS session on
  the same event-loop thread.

## 0.2.1 - 2026-08-21

- Added readiness-driven client and server handshakes that preserve libssl's
  WANT_READ and WANT_WRITE progress states.
- Made `TLSStream` conform to `ReadinessStream` with partial encrypted reads
  and writes while keeping the blocking `IOStream` API compatible.
- Added bounded non-blocking transfer and backpressure differentials against
  CPython TLS peers.

## 0.2.0 - 2026-08-21

- Ships the compiled Mojo module and native OpenSSL shim in one package.
- Uses exact relative loader paths on macOS and Linux, with strict Mojo 1.0,
  mojo-net 0.2, and OpenSSL 3 dependency ranges.
- Tests the installed artifact with CA and hostname verification, `h2` ALPN,
  and an encrypted echo on both supported CI platforms.

## 0.1.0 - 2026-08-21

Initial release.

- `TLSContext` (client and server) and `TLSStream` over mojo-net's
  `TCPStream`, conforming to the `IOStream` trait.
- TLS 1.2/1.3, SNI with RFC 6125 hostname verification, ALPN on both
  roles (server selection via the C shim's callback), strict X.509
  chain verification matching modern CPython.
- Differential compatibility suite against CPython's `ssl` module:
  version negotiation, ALPN agreement and no-overlap behavior, bulk
  transfer, and a generated bad-certificate corpus both implementations
  must reject.
