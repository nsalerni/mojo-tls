# Changelog

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
