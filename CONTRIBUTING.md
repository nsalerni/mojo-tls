# Contributing to mojo-tls

Thanks for looking at the project. TLS behavior is checked against CPython's
`ssl` module on a live connection.

## Setup

```sh
curl -fsSL https://pixi.sh/install.sh | sh
git clone https://github.com/nsalerni/mojo-tls.git
cd mojo-tls
pixi install
python3 tools/fetch_deps.py
pixi run test
```

## Style

- Public APIs follow the
  [Mojo docstring style](https://github.com/modular/modular/blob/main/mojo/stdlib/docs/docstring-style-guide.md).
- This repo targets Mojo 1.0: `def` only (no `fn`), `comptime` not `alias`,
  `std.`-prefixed imports, and explicit `.copy()` / `^` moves. SNI,
  filesystem paths, and other borrowed text take `StringSpan`. Paths are
  copied to `String` at the OpenSSL FFI boundary.
  Tests are plain executables run by `tools/run_tests.py` (`mojo test` no
  longer exists).

## Checks

```sh
pixi run test
pixi run compliance    # if you change handshake, identity, or I/O behavior
```

The C shim in `shim/` is part of the security surface; keep it small and
paired with a differential check.

Fork, branch from `main`, and keep pull requests focused. By contributing,
you agree that your contributions are licensed under
[Apache License 2.0](LICENSE).
