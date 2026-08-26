# Examples

Both examples stay on loopback and use generated test certificates. They do
not use the external network.

| File | What it shows | Command |
|---|---|---|
| [blocking_tls_client.mojo](blocking_tls_client.mojo) | CA trust, hostname check, ALPN, exact request/response | `pixi run blocking-example` |
| [nonblocking_tls_echo.mojo](nonblocking_tls_echo.mojo) | Client and server on one `Poller` | `pixi run example` |

```sh
python3 tools/fetch_deps.py
pixi run blocking-example
pixi run example
```
