#!/usr/bin/env python3
"""Run the blocking Mojo client against a local CPython TLS server."""

import queue
import socket
import ssl
import subprocess
import threading
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CERTS = ROOT / "build" / "certs"
ALPN = "mojo-tls-echo/1"
REQUEST = b"mojo-tls blocking client\n"
RESPONSE = b"python ssl server reply\n"


def receive_exact(stream: ssl.SSLSocket, length: int) -> bytes:
    received = bytearray()
    while len(received) < length:
        chunk = stream.recv(length - len(received))
        if not chunk:
            raise RuntimeError("TLS client closed before sending its request")
        received.extend(chunk)
    return bytes(received)


def serve_once(
    listener: socket.socket,
    context: ssl.SSLContext,
    failures: queue.Queue[Exception],
) -> None:
    try:
        connection, _ = listener.accept()
        connection.settimeout(30)
        with context.wrap_socket(connection, server_side=True) as stream:
            if stream.selected_alpn_protocol() != ALPN:
                raise RuntimeError(f"TLS client did not negotiate {ALPN}")
            if receive_exact(stream, len(REQUEST)) != REQUEST:
                raise RuntimeError("TLS client sent an unexpected request")
            stream.sendall(RESPONSE)
    except Exception as error:
        failures.put(error)
    finally:
        listener.close()


def main() -> None:
    net_source = subprocess.check_output(
        ["python3", "tools/dep_src.py", "mojo-net"],
        cwd=ROOT,
        text=True,
    ).strip()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(CERTS / "server.pem", CERTS / "server.key")
    context.set_alpn_protocols([ALPN])

    seen_sni: queue.Queue[str | None] = queue.Queue()

    def require_localhost_sni(
        stream: ssl.SSLSocket,
        server_name: str | None,
        selected_context: ssl.SSLContext,
    ) -> int | None:
        del stream, selected_context
        seen_sni.put(server_name)
        if server_name != "localhost":
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
        return None

    context.set_servername_callback(require_localhost_sni)

    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(30)
    failures: queue.Queue[Exception] = queue.Queue()
    server = threading.Thread(
        target=serve_once,
        args=(listener, context, failures),
        name="blocking-tls-example-server",
        daemon=True,
    )
    server.start()

    try:
        subprocess.run(
            [
                "mojo",
                "run",
                "-I",
                "src",
                "-I",
                net_source,
                "examples/blocking_tls_client.mojo",
                str(listener.getsockname()[1]),
                str(CERTS / "ca.pem"),
            ],
            cwd=ROOT,
            check=True,
            timeout=60,
        )
    except BaseException:
        listener.close()
        server.join(timeout=1)
        raise

    server.join(timeout=35)
    if server.is_alive():
        listener.close()
        raise RuntimeError("local TLS server did not stop")

    if not failures.empty():
        raise failures.get()

    try:
        server_name = seen_sni.get_nowait()
    except queue.Empty as error:
        raise RuntimeError("TLS client did not send SNI") from error
    if server_name != "localhost":
        raise RuntimeError(f"TLS client sent unexpected SNI: {server_name!r}")


if __name__ == "__main__":
    main()
