# ===----------------------------------------------------------------------=== #
# Copyright (c) 2026 the grpc-mojo contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ===----------------------------------------------------------------------=== #

"""Verified, readiness-driven TLS echo over a single Poller.

The client trusts only the generated test CA and verifies "localhost" as
both its SNI name and certificate identity. Both endpoints negotiate the h2
ALPN token, advance their handshakes without blocking, and retain plaintext
across partial encrypted writes.
"""

from net import Poller, TCPListener, TCPStream, is_would_block
from tls import TLSContext


comptime CA = "build/certs/ca.pem"
comptime SERVER_CERT = "build/certs/server.pem"
comptime SERVER_KEY = "build/certs/server.key"
comptime PAYLOAD_SIZE = 1024 * 1024


def payload_byte(index: Int) -> UInt8:
    return UInt8((index * 17 + 11) % 256)


def main() raises:
    var listener = TCPListener("127.0.0.1", 0)
    var client_tcp = TCPStream.connect("127.0.0.1", listener.local_port)
    var server_tcp = listener.accept()
    listener.close()
    client_tcp.set_nonblocking(True)
    server_tcp.set_nonblocking(True)

    var client_context = TLSContext.client(ca_file=CA, alpn=["h2"])
    var server_context = TLSContext.server(SERVER_CERT, SERVER_KEY, alpn=["h2"])
    var client_handshake = client_context.start_connect(
        client_tcp^, "localhost"
    )
    var server_handshake = server_context.start_accept(server_tcp^)

    var client_ready = client_handshake.advance()
    var server_ready = server_handshake.advance()
    var poller = Poller()
    if not client_ready:
        poller.register(
            client_handshake.descriptor(),
            readable=client_handshake.wants_read(),
            writable=client_handshake.wants_write(),
        )
    if not server_ready:
        poller.register(
            server_handshake.descriptor(),
            readable=server_handshake.wants_read(),
            writable=server_handshake.wants_write(),
        )

    var waits = 0
    while not client_ready or not server_ready:
        waits += 1
        if waits > 100:
            raise Error("TLS handshake exceeded the event-loop bound")
        var events = poller.wait(5000)
        if len(events) == 0:
            raise Error("TLS handshake timed out")
        for event in events:
            if event.error or event.hangup:
                raise Error("TLS peer closed during the handshake")
            if (
                not client_ready
                and event.fd == client_handshake.descriptor()
                and (
                    (event.readable and client_handshake.wants_read())
                    or (event.writable and client_handshake.wants_write())
                )
            ):
                client_ready = client_handshake.advance()
                if client_ready:
                    poller.unregister(client_handshake.descriptor())
                else:
                    # TLS can switch direction between handshake steps.
                    poller.modify(
                        client_handshake.descriptor(),
                        readable=client_handshake.wants_read(),
                        writable=client_handshake.wants_write(),
                    )
            if (
                not server_ready
                and event.fd == server_handshake.descriptor()
                and (
                    (event.readable and server_handshake.wants_read())
                    or (event.writable and server_handshake.wants_write())
                )
            ):
                server_ready = server_handshake.advance()
                if server_ready:
                    poller.unregister(server_handshake.descriptor())
                else:
                    poller.modify(
                        server_handshake.descriptor(),
                        readable=server_handshake.wants_read(),
                        writable=server_handshake.wants_write(),
                    )

    var client = client_handshake^.finish()
    var server = server_handshake^.finish()
    if client.negotiated_alpn() != "h2" or server.negotiated_alpn() != "h2":
        raise Error("TLS endpoints did not negotiate h2")

    var payload = List[Byte](capacity=PAYLOAD_SIZE)
    for index in range(PAYLOAD_SIZE):
        payload.append(payload_byte(index))

    var sent = 0
    var request_writes = 0
    var received_by_server = List[Byte](capacity=PAYLOAD_SIZE)
    poller.register(client.descriptor(), readable=False, writable=True)
    poller.register(server.descriptor(), readable=True, writable=False)
    while len(received_by_server) < PAYLOAD_SIZE:
        var events = poller.wait(5000)
        if len(events) == 0:
            raise Error("TLS request transfer timed out")
        for event in events:
            if event.error or event.hangup:
                raise Error("TLS peer closed during the request transfer")
            if event.fd == client.descriptor() and sent < PAYLOAD_SIZE:
                try:
                    var n = client.write_some(Span(payload)[sent:PAYLOAD_SIZE])
                    if n <= 0:
                        raise Error("TLS write made no progress")
                    sent += n
                    request_writes += 1
                    if sent == PAYLOAD_SIZE:
                        poller.unregister(client.descriptor())
                    else:
                        poller.modify(
                            client.descriptor(), readable=False, writable=True
                        )
                except error:
                    if not is_would_block(error):
                        raise error
                    # Retry the same remaining plaintext after the direction
                    # requested by libssl becomes ready.
                    poller.modify(
                        client.descriptor(),
                        readable=client.wants_read(),
                        writable=client.wants_write(),
                    )
            if (
                event.fd == server.descriptor()
                and len(received_by_server) < PAYLOAD_SIZE
            ):
                var chunk = List[Byte](
                    length=min(16384, PAYLOAD_SIZE - len(received_by_server)),
                    fill=0,
                )
                try:
                    var n = server.read(chunk)
                    if n == 0:
                        raise Error(
                            "TLS client closed before sending its request"
                        )
                    received_by_server.extend(Span(chunk))
                    if len(received_by_server) == PAYLOAD_SIZE:
                        poller.unregister(server.descriptor())
                    else:
                        poller.modify(
                            server.descriptor(), readable=True, writable=False
                        )
                except error:
                    if not is_would_block(error):
                        raise error
                    poller.modify(
                        server.descriptor(),
                        readable=server.wants_read(),
                        writable=server.wants_write(),
                    )

    if request_writes <= 1:
        raise Error("TLS request did not expose partial write progress")

    var echoed = 0
    var echo_writes = 0
    var received_by_client = 0
    poller.register(server.descriptor(), readable=False, writable=True)
    poller.register(client.descriptor(), readable=True, writable=False)
    while received_by_client < PAYLOAD_SIZE:
        var events = poller.wait(5000)
        if len(events) == 0:
            raise Error("TLS echo transfer timed out")
        for event in events:
            if event.error or event.hangup:
                raise Error("TLS peer closed during the echo transfer")
            if event.fd == server.descriptor() and echoed < PAYLOAD_SIZE:
                try:
                    var n = server.write_some(
                        Span(received_by_server)[echoed:PAYLOAD_SIZE]
                    )
                    if n <= 0:
                        raise Error("TLS echo write made no progress")
                    echoed += n
                    echo_writes += 1
                    if echoed == PAYLOAD_SIZE:
                        poller.unregister(server.descriptor())
                    else:
                        poller.modify(
                            server.descriptor(), readable=False, writable=True
                        )
                except error:
                    if not is_would_block(error):
                        raise error
                    poller.modify(
                        server.descriptor(),
                        readable=server.wants_read(),
                        writable=server.wants_write(),
                    )
            if (
                event.fd == client.descriptor()
                and received_by_client < PAYLOAD_SIZE
            ):
                var chunk = List[Byte](
                    length=min(16384, PAYLOAD_SIZE - received_by_client),
                    fill=0,
                )
                try:
                    var n = client.read(chunk)
                    if n == 0:
                        raise Error(
                            "TLS server closed before completing the echo"
                        )
                    for index in range(n):
                        if chunk[index] != payload_byte(
                            received_by_client + index
                        ):
                            raise Error("TLS echo payload mismatch")
                    received_by_client += n
                    if received_by_client == PAYLOAD_SIZE:
                        poller.unregister(client.descriptor())
                    else:
                        poller.modify(
                            client.descriptor(), readable=True, writable=False
                        )
                except error:
                    if not is_would_block(error):
                        raise error
                    poller.modify(
                        client.descriptor(),
                        readable=client.wants_read(),
                        writable=client.wants_write(),
                    )

    if echo_writes <= 1:
        raise Error("TLS echo did not expose partial write progress")

    print(
        "verified ",
        client.version(),
        " h2 echo: ",
        received_by_client,
        " bytes in ",
        request_writes,
        "+",
        echo_writes,
        " partial writes",
        sep="",
    )
    poller.close()
    client.close()
    server.close()
