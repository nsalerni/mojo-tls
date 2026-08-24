# Readiness-driven TLS client against a CPython ssl peer.
# Usage: tls_nonblocking_client <port> <ca.pem> <bytes> [backpressure]
#        tls_nonblocking_client <port> <ca.pem> <bytes> <cert.pem> <key.pem>

from std.sys import argv

from net import Poller, TCPStream, is_would_block
from tls import TLSContext


def main() raises:
    var args = argv()
    if len(args) != 4 and len(args) != 5 and len(args) != 6:
        raise Error(
            "usage: tls_nonblocking_client <port> <ca> <bytes>"
            " [backpressure | <cert> <key>]"
        )
    var size = Int(args[3])
    var backpressure = len(args) == 5 and String(args[4]) == "backpressure"
    if len(args) == 5 and not backpressure:
        raise Error("the optional single argument must be 'backpressure'")
    var payload = List[Byte](capacity=size)
    for i in range(size):
        payload.append(UInt8((i * 17 + 11) % 256))

    var tcp = TCPStream.connect("127.0.0.1", UInt16(Int(args[1])))
    tcp.set_nonblocking(True)
    var ctx: TLSContext
    if len(args) == 6:
        ctx = TLSContext.client(
            ca_file=String(args[2]),
            cert_chain_pem=String(args[4]),
            key_pem=String(args[5]),
            alpn=["h2"],
        )
    else:
        ctx = TLSContext.client(ca_file=String(args[2]), alpn=["h2"])
    var handshake = ctx.start_connect(tcp^, "localhost")

    var handshake_read = 0
    var handshake_write = 0
    var complete = handshake.advance()
    if not complete:
        handshake_read += Int(handshake.wants_read())
        handshake_write += Int(handshake.wants_write())

    var poller = Poller()
    if not complete:
        poller.register(
            handshake.descriptor(),
            readable=handshake.wants_read(),
            writable=handshake.wants_write(),
        )
    var waits = 0
    while not complete:
        waits += 1
        if waits > 1000:
            raise Error("TLS handshake exceeded event-loop bound")
        var events = poller.wait(10000)
        if len(events) == 0:
            raise Error("TLS handshake timed out")
        for event in events:
            if (
                (handshake.wants_read() and event.readable)
                or (handshake.wants_write() and event.writable)
                or event.error
                or event.hangup
            ):
                complete = handshake.advance()
                if not complete:
                    handshake_read += Int(handshake.wants_read())
                    handshake_write += Int(handshake.wants_write())
                    poller.modify(
                        handshake.descriptor(),
                        readable=handshake.wants_read(),
                        writable=handshake.wants_write(),
                    )

    poller.unregister(handshake.descriptor())
    var stream = handshake^.finish()
    if stream.negotiated_alpn() != "h2":
        raise Error("TLS peer did not negotiate h2")
    if not stream.version().startswith("TLSv1."):
        raise Error("TLS peer negotiated an unexpected version")

    var sent = 0
    var received = 0
    var writes = 0
    var reads = 0
    var io_read = 0
    var io_write = 0
    if backpressure:
        while sent < size:
            try:
                var n = stream.write_some(Span(payload)[sent:size])
                if n <= 0:
                    raise Error("TLS partial write made no progress")
                sent += n
                writes += 1
            except error:
                if not is_would_block(error):
                    raise error
                if not stream.wants_write():
                    raise Error("TLS write blocked without WANT_WRITE")
                print(
                    "BLOCKED ",
                    sent,
                    " ",
                    writes,
                    " ",
                    handshake_read,
                    " ",
                    handshake_write,
                    sep="",
                )
                poller.close()
                stream.close()
                return
        raise Error("TLS write did not reach WANT_WRITE")

    poller.register(stream.descriptor(), readable=False, writable=True)
    waits = 0
    while sent < size:
        waits += 1
        if waits > 100000:
            raise Error("TLS write loop exceeded event bound")
        var events = poller.wait(10000)
        if len(events) == 0:
            raise Error("TLS write loop timed out")
        for event in events:
            if event.error or event.hangup:
                raise Error("TLS peer closed during write")
            if event.writable or event.readable:
                try:
                    var n = stream.write_some(Span(payload)[sent:size])
                    if n <= 0:
                        raise Error("TLS partial write made no progress")
                    sent += n
                    writes += 1
                    poller.modify(
                        stream.descriptor(), readable=False, writable=True
                    )
                except error:
                    if not is_would_block(error):
                        raise error
                    io_read += Int(stream.wants_read())
                    io_write += Int(stream.wants_write())
                    poller.modify(
                        stream.descriptor(),
                        readable=stream.wants_read(),
                        writable=stream.wants_write(),
                    )
    poller.modify(stream.descriptor(), readable=True, writable=False)

    while received < size:
        waits += 1
        if waits > 200000:
            raise Error("TLS read loop exceeded event bound")
        var events = poller.wait(10000)
        if len(events) == 0:
            raise Error("TLS read loop timed out")
        for event in events:
            if event.error:
                raise Error("TLS peer failed during read")
            if event.readable or event.writable or event.hangup:
                var buf = List[Byte](length=min(65536, size - received), fill=0)
                try:
                    var n = stream.read(buf)
                    if n == 0:
                        raise Error("TLS peer closed before echo completed")
                    for i in range(n):
                        if buf[i] != UInt8(((received + i) * 17 + 11) % 256):
                            raise Error("TLS echo payload mismatch")
                    received += n
                    reads += 1
                    poller.modify(
                        stream.descriptor(), readable=True, writable=False
                    )
                except error:
                    if not is_would_block(error):
                        raise error
                    io_read += Int(stream.wants_read())
                    io_write += Int(stream.wants_write())
                    poller.modify(
                        stream.descriptor(),
                        readable=stream.wants_read(),
                        writable=stream.wants_write(),
                    )

    print(
        "OK ",
        sent,
        " ",
        received,
        " ",
        writes,
        " ",
        reads,
        " ",
        handshake_read,
        " ",
        handshake_write,
        " ",
        io_read,
        " ",
        io_write,
        sep="",
    )
    poller.close()
    stream.close()
