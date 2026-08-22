# Compliance tool: one fatal TLS session must not poison the next session.

from std.sys import argv

from net import Poller, TCPListener, is_would_block
from tls import TLSContext


def main() raises:
    var args = argv()
    var ctx = TLSContext.server(String(args[1]), String(args[2]), alpn=["h2"])
    var listener = TCPListener("127.0.0.1", 0)
    print("PORT ", listener.local_port, sep="")

    var failed_tcp = listener.accept()
    var failed = ctx.accept(failed_tcp^)
    print("FIRST_READY")
    var scratch = List[Byte](length=64, fill=0)
    var failed_as_expected = False
    try:
        _ = failed.read(scratch)
    except:
        failed_as_expected = True
    if not failed_as_expected:
        raise Error("malformed TLS record did not fail")
    failed.close()

    var healthy_tcp = listener.accept()
    healthy_tcp.set_nonblocking(True)
    var handshake = ctx.start_accept(healthy_tcp^)
    if handshake.advance():
        raise Error("TLS handshake completed before ClientHello")
    if not handshake.wants_read() or handshake.wants_write():
        raise Error("initial TLS handshake did not preserve WANT_READ")
    print("SECOND_READY")

    var poller = Poller()
    poller.register(
        handshake.descriptor(),
        readable=handshake.wants_read(),
        writable=handshake.wants_write(),
    )
    var steps = 0
    while not handshake.is_complete():
        steps += 1
        if steps >= 100:
            raise Error("TLS handshake did not converge")
        var events = poller.wait(10_000)
        if len(events) == 0:
            raise Error("TLS handshake timed out")
        for event in events:
            if event.fd != handshake.descriptor():
                continue
            if handshake.advance():
                break
            poller.modify(
                event.fd,
                readable=handshake.wants_read(),
                writable=handshake.wants_write(),
            )

    poller.unregister(handshake.descriptor())
    var healthy = handshake^.finish()
    if healthy.negotiated_alpn() != "h2":
        raise Error("healthy TLS session did not negotiate h2")

    var blocked = False
    try:
        _ = healthy.read(scratch)
    except error:
        if not is_would_block(error):
            raise error
        blocked = healthy.wants_read() and not healthy.wants_write()
    if not blocked:
        raise Error("healthy TLS session did not preserve WANT_READ")

    healthy.set_nonblocking(False)
    print("SEND")
    var payload = healthy.read_exact(4)
    healthy.write_all(Span(payload))
    healthy.close()
    listener.close()
    poller.close()
    print("OK")
