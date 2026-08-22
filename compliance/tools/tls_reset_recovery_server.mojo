# Compliance tool: rejected TLS peers must not terminate the server.

from std.sys import argv

from net import TCPListener
from tls import TLSContext


def main() raises:
    var args = argv()
    var ctx = TLSContext.server(String(args[1]), String(args[2]), alpn=["h2"])
    var tls_listener = TCPListener("127.0.0.1", 0)
    var gate_listener = TCPListener("127.0.0.1", 0)
    print("PORTS ", tls_listener.local_port, " ", gate_listener.local_port, sep="")

    for attempt in range(8):
        var rejected_tcp = tls_listener.accept()

        # The separate gate lets the peer send its ClientHello and reset the
        # connection before libssl tries to return the fatal ALPN alert.
        var gate = gate_listener.accept()
        _ = gate.read_exact(1)
        gate.close()

        var rejected = False
        try:
            var unexpected = ctx.accept(rejected_tcp^)
            unexpected.close()
        except:
            rejected = True
        if not rejected:
            raise Error("non-overlapping ALPN handshake succeeded")
        print("REJECTED ", attempt, sep="")

    var healthy_tcp = tls_listener.accept()
    var healthy = ctx.accept(healthy_tcp^)
    if healthy.negotiated_alpn() != "h2":
        raise Error("healthy TLS session did not negotiate h2")
    var payload = healthy.read_exact(4)
    healthy.write_all(Span(payload))
    healthy.close()
    tls_listener.close()
    gate_listener.close()
    print("OK")
