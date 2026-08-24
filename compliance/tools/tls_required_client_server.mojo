# Compliance tool: TLS echo server that requires a client certificate.
# Usage: tls_required_client_server <cert_pem> <key_pem> <client_ca_pem>
# Prints "PORT <n>", accepts one TLS client, echoes until clean TLS EOF,
# prints "DONE", and exits. Handshake rejection exits nonzero.

from std.sys import argv

from net import TCPListener
from tls import TLSContext


def main() raises:
    var args = argv()
    if len(args) != 4:
        raise Error(
            "usage: tls_required_client_server <cert> <key> <client_ca>"
        )
    var context = TLSContext.server(
        String(args[1]),
        String(args[2]),
        client_ca_file=String(args[3]),
        require_client_cert=True,
        alpn=["h2"],
    )
    var listener = TCPListener("127.0.0.1", 0)
    print("PORT ", listener.local_port, sep="")
    var tcp = listener.accept()
    var stream = context.accept(tcp^)
    while True:
        var buf = List[Byte](length=65536, fill=0)
        var n = stream.read(buf)
        if n == 0:
            break
        stream.write_all(Span(buf)[0:n])
    stream.close()
    listener.close()
    print("DONE")
