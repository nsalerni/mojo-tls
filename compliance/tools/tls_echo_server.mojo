# Compliance tool: TLS echo server (one connection).
# Usage: tls_echo_server <cert_pem> <key_pem> [alpn_csv]
# Prints "PORT <n>", accepts one TCP connection, runs the TLS handshake,
# echoes until clean TLS EOF, prints "DONE", exits. A failed handshake
# exits non-zero, which the rejection checks rely on.

from std.sys import argv

from net import TCPListener
from tls import TLSContext


def main() raises:
    var args = argv()
    var cert = String(args[1])
    var key = String(args[2])
    var alpn = List[String]()
    if len(args) > 3:
        for part in String(args[3]).split(","):
            alpn.append(String(part))

    var ctx = TLSContext.server(cert, key, alpn=alpn)
    var listener = TCPListener("127.0.0.1", 0)
    print("PORT ", listener.local_port, sep="")
    var tcp = listener.accept()
    var stream = ctx.accept(tcp^)
    while True:
        var buf = List[Byte]()
        buf.resize(65536, 0)
        var n = stream.read(buf)
        if n == 0:
            break
        stream.write_all(Span(buf))
    stream.close()
    listener.close()
    print("DONE")
