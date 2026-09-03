# Compliance tool: TLS resume server (two connections).
# Usage: tls_resume_server <cert_pem> <key_pem>
# Prints "PORT <n>", accepts two connections, echoes until each client
# closes, then prints "DONE".

from std.sys import argv

from net import TCPListener
from tls import TLSContext


def serve_one(mut ctx: TLSContext, mut listener: TCPListener) raises:
    var tcp = listener.accept()
    var stream = ctx.accept(tcp^)
    while True:
        var buf = List[Byte]()
        buf.resize(4096, 0)
        var n = stream.read(buf)
        if n == 0:
            break
        stream.write_all(Span(buf))
    stream.close()


def main() raises:
    var args = argv()
    var ctx = TLSContext.server(String(args[1]), String(args[2]), alpn=["h2"])
    var listener = TCPListener("127.0.0.1", 0)
    print("PORT ", listener.local_port, sep="")
    serve_one(ctx, listener)
    serve_one(ctx, listener)
    listener.close()
    print("DONE")
