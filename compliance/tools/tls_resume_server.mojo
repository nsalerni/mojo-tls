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
    # One request/response, then close. CPython's SSLSocket.close() often
    # drops the TCP connection without close_notify; a read-until-EOF loop
    # would raise unexpected-eof and skip the second accept.
    var got = stream.read_exact(4)
    stream.write_all(Span(got))
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
