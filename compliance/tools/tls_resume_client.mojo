# Compliance tool: TLS resume client.
# Usage: tls_resume_client <port> <ca_pem>
# Connects twice. The second handshake uses the ticket from the first.
# Prints:
#   FIRST reused=<0|1> ticket=<n>
#   SECOND reused=<0|1>
# Exits non-zero if the second handshake did not resume.

from std.sys import argv

from net import TCPStream
from tls import TLSContext, TLSStream


def echo(mut stream: TLSStream, payload: StringSpan) raises:
    stream.write_all(payload.as_bytes())
    var got = stream.read_exact(payload.byte_length())
    if String(from_utf8=got) != String(payload):
        raise Error("echo mismatch")


def main() raises:
    var args = argv()
    if len(args) != 3:
        raise Error("usage: tls_resume_client <port> <ca_pem>")
    var port = UInt16(Int(args[1]))
    var ctx = TLSContext.client(ca_file=String(args[2]), alpn=["h2"])

    var first_tcp = TCPStream.connect("127.0.0.1", port)
    var first = ctx.connect(first_tcp^, "localhost")
    echo(first, "ping")
    var ticket = first.session()
    print(
        "FIRST reused=",
        1 if first.session_reused() else 0,
        " ticket=",
        len(ticket.value().ticket) if ticket else 0,
        sep="",
    )
    first.close()
    if not ticket:
        raise Error("no resumable ticket after first handshake")

    var second_tcp = TCPStream.connect("127.0.0.1", port)
    var second = ctx.connect(
        second_tcp^, "localhost", session=ticket.value().copy()
    )
    echo(second, "pong")
    print("SECOND reused=", 1 if second.session_reused() else 0, sep="")
    var reused = second.session_reused()
    second.close()
    if not reused:
        raise Error("second handshake did not resume")
