# Compliance tool: classify a TLS peer shutdown.
# Usage: tls_shutdown_client <port> <ca_pem>
# Reads the four-byte payload, then prints EOF for close_notify or ERROR for
# a transport close that truncates the TLS session.

from std.sys import argv

from net import TCPStream
from tls import TLSContext


def main() raises:
    var args = argv()
    if len(args) != 3:
        raise Error("usage: tls_shutdown_client <port> <ca_pem>")

    var ctx = TLSContext.client(ca_file=String(args[2]))
    var tcp = TCPStream.connect("127.0.0.1", UInt16(Int(args[1])))
    var stream = ctx.connect(tcp^, "localhost")
    if String(from_utf8=stream.read_exact(4)) != "done":
        raise Error("shutdown probe payload mismatch")

    var probe = List[Byte](length=1, fill=0)
    try:
        var count = stream.read(probe)
        if count == 0:
            print("EOF")
        else:
            print("DATA ", count, sep="")
    except error:
        print("ERROR ", String(error), sep="")
    stream.close()
