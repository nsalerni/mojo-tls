# Compliance tool: TLS probe client.
# Usage: tls_probe_client <port> <sni> <ca_pem|-> <alpn_csv|-> <nbytes>
# Connects, handshakes, prints "VERSION <v>" and "ALPN <p>", echoes nbytes
# of patterned data, verifies the echo, prints "OK <n>". A failed
# handshake exits non-zero with the error on stderr.

from std.sys import argv

from net import TCPStream
from tls import TLSContext


def main() raises:
    var args = argv()
    var port = UInt16(Int(args[1]))
    var sni = String(args[2])
    var ca = String(args[3])
    var alpn_csv = String(args[4])
    var n = Int(args[5])

    var alpn = List[String]()
    if alpn_csv != "-":
        for part in alpn_csv.split(","):
            alpn.append(String(part))
    var ctx: TLSContext
    if ca == "-":
        ctx = TLSContext.client(verify=False, alpn=alpn)
    else:
        ctx = TLSContext.client(ca_file=ca, alpn=alpn)

    var tcp = TCPStream.connect("127.0.0.1", port)
    var stream = ctx.connect(tcp^, sni)
    print("VERSION ", stream.version(), sep="")
    print("ALPN ", stream.negotiated_alpn(), sep="")

    var chunk_size = 16384
    var sent = 0
    var pattern = List[Byte](capacity=chunk_size)
    for i in range(chunk_size):
        pattern.append(UInt8((i * 11 + 3) % 256))
    while sent < n:
        var take = min(chunk_size, n - sent)
        stream.write_all(Span(pattern)[0:take])
        var got = stream.read_exact(take)
        for i in range(take):
            if got[i] != pattern[i]:
                raise Error("byte mismatch at " + String(sent + i))
        sent += take
    print("OK ", sent, sep="")
    stream.close()
