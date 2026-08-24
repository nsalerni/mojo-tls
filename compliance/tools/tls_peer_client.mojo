# Compliance tool that reports a copied server certificate.
# Usage: tls_peer_client <port> <ca_pem|-> <server_name> <expected_der_hex>

from std.sys import argv

from net import TCPStream
from tls import PeerCertificate, TLSContext


def to_hex(data: Span[Byte, _]) -> String:
    comptime digits = "0123456789abcdef"
    var out = String()
    for byte in data:
        out += digits[byte = Int(byte >> 4) : Int(byte >> 4) + 1]
        out += digits[byte = Int(byte & 0xF) : Int(byte & 0xF) + 1]
    return out^


def print_peer_certificate(
    certificate: PeerCertificate, expected_der_hex: String
):
    var name = certificate.matched_name
    if name == "":
        name = "-"
    print(
        "PEER ",
        "VERIFIED" if certificate.verified else "UNVERIFIED",
        " ",
        name,
        " ",
        len(certificate.leaf_der),
        " ",
        "MATCH" if to_hex(Span(certificate.leaf_der))
        == expected_der_hex else "MISMATCH",
        sep="",
    )


def main() raises:
    var args = argv()
    if len(args) != 5:
        raise Error(
            "usage: tls_peer_client <port> <ca|-> <server_name>"
            " <expected_der_hex>"
        )

    var context: TLSContext
    if String(args[2]) == "-":
        context = TLSContext.client(verify=False, alpn=["h2"])
    else:
        context = TLSContext.client(ca_file=String(args[2]), alpn=["h2"])
    var tcp = TCPStream.connect("127.0.0.1", UInt16(Int(args[1])))
    var stream = context.connect(tcp^, String(args[3]))
    print("VERSION ", stream.version(), sep="")
    print("ALPN ", stream.negotiated_alpn(), sep="")
    var peer = stream.peer_certificate()

    var payload = List[Byte](length=16, fill=0x5A)
    stream.write_all(Span(payload))
    var echoed = stream.read_exact(16)
    if echoed != payload:
        raise Error("TLS peer identity echo mismatch")
    print("OK")
    stream.close()
    if not peer:
        print("PEER NONE")
        return
    var certificate = peer.value().copy()
    print_peer_certificate(certificate, String(args[4]))
