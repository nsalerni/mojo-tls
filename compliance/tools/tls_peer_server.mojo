# Compliance tool that reports a copied peer certificate.
# Usage: tls_peer_server <cert_pem> <key_pem> <client_ca_pem|-> <expected_der_hex>

from std.sys import argv

from net import TCPListener
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
    for value in certificate.subject_alt_names.dns_names:
        print("SAN DNS ", value, sep="")
    for value in certificate.subject_alt_names.uri_names:
        print("SAN URI ", value, sep="")
    for value in certificate.subject_alt_names.email_addresses:
        print("SAN EMAIL ", value, sep="")
    for value in certificate.subject_alt_names.ip_addresses:
        print("SAN IP ", value, sep="")


def main() raises:
    var args = argv()
    if len(args) != 5:
        raise Error(
            "usage: tls_peer_server <cert> <key> <client_ca|->"
            " <expected_der_hex>"
        )

    var context: TLSContext
    if String(args[3]) == "-":
        context = TLSContext.server(
            String(args[1]), String(args[2]), alpn=["h2"]
        )
    else:
        context = TLSContext.server(
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
    var peer = stream.peer_certificate()
    var payload = stream.read_exact(16)
    stream.write_all(Span(payload))
    stream.close()
    listener.close()
    if not peer:
        print("PEER NONE")
        print("DONE")
        return
    var certificate = peer.value().copy()
    print_peer_certificate(certificate, String(args[4]))
    print("DONE")
