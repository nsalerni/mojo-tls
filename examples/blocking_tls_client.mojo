# ===----------------------------------------------------------------------=== #
# Copyright (c) 2026 the grpc-mojo contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ===----------------------------------------------------------------------=== #

"""Blocking TLS client with CA, hostname, and ALPN verification.

The companion Python runner starts a loopback TLS server with the generated
localhost certificate. This client trusts only the generated CA and passes
"localhost" to `connect()` for both SNI and certificate name verification.
"""

from std.sys import argv

from net import TCPStream
from tls import TLSContext


comptime ALPN = "mojo-tls-echo/1"
comptime REQUEST = "mojo-tls blocking client\n"
comptime RESPONSE = "python ssl server reply\n"


def main() raises:
    var args = argv()
    if len(args) != 3:
        raise Error("usage: blocking_tls_client <port> <ca-pem>")

    var context = TLSContext.client(
        ca_file=String(args[2]), alpn=[String(ALPN)]
    )
    var tcp = TCPStream.connect("127.0.0.1", UInt16(Int(args[1])))
    # The socket deadlines survive the move into TLS. They bound the handshake
    # and the later request and response if a local peer stalls.
    tcp.set_read_timeout(10_000_000_000)
    tcp.set_write_timeout(10_000_000_000)
    var stream = context.connect(tcp^, "localhost")

    if stream.negotiated_alpn() != ALPN:
        raise Error("TLS server did not negotiate " + ALPN)
    var peer = stream.peer_certificate()
    if not peer:
        raise Error("TLS server did not provide a certificate")
    # Copy the snapshot before closing the stream. It owns the DER bytes and
    # typed names, so applications can keep it after the connection closes.
    var certificate = peer.value().copy()
    if not certificate.verified or certificate.matched_name != "localhost":
        raise Error("TLS server identity was not verified for localhost")

    stream.write_all(REQUEST.as_bytes())
    var response = String(from_utf8=stream.read_exact(RESPONSE.byte_length()))
    if response != RESPONSE:
        raise Error("TLS server returned an unexpected response")
    var version = stream.version()
    stream.close()

    if len(certificate.leaf_der) == 0:
        raise Error("owned certificate snapshot is empty")
    if (
        len(certificate.subject_alt_names.uri_names) != 1
        or certificate.subject_alt_names.uri_names[0]
        != "spiffe://example.test/server"
    ):
        raise Error("owned certificate URI is missing")
    print("verified localhost over ", version, " with ", ALPN, sep="")
