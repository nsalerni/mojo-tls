from std.ffi import c_int, external_call
from std.sys import argv
from std.testing import assert_equal, assert_true

from net import TCPListener, TCPStream
from tls import TLSContext


def run_server(
    cert: String, key: String, client_ca: String
) raises -> Tuple[UInt16, c_int]:
    var listener = TCPListener("127.0.0.1", 0)
    var port = listener.local_port
    var pid = external_call["fork", c_int]()
    if pid == 0:
        try:
            var context = TLSContext.server(
                cert,
                key,
                client_ca_file=client_ca,
                require_client_cert=True,
                alpn=["h2"],
            )
            var tcp = listener.accept()
            var stream = context.accept(tcp^)
            var request = stream.read_exact(4)
            stream.write_all(Span(request))
            stream.close()
        except:
            external_call["_exit", NoneType](c_int(1))
        external_call["_exit", NoneType](c_int(0))
    listener.close()
    return (port, pid)


def main() raises:
    var args = argv()
    assert_equal(
        len(args),
        6,
        "expected CA, server identity, and client identity paths",
    )

    var server = run_server(
        String(args[2]), String(args[3]), String(args[1])
    )
    var context = TLSContext.client(
        ca_file=String(args[1]),
        cert_chain_pem=String(args[4]),
        key_pem=String(args[5]),
        alpn=["h2"],
    )
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    var stream = context.connect(tcp^, "localhost")

    assert_true(stream.version().startswith("TLSv1."), stream.version())
    assert_equal(stream.negotiated_alpn(), "h2")
    stream.write_all("ping".as_bytes())
    assert_equal(String(from_utf8=stream.read_exact(4)), "ping")
    stream.close()

    var status = c_int(0)
    var waited = external_call["waitpid", c_int](
        server[1], Pointer(to=status), c_int(0)
    )
    assert_equal(waited, server[1], "waitpid failed")
    assert_equal(status, 0, "TLS server failed")
    print("installed mojo-tls package handshake passed")
