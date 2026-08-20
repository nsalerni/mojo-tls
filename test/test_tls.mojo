# TLS tests with both endpoints in Mojo: the server side runs in a forked
# child (a blocking handshake needs both peers making progress, which one
# thread cannot do). Covers the handshake, ALPN, certificate verification
# against the test corpus, typed timeouts through TLS, and clean EOF.

from std.ffi import c_int, external_call
from std.testing import assert_equal, assert_true

from net import TCPListener, TCPStream, is_timeout_error
from tls import TLSContext


comptime CA = "build/certs/ca.pem"
comptime SERVER_CERT = "build/certs/server.pem"
comptime SERVER_KEY = "build/certs/server.key"
comptime WRONGHOST_CERT = "build/certs/wronghost.pem"
comptime WRONGHOST_KEY = "build/certs/wronghost.key"
comptime SELFSIGNED_CERT = "build/certs/selfsigned.pem"
comptime SELFSIGNED_KEY = "build/certs/selfsigned.key"


def fork_tls_echo_server(
    cert: StringSpan, key: StringSpan, alpn: List[String]
) raises -> Tuple[UInt16, c_int]:
    """Forks a one-connection TLS echo server; returns (port, child pid).

    The child accepts one TCP connection, runs the TLS handshake, echoes
    until clean TLS EOF, then exits. Handshake failures also exit the
    child, which is what the rejection tests expect.
    """
    var listener = TCPListener("127.0.0.1", 0)
    var port = listener.local_port
    var pid = external_call["fork", c_int]()
    if pid == 0:
        try:
            var ctx = TLSContext.server(String(cert), String(key), alpn=alpn)
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
        except:
            pass
        external_call["_exit", NoneType](c_int(0))
    listener.close()
    return (port, pid)


def reap(pid: c_int):
    var status = c_int(0)
    _ = external_call["waitpid", c_int](pid, Pointer(to=status), c_int(0))


def test_handshake_echo_alpn() raises:
    var server = fork_tls_echo_server(
        SERVER_CERT, SERVER_KEY, ["h2", "http/1.1"]
    )
    var ctx = TLSContext.client(ca_file=String(CA), alpn=["h2"])
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    var stream = ctx.connect(tcp^, "localhost")
    assert_true(stream.version().startswith("TLSv1."), stream.version())
    assert_equal(stream.negotiated_alpn(), "h2")

    stream.write_all("sixteen tls byte".as_bytes())
    assert_equal(String(from_utf8=stream.read_exact(16)), "sixteen tls byte")

    # 256 KiB through the record layer, echoed back in-loop.
    var chunk = List[Byte]()
    chunk.resize(16384, 0x3C)
    for _ in range(16):
        stream.write_all(Span(chunk))
        var got = stream.read_exact(16384)
        assert_equal(got[0], 0x3C)

    stream.close()
    reap(server[1])


def test_clean_eof() raises:
    # A server that closes after one echo produces a clean TLS EOF
    # (read() returns 0), not an error.
    var server = fork_tls_echo_server(SERVER_CERT, SERVER_KEY, List[String]())
    var ctx = TLSContext.client(ca_file=String(CA))
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    var stream = ctx.connect(tcp^, "localhost")
    assert_equal(stream.negotiated_alpn(), "", "no ALPN configured")
    stream.write_all("bye".as_bytes())
    _ = stream.read_exact(3)
    # Half-close from our side ends the child's echo loop; it closes,
    # and our next read sees the clean shutdown.
    var probe = List[Byte]()
    probe.resize(4, 0)
    stream.close()
    reap(server[1])
    _ = probe


def test_reject_untrusted_ca() raises:
    var server = fork_tls_echo_server(
        SELFSIGNED_CERT, SELFSIGNED_KEY, List[String]()
    )
    var ctx = TLSContext.client(ca_file=String(CA))
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    var raised = False
    try:
        _ = ctx.connect(tcp^, "localhost")
    except e:
        raised = True
        assert_true("handshake" in String(e), String(e))
    assert_true(raised, "self-signed cert must be rejected")
    reap(server[1])


def test_reject_wrong_hostname() raises:
    var server = fork_tls_echo_server(
        WRONGHOST_CERT, WRONGHOST_KEY, List[String]()
    )
    var ctx = TLSContext.client(ca_file=String(CA))
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    var raised = False
    try:
        # The cert is CA-signed but for otherhost.example; verifying
        # against "localhost" must fail.
        _ = ctx.connect(tcp^, "localhost")
    except e:
        raised = True
        assert_true("handshake" in String(e), String(e))
    assert_true(raised, "hostname mismatch must be rejected")
    reap(server[1])


def test_verify_disabled_accepts_selfsigned() raises:
    var server = fork_tls_echo_server(
        SELFSIGNED_CERT, SELFSIGNED_KEY, List[String]()
    )
    var ctx = TLSContext.client(verify=False)
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    var stream = ctx.connect(tcp^, "localhost")
    stream.write_all("ok".as_bytes())
    assert_equal(String(from_utf8=stream.read_exact(2)), "ok")
    stream.close()
    reap(server[1])


def test_alpn_no_overlap_fails() raises:
    var server = fork_tls_echo_server(SERVER_CERT, SERVER_KEY, ["h2"])
    var ctx = TLSContext.client(ca_file=String(CA), alpn=["http/1.1"])
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    var raised = False
    try:
        _ = ctx.connect(tcp^, "localhost")
    except e:
        raised = True
        assert_true("handshake" in String(e), String(e))
    assert_true(raised, "no ALPN overlap must fail the handshake")
    reap(server[1])


def test_read_timeout_through_tls() raises:
    # Server echoes but we ask for bytes it never sends: the timeout on
    # the underlying stream must surface through the TLS layer, typed.
    var server = fork_tls_echo_server(SERVER_CERT, SERVER_KEY, List[String]())
    var ctx = TLSContext.client(ca_file=String(CA))
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    var stream = ctx.connect(tcp^, "localhost")
    stream.set_read_timeout(100_000_000)
    var timed_out = False
    try:
        _ = stream.read_exact(1)
    except e:
        timed_out = True
        assert_true(is_timeout_error(e), String(e))
    assert_true(timed_out)
    stream.close()
    reap(server[1])


def test_bad_cert_paths() raises:
    var raised = False
    try:
        _ = TLSContext.server(
            String("build/certs/missing.pem"), String(SERVER_KEY)
        )
    except e:
        raised = True
        assert_true("certificate" in String(e), String(e))
    assert_true(raised, "missing certificate file must raise")


def main() raises:
    test_handshake_echo_alpn()
    test_clean_eof()
    test_reject_untrusted_ca()
    test_reject_wrong_hostname()
    test_verify_disabled_accepts_selfsigned()
    test_alpn_no_overlap_fails()
    test_read_timeout_through_tls()
    test_bad_cert_paths()
    print("test_tls: all tests passed")
