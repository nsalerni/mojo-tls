# TLS tests with both endpoints in Mojo. Blocking servers run in forked
# children, while the readiness test drives both endpoints on one Poller.
# Covers handshakes, ALPN, certificate verification, timeouts, partial I/O,
# typed WANT_READ and WANT_WRITE states, and clean EOF.

from std.ffi import c_int, external_call
from std.testing import assert_equal, assert_true

from net import (
    Poller,
    ReadinessStream,
    TCPListener,
    TCPStream,
    is_timeout_error,
    is_would_block,
)
from tls import PeerCertificate, TLSContext


comptime CA = "build/certs/ca.pem"
comptime SERVER_CERT = "build/certs/server.pem"
comptime SERVER_KEY = "build/certs/server.key"
comptime WRONGHOST_CERT = "build/certs/wronghost.pem"
comptime WRONGHOST_KEY = "build/certs/wronghost.key"
comptime SELFSIGNED_CERT = "build/certs/selfsigned.pem"
comptime SELFSIGNED_KEY = "build/certs/selfsigned.key"
comptime CLIENT_CERT = "build/certs/client-chain.pem"
comptime CLIENT_KEY = "build/certs/client.key"
comptime UNTRUSTED_CLIENT_CERT = "build/certs/untrusted_client.pem"
comptime UNTRUSTED_CLIENT_KEY = "build/certs/untrusted_client.key"
comptime CLIENT_ENCRYPTED_KEY = "build/certs/client-encrypted.key"
comptime MALFORMED_NUL_CERT = "build/certs/malformed_nul.pem"
comptime MALFORMED_NUL_KEY = "build/certs/malformed_nul.key"
comptime MALFORMED_LF_CERT = "build/certs/malformed_lf.pem"
comptime MALFORMED_LF_KEY = "build/certs/malformed_lf.key"
comptime MALFORMED_HIGH_CERT = "build/certs/malformed_high.pem"
comptime MALFORMED_HIGH_KEY = "build/certs/malformed_high.key"
comptime MALFORMED_IP_CERT = "build/certs/malformed_ip.pem"
comptime MALFORMED_IP_KEY = "build/certs/malformed_ip.key"
comptime OVERSIZED_SAN_VALUE_CERT = "build/certs/oversized_san_value.pem"
comptime OVERSIZED_SAN_VALUE_KEY = "build/certs/oversized_san_value.key"
comptime EMPTY_SAN_CERT = "build/certs/empty_san.pem"
comptime EMPTY_SAN_KEY = "build/certs/empty_san.key"
comptime TOO_MANY_SANS_CERT = "build/certs/too_many_sans.pem"
comptime TOO_MANY_SANS_KEY = "build/certs/too_many_sans.key"
comptime TOO_MANY_SAN_BYTES_CERT = "build/certs/too_many_san_bytes.pem"
comptime TOO_MANY_SAN_BYTES_KEY = "build/certs/too_many_san_bytes.key"


def fork_tls_echo_server(
    cert: StringSpan,
    key: StringSpan,
    alpn: List[String],
    client_ca: StringSpan = "",
    require_client_cert: Bool = False,
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
            var ctx = TLSContext.server(
                String(cert),
                String(key),
                client_ca_file=String(client_ca),
                require_client_cert=require_client_cert,
                alpn=alpn,
            )
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
    var peer = stream.peer_certificate()
    if not peer:
        raise Error("verified TLS client receives a server certificate")
    var certificate = peer.value().copy()
    assert_true(len(certificate.leaf_der) > 0)
    assert_true(certificate.verified)
    assert_equal(certificate.matched_name, "localhost")
    assert_equal(len(certificate.subject_alt_names.dns_names), 2)
    assert_equal(certificate.subject_alt_names.dns_names[0], "localhost")
    assert_equal(
        certificate.subject_alt_names.dns_names[1], "service.example.test"
    )
    assert_equal(len(certificate.subject_alt_names.uri_names), 1)
    assert_equal(
        certificate.subject_alt_names.uri_names[0],
        "spiffe://example.test/server",
    )
    assert_equal(len(certificate.subject_alt_names.email_addresses), 1)
    assert_equal(
        certificate.subject_alt_names.email_addresses[0],
        "server@example.test",
    )
    assert_equal(len(certificate.subject_alt_names.ip_addresses), 2)
    assert_equal(certificate.subject_alt_names.ip_addresses[0], "127.0.0.1")
    assert_equal(certificate.subject_alt_names.ip_addresses[1], "2001:db8::1")

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
    assert_true(
        len(certificate.leaf_der) > 0,
        "certificate snapshot remains owned after stream close",
    )
    assert_equal(
        certificate.subject_alt_names.uri_names[0],
        "spiffe://example.test/server",
        "certificate names remain owned after stream close",
    )
    var closed_raised = False
    try:
        _ = stream.peer_certificate()
    except error:
        closed_raised = True
        assert_true("after close" in String(error), String(error))
    assert_true(closed_raised, "closed stream rejects certificate access")
    reap(server[1])


def test_required_client_certificate() raises:
    var server = fork_tls_echo_server(
        SERVER_CERT,
        SERVER_KEY,
        ["h2"],
        client_ca=CA,
        require_client_cert=True,
    )
    var ctx = TLSContext.client(
        ca_file=String(CA),
        cert_chain_pem=String(CLIENT_CERT),
        key_pem=String(CLIENT_KEY),
        alpn=["h2"],
    )
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    var stream = ctx.connect(tcp^, "localhost")
    assert_equal(stream.negotiated_alpn(), "h2")
    stream.write_all("auth".as_bytes())
    assert_equal(String(from_utf8=stream.read_exact(4)), "auth")
    stream.close()
    reap(server[1])


def test_reject_untrusted_client_certificate() raises:
    var server = fork_tls_echo_server(
        SERVER_CERT,
        SERVER_KEY,
        ["h2"],
        client_ca=CA,
        require_client_cert=True,
    )
    var ctx = TLSContext.client(
        ca_file=String(CA),
        cert_chain_pem=String(UNTRUSTED_CLIENT_CERT),
        key_pem=String(UNTRUSTED_CLIENT_KEY),
        alpn=["h2"],
    )
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    var raised = False
    try:
        _ = ctx.connect(tcp^, "localhost")
    except e:
        raised = True
        assert_true("handshake" in String(e), String(e))
    assert_true(raised, "untrusted client certificate must fail connect")
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


def test_ip_literal_hostname() raises:
    var server = fork_tls_echo_server(SERVER_CERT, SERVER_KEY, ["h2"])
    var ctx = TLSContext.client(ca_file=String(CA), alpn=["h2"])
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    var stream = ctx.connect(tcp^, "127.0.0.1")
    var peer = stream.peer_certificate()
    if not peer:
        raise Error("IP-literal TLS client receives a server certificate")
    var certificate = peer.value().copy()
    assert_true(certificate.verified)
    # IP identity uses X509_VERIFY_PARAM_set1_ip_asc; SSL_get0_peername
    # only reports DNS names set via SSL_set1_host.
    assert_equal(certificate.matched_name, "")
    assert_equal(certificate.subject_alt_names.ip_addresses[0], "127.0.0.1")
    stream.write_all("ip literal name".as_bytes())
    assert_equal(String(from_utf8=stream.read_exact(15)), "ip literal name")
    stream.close()
    reap(server[1])


def test_verify_disabled_accepts_selfsigned() raises:
    var server = fork_tls_echo_server(
        SELFSIGNED_CERT, SELFSIGNED_KEY, List[String]()
    )
    var ctx = TLSContext.client(verify=False)
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    var stream = ctx.connect(tcp^, "localhost")
    var peer = stream.peer_certificate()
    if not peer:
        raise Error("unverified TLS still exposes the presented certificate")
    assert_true(not peer.value().verified)
    assert_equal(peer.value().matched_name, "")
    stream.write_all("ok".as_bytes())
    assert_equal(String(from_utf8=stream.read_exact(2)), "ok")
    stream.close()
    reap(server[1])


def assert_peer_names_rejected(
    cert: StringSpan, key: StringSpan, expected_error: StringSpan
) raises:
    var server = fork_tls_echo_server(cert, key, List[String]())
    var ctx = TLSContext.client(verify=False)
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    var stream = ctx.connect(tcp^, "localhost")
    var raised = False
    try:
        _ = stream.peer_certificate()
    except error:
        raised = True
        assert_true(String(expected_error) in String(error), String(error))
    stream.close()
    reap(server[1])
    assert_true(raised, "unsafe certificate names must be rejected")


def test_reject_unsafe_subject_alt_names() raises:
    assert_peer_names_rejected(
        MALFORMED_NUL_CERT,
        MALFORMED_NUL_KEY,
        "malformed peer certificate name",
    )
    assert_peer_names_rejected(
        MALFORMED_LF_CERT,
        MALFORMED_LF_KEY,
        "malformed peer certificate name",
    )
    assert_peer_names_rejected(
        MALFORMED_HIGH_CERT,
        MALFORMED_HIGH_KEY,
        "malformed peer certificate name",
    )
    assert_peer_names_rejected(
        MALFORMED_IP_CERT,
        MALFORMED_IP_KEY,
        "malformed peer certificate name",
    )
    assert_peer_names_rejected(
        EMPTY_SAN_CERT,
        EMPTY_SAN_KEY,
        "malformed peer certificate name",
    )
    assert_peer_names_rejected(
        OVERSIZED_SAN_VALUE_CERT,
        OVERSIZED_SAN_VALUE_KEY,
        "malformed peer certificate name",
    )
    assert_peer_names_rejected(
        TOO_MANY_SANS_CERT,
        TOO_MANY_SANS_KEY,
        "more than 256 names",
    )
    assert_peer_names_rejected(
        TOO_MANY_SAN_BYTES_CERT,
        TOO_MANY_SAN_BYTES_KEY,
        "names exceed 64 KiB",
    )


def test_peer_certificate_compatibility_constructor() raises:
    var der = List[Byte](length=2, fill=0xA5)
    var certificate = PeerCertificate(der^, True, String("legacy.example"))
    assert_equal(len(certificate.leaf_der), 2)
    assert_true(certificate.verified)
    assert_equal(certificate.matched_name, "legacy.example")
    assert_equal(len(certificate.subject_alt_names.dns_names), 0)
    assert_equal(len(certificate.subject_alt_names.uri_names), 0)
    assert_equal(len(certificate.subject_alt_names.email_addresses), 0)
    assert_equal(len(certificate.subject_alt_names.ip_addresses), 0)


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


def accepts_readiness_stream[S: ReadinessStream](stream: S):
    """Compile-time proof that TLSStream satisfies the readiness trait."""
    _ = stream


def test_nonblocking_handshake_and_partial_io() raises:
    var listener = TCPListener("127.0.0.1", 0)
    var client_tcp = TCPStream.connect("127.0.0.1", listener.local_port)
    var server_tcp = listener.accept()
    listener.close()
    client_tcp.set_nonblocking(True)
    server_tcp.set_nonblocking(True)

    var client_ctx = TLSContext.client(ca_file=String(CA), alpn=["h2"])
    var server_ctx = TLSContext.server(
        String(SERVER_CERT), String(SERVER_KEY), alpn=["h2"]
    )
    var client_hs = client_ctx.start_connect(client_tcp^, "localhost")
    var server_hs = server_ctx.start_accept(server_tcp^)

    var client_done = client_hs.advance()
    var server_done = server_hs.advance()
    assert_true(
        client_done or client_hs.wants_read() or client_hs.wants_write()
    )
    assert_true(
        server_done or server_hs.wants_read() or server_hs.wants_write()
    )

    var poller = Poller()
    if not client_done:
        poller.register(
            client_hs.descriptor(),
            readable=client_hs.wants_read(),
            writable=client_hs.wants_write(),
        )
    if not server_done:
        poller.register(
            server_hs.descriptor(),
            readable=server_hs.wants_read(),
            writable=server_hs.wants_write(),
        )

    var steps = 0
    while not client_done or not server_done:
        steps += 1
        assert_true(steps < 100, "non-blocking handshake must converge")
        var events = poller.wait(2000)
        assert_true(len(events) > 0, "handshake descriptor becomes ready")
        for event in events:
            if not client_done and event.fd == client_hs.descriptor():
                if (
                    (client_hs.wants_read() and event.readable)
                    or (client_hs.wants_write() and event.writable)
                    or event.error
                    or event.hangup
                ):
                    client_done = client_hs.advance()
                    if client_done:
                        poller.unregister(client_hs.descriptor())
                    else:
                        poller.modify(
                            client_hs.descriptor(),
                            readable=client_hs.wants_read(),
                            writable=client_hs.wants_write(),
                        )
            if not server_done and event.fd == server_hs.descriptor():
                if (
                    (server_hs.wants_read() and event.readable)
                    or (server_hs.wants_write() and event.writable)
                    or event.error
                    or event.hangup
                ):
                    server_done = server_hs.advance()
                    if server_done:
                        poller.unregister(server_hs.descriptor())
                    else:
                        poller.modify(
                            server_hs.descriptor(),
                            readable=server_hs.wants_read(),
                            writable=server_hs.wants_write(),
                        )
    poller.close()

    var client = client_hs^.finish()
    var server = server_hs^.finish()
    accepts_readiness_stream(client)
    accepts_readiness_stream(server)
    assert_equal(client.negotiated_alpn(), "h2")
    assert_equal(server.negotiated_alpn(), "h2")
    var client_peer = client.peer_certificate()
    if not client_peer:
        raise Error("verified TLS client receives a server certificate")
    assert_true(client_peer.value().verified)
    assert_equal(client_peer.value().matched_name, "localhost")
    assert_true(
        not server.peer_certificate(),
        "server receives no certificate without client authentication",
    )

    var empty = List[Byte](length=1, fill=0)
    var blocked = False
    try:
        _ = server.read(empty)
    except error:
        blocked = True
        assert_true(is_would_block(error), String(error))
        assert_true(server.wants_read())
        assert_true(not server.wants_write())
    assert_true(blocked, "empty TLS read reports WANT_READ")

    var payload = List[Byte](length=8 * 1024 * 1024, fill=0x5A)
    var sent = 0
    var writes = 0
    blocked = False
    while sent < len(payload):
        try:
            var n = client.write_some(Span(payload)[sent : len(payload)])
            assert_true(n > 0)
            sent += n
            writes += 1
        except error:
            assert_true(is_would_block(error), String(error))
            assert_true(client.wants_write())
            assert_true(not client.wants_read())
            blocked = True
            break
    assert_true(writes > 1, "partial TLS writes expose bounded progress")
    assert_true(blocked, "stalled TLS peer produces WANT_WRITE")

    client.close()
    server.close()


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

    raised = False
    try:
        _ = TLSContext.server(
            String(SERVER_CERT),
            String(SERVER_KEY),
            client_ca_file=String(CA),
        )
    except e:
        raised = True
        assert_true("provided together" in String(e), String(e))
    assert_true(raised, "a client CA without the required flag must raise")

    raised = False
    try:
        _ = TLSContext.server(
            String(SERVER_CERT),
            String(SERVER_KEY),
            require_client_cert=True,
        )
    except e:
        raised = True
        assert_true("provided together" in String(e), String(e))
    assert_true(raised, "the required flag without a client CA must raise")

    raised = False
    try:
        _ = TLSContext.server(
            String(SERVER_CERT),
            String(SERVER_KEY),
            client_ca_file="build/certs/missing-ca.pem",
            require_client_cert=True,
        )
    except e:
        raised = True
        assert_true("loading client CA" in String(e), String(e))
    assert_true(raised, "a missing client CA file must raise")

    raised = False
    try:
        _ = TLSContext.client(
            verify=False, cert_chain_pem=String(CLIENT_CERT)
        )
    except e:
        raised = True
        assert_true("provided together" in String(e), String(e))
    assert_true(raised, "a client certificate without its key must raise")

    raised = False
    try:
        _ = TLSContext.client(verify=False, key_pem=String(CLIENT_KEY))
    except e:
        raised = True
        assert_true("provided together" in String(e), String(e))
    assert_true(raised, "a client key without its certificate must raise")

    raised = False
    try:
        _ = TLSContext.client(
            verify=False,
            cert_chain_pem=String(CLIENT_CERT),
            key_pem=String(SERVER_KEY),
        )
    except e:
        raised = True
        assert_true("client certificate" in String(e), String(e))
    assert_true(raised, "a mismatched client certificate and key must raise")

    raised = False
    try:
        _ = TLSContext.client(
            verify=False,
            cert_chain_pem=String(CLIENT_CERT),
            key_pem=String(CLIENT_ENCRYPTED_KEY),
        )
    except e:
        raised = True
        assert_true("client certificate" in String(e), String(e))
    assert_true(raised, "an encrypted client key must raise")

    raised = False
    try:
        _ = TLSContext.server(SERVER_CERT, CLIENT_ENCRYPTED_KEY)
    except e:
        raised = True
        assert_true("certificate/key" in String(e), String(e))
    assert_true(raised, "an encrypted server key must raise")


def test_client_identity_configuration() raises:
    _ = TLSContext.client(
        verify=False,
        cert_chain_pem=String(CLIENT_CERT),
        key_pem=String(CLIENT_KEY),
    )


def test_session_ticket_resume() raises:
    var listener = TCPListener("127.0.0.1", 0)
    var port = listener.local_port
    var pid = external_call["fork", c_int]()
    if pid == 0:
        try:
            var ctx = TLSContext.server(SERVER_CERT, SERVER_KEY, alpn=["h2"])
            var first_tcp = listener.accept()
            var first = ctx.accept(first_tcp^)
            var ping = first.read_exact(4)
            first.write_all(Span(ping))
            first.close()
            var second_tcp = listener.accept()
            var second = ctx.accept(second_tcp^)
            var pong = second.read_exact(4)
            second.write_all(Span(pong))
            second.close()
        except:
            pass
        external_call["_exit", NoneType](c_int(0))
    listener.close()

    var ctx = TLSContext.client(ca_file=String(CA), alpn=["h2"])
    var tcp = TCPStream.connect("127.0.0.1", port)
    var stream = ctx.connect(tcp^, "localhost")
    assert_true(not stream.session_reused(), "first handshake is full")
    stream.write_all("ping".as_bytes())
    assert_equal(String(from_utf8=stream.read_exact(4)), "ping")
    var ticket = stream.session()
    if not ticket:
        stream.close()
        reap(pid)
        raise Error("expected a resumable TLS 1.3 ticket after I/O")
    stream.close()

    var resume_tcp = TCPStream.connect("127.0.0.1", port)
    var resumed = ctx.connect(
        resume_tcp^, "localhost", session=ticket.value().copy()
    )
    assert_true(resumed.session_reused(), "second handshake resumes")
    resumed.write_all("pong".as_bytes())
    assert_equal(String(from_utf8=resumed.read_exact(4)), "pong")
    resumed.close()
    reap(pid)


def test_write_timeout_after_wrap() raises:
    var server = fork_tls_echo_server(SERVER_CERT, SERVER_KEY, ["h2"])
    var ctx = TLSContext.client(ca_file=String(CA), alpn=["h2"])
    var tcp = TCPStream.connect("127.0.0.1", server[0])
    var stream = ctx.connect(tcp^, "localhost")
    stream.set_write_timeout(1_000_000_000)
    stream.set_read_timeout(1_000_000_000)
    stream.write_all("ping".as_bytes())
    assert_equal(String(from_utf8=stream.read_exact(4)), "ping")
    stream.set_write_timeout(0)
    stream.close()
    reap(server[1])


def main() raises:
    test_handshake_echo_alpn()
    test_required_client_certificate()
    test_reject_untrusted_client_certificate()
    test_clean_eof()
    test_reject_untrusted_ca()
    test_reject_wrong_hostname()
    test_ip_literal_hostname()
    test_verify_disabled_accepts_selfsigned()
    test_reject_unsafe_subject_alt_names()
    test_peer_certificate_compatibility_constructor()
    test_alpn_no_overlap_fails()
    test_read_timeout_through_tls()
    test_nonblocking_handshake_and_partial_io()
    test_bad_cert_paths()
    test_client_identity_configuration()
    test_session_ticket_resume()
    test_write_timeout_after_wrap()
    print("test_tls: all tests passed")
