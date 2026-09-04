# ===----------------------------------------------------------------------=== #
# Copyright (c) 2026 the grpc-mojo contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ===----------------------------------------------------------------------=== #

"""TLS streams over libssl, loaded through the mojo-tls C shim.

`TLSContext` holds configuration (role, trust, certificates, ALPN) and
wraps connected `TCPStream`s into `TLSStream`s via `connect()` (client,
with SNI and hostname verification) or `accept()` (server). `TLSStream`
conforms to mojo-net's `IOStream`, so anything written against that trait
(mojo-http2's connection, gRPC above it) runs over TLS unchanged.

The shim (`shim/mojotls_shim.c`, built by `tools/build_shim.sh`) exists
because OpenSSL's server-side ALPN selection requires a C callback; it
also flattens the libssl surface into plain functions resolved with
`dlopen`. The library is located via `$MOJO_TLS_SHIM`, then the package's
`build/` directory, then `$CONDA_PREFIX/lib`.

Blocking helpers remain available. A non-blocking TCP stream can instead be
driven through `TLSHandshake.advance()` and `TLSStream` partial I/O using a
mojo-net `Poller`. OpenSSL's WANT_READ and WANT_WRITE states are preserved so
the caller always watches the direction the TLS state machine actually needs.
"""

from std.ffi import OwnedDLHandle, c_int
from std.os import getenv
from std.pathlib import Path
from std.sys import CompilationTarget

from net import ReadinessStream, TCPStream, WOULD_BLOCK_ERROR, is_timeout_error
from net.libc import os_error


comptime _WANT_READ = -2
comptime _WANT_WRITE = -3
comptime _SYSCALL_ERROR = -5
comptime _MAX_PEER_CERT_DER = 1024 * 1024
comptime _MAX_PEER_NAME = 4096
comptime _MAX_PEER_SAN_COUNT = 256
comptime _MAX_PEER_SAN_BYTES = 64 * 1024
comptime _MAX_PEER_SAN_VALUE = 4096
comptime _MAX_SESSION_DER = 16 * 1024


def _shim_filename() -> String:
    comptime if CompilationTarget.is_macos():
        return "libmojotls.dylib"
    else:
        return "libmojotls.so"


def _shim_path() raises -> String:
    """Locates the compiled shim library.

    Returns:
        The first existing candidate path.

    Raises:
        If the shim cannot be found (build it with
        `pixi run build-shim`).
    """
    var name = _shim_filename()
    var candidates = List[String]()
    var env = getenv("MOJO_TLS_SHIM")
    if env != "":
        candidates.append(env)
    candidates.append(String("build/") + name)
    var prefix = getenv("CONDA_PREFIX")
    if prefix != "":
        candidates.append(prefix + "/lib/" + name)
    for c in candidates:
        if Path(c).exists():
            return c.copy()
    raise Error(
        "tls: shim library not found; run `pixi run build-shim` or set"
        " MOJO_TLS_SHIM"
    )


def _shim_error(lib: OwnedDLHandle, var context: String) -> Error:
    # Pull the most recent entry off the libssl error queue for context.
    var buf = List[Byte]()
    buf.resize(256, 0)
    try:
        var n = lib.get_function[c_int]("mts_last_error")(
            buf.unsafe_ptr(), c_int(256)
        )
        if Int(n) > 0:
            buf.shrink(Int(n))
            return Error(context + ": " + String(from_utf8=buf))
    except:
        pass
    return Error(context^)


def _alpn_wire(protocols: List[String]) raises -> List[Byte]:
    # RFC 7301 wire format: length-prefixed protocol names.
    var out = List[Byte]()
    for p in protocols:
        var bytes = p.as_bytes()
        if len(bytes) == 0 or len(bytes) > 255:
            raise Error("tls: invalid ALPN protocol name")
        out.append(UInt8(len(bytes)))
        out.extend(bytes)
    return out^


@fieldwise_init
struct SubjectAlternativeNames(Copyable, Movable):
    """Owned subject alternative names from a peer leaf certificate.

    OpenSSL preserves certificate order within each list. Unsupported
    GeneralName choices, such as otherName and directoryName, are omitted.
    """

    var dns_names: List[String]
    """DNS names."""
    var uri_names: List[String]
    """Uniform resource identifiers."""
    var email_addresses: List[String]
    """RFC 822 email addresses."""
    var ip_addresses: List[String]
    """IPv4 and IPv6 addresses in canonical text form."""


@fieldwise_init
struct PeerCertificate(Copyable, Movable):
    """An owned snapshot of the peer's leaf certificate.

    The DER bytes, matched name, and subject alternative names are copied out
    of libssl. They remain valid after the TLS stream closes. Certificate
    presence alone does not establish trust, so authorization code must check
    `verified`.
    """

    var leaf_der: List[Byte]
    """The peer leaf certificate in DER form, excluding its chain."""
    var verified: Bool
    """Whether this session required peer verification and it succeeded."""
    var matched_name: String
    """The certificate name matched by hostname verification, if any."""
    var subject_alt_names: SubjectAlternativeNames
    """Typed names copied from the subjectAltName extension."""

    def __init__(
        out self,
        var leaf_der: List[Byte],
        verified: Bool,
        var matched_name: String,
    ):
        """Builds a snapshot without parsed subject alternative names.

        This initializer preserves the original three-argument API. New
        snapshots returned by `TLSStream` populate `subject_alt_names`.

        Args:
            leaf_der: Peer leaf certificate in DER form.
            verified: Whether required peer verification succeeded.
            matched_name: Name matched by hostname verification, if any.
        """
        self.leaf_der = leaf_der^
        self.verified = verified
        self.matched_name = matched_name^
        self.subject_alt_names = SubjectAlternativeNames(
            dns_names=List[String](),
            uri_names=List[String](),
            email_addresses=List[String](),
            ip_addresses=List[String](),
        )


@fieldwise_init
struct TLSSession(Copyable, Movable):
    """Opaque TLS session ticket bytes for handshake resumption.

    Obtained from `TLSStream.session()` after a completed handshake and
    some application I/O (TLS 1.3 tickets arrive post-handshake). Pass
    the same value to `TLSContext.connect` / `start_connect`. A ticket
    resumes the handshake only; it never sends 0-RTT application data.
    """

    var ticket: List[Byte]
    """DER-coded `SSL_SESSION` bytes from OpenSSL."""


@fieldwise_init
struct TLSContext(Movable):
    """TLS configuration: role, trust anchors, certificates, and ALPN.

    Build one per client or server, then wrap connected TCP streams with
    `connect()` / `accept()`. TLS 1.2 is the floor on both roles. Client
    `connect` accepts an optional `TLSSession` ticket to resume; early
    data is never sent.
    """

    var _lib: OwnedDLHandle
    var _ctx: UInt64
    var _is_server: Bool

    @staticmethod
    def client(
        *,
        verify: Bool = True,
        ca_file: StringSpan = "",
        cert_chain_pem: StringSpan = "",
        key_pem: StringSpan = "",
        alpn: List[String] = List[String](),
    ) raises -> TLSContext:
        """Builds a client-side context.

        Args:
            verify: Verify the server certificate chain (and, when SNI is
                given to `connect`, the hostname). Disable only in tests.
            ca_file: Path to a PEM bundle of trust anchors; empty uses the
                environment's default trust store.
            cert_chain_pem: Path to the client certificate chain presented
                when the server requests one. Must be paired with `key_pem`.
            key_pem: Path to the unencrypted private key for `cert_chain_pem`.
                Encrypted keys fail without prompting for a passphrase.
            alpn: Protocols to offer, most preferred first (e.g. "h2").

        Returns:
            The configured context.

        Raises:
            If the shim, trust store, identity, or ALPN configuration fails.
        """
        if (cert_chain_pem.byte_length() == 0) != (key_pem.byte_length() == 0):
            raise Error(
                "tls: client certificate and key must be provided together"
            )
        var lib = OwnedDLHandle(_shim_path())
        var ctx = lib.get_function[UInt64]("mts_ctx_new_client")()
        if ctx == 0:
            raise _shim_error(lib, "tls: context creation failed")
        var out = TLSContext(_lib=lib^, _ctx=ctx, _is_server=False)
        if verify:
            if ca_file.byte_length() != 0:
                var path = String(ca_file)
                var rc = out._lib.get_function[c_int]("mts_ctx_load_ca")(
                    out._ctx, path.as_c_string_slice()
                )
                if Int(rc) != 0:
                    raise _shim_error(out._lib, "tls: loading CA bundle")
            else:
                var rc = out._lib.get_function[c_int](
                    "mts_ctx_load_default_ca"
                )(out._ctx)
                if Int(rc) != 0:
                    raise _shim_error(out._lib, "tls: default trust store")
        out._lib.get_function[NoneType]("mts_ctx_set_verify")(
            out._ctx, c_int(1 if verify else 0)
        )
        if cert_chain_pem.byte_length() != 0:
            var cert = String(cert_chain_pem)
            var key = String(key_pem)
            var rc = out._lib.get_function[c_int]("mts_ctx_load_identity")(
                out._ctx,
                cert.as_c_string_slice(),
                key.as_c_string_slice(),
            )
            if Int(rc) != 0:
                raise _shim_error(
                    out._lib, "tls: loading client certificate/key"
                )
        out._set_alpn(alpn)
        return out^

    @staticmethod
    def server(
        cert_chain_pem: StringSpan,
        key_pem: StringSpan,
        *,
        client_ca_file: StringSpan = "",
        require_client_cert: Bool = False,
        alpn: List[String] = List[String](),
    ) raises -> TLSContext:
        """Builds a server-side context from a certificate chain and key.

        Args:
            cert_chain_pem: Path to the PEM certificate chain file.
            key_pem: Path to the PEM private key file.
            client_ca_file: PEM bundle of client trust anchors. Must be paired
                with `require_client_cert=True`.
            require_client_cert: Require and verify a client certificate
                against `client_ca_file`.
            alpn: Protocols to accept, most preferred first; a client
                offering no overlap is rejected with a fatal alert.

        Returns:
            The configured context.

        Raises:
            If the shim, identity, client CA, or ALPN configuration fails.
        """
        if require_client_cert != (client_ca_file.byte_length() != 0):
            raise Error(
                "tls: client CA and require_client_cert must be provided"
                " together"
            )
        var lib = OwnedDLHandle(_shim_path())
        var cert = String(cert_chain_pem)
        var key = String(key_pem)
        var ctx = lib.get_function[UInt64]("mts_ctx_new_server")(
            cert.as_c_string_slice(), key.as_c_string_slice()
        )
        if ctx == 0:
            raise _shim_error(lib, "tls: loading certificate/key")
        var out = TLSContext(_lib=lib^, _ctx=ctx, _is_server=True)
        if require_client_cert:
            var client_ca = String(client_ca_file)
            var rc = out._lib.get_function[c_int](
                "mts_ctx_require_client_cert"
            )(out._ctx, client_ca.as_c_string_slice())
            if Int(rc) != 0:
                raise _shim_error(out._lib, "tls: loading client CA")
        out._set_alpn(alpn)
        return out^

    def _set_alpn(self, protocols: List[String]) raises:
        if len(protocols) == 0:
            return
        var wire = _alpn_wire(protocols)
        var rc = self._lib.get_function[c_int]("mts_ctx_set_alpn")(
            self._ctx, wire.unsafe_ptr(), c_int(len(wire))
        )
        if Int(rc) != 0:
            raise _shim_error(self._lib, "tls: ALPN configuration")

    def connect(
        self,
        var tcp: TCPStream,
        sni: StringSpan,
        *,
        session: Optional[TLSSession] = None,
    ) raises -> TLSStream:
        """Runs the client handshake over a connected TCP stream.

        Args:
            tcp: The connected stream; ownership is taken.
            sni: Server name for SNI and hostname verification; empty
                skips both (the chain is still verified when the context
                verifies).
            session: Optional ticket from a previous `TLSStream.session()`.
                Resume skips the full certificate handshake. Early data
                is never sent.

        Returns:
            The established TLS stream.

        Raises:
            If the handshake fails, including a post-handshake alert that
            rejects the client certificate.
        """
        var handshake = self.start_connect(tcp^, sni, session=session)
        if not handshake.advance():
            raise Error("tls: blocking handshake requested socket readiness")
        return handshake^.finish()

    def start_connect(
        self,
        var tcp: TCPStream,
        sni: StringSpan,
        *,
        session: Optional[TLSSession] = None,
    ) raises -> TLSHandshake:
        """Starts a client handshake that may be advanced incrementally.

        The caller normally places `tcp` in non-blocking mode first. Call
        `advance()` until it completes, watching `descriptor()` for the
        direction reported by `wants_read()` or `wants_write()` between
        attempts.

        Args:
            tcp: The connected stream; ownership is taken.
            sni: Server name for SNI and hostname verification.
            session: Optional ticket from a previous `TLSStream.session()`.

        Returns:
            A client handshake that advances with socket readiness.

        Raises:
            If the TLS session or hostname configuration fails.
        """
        var lib = OwnedDLHandle(_shim_path())
        var ssl = lib.get_function[UInt64]("mts_ssl_new")(self._ctx, tcp.fd)
        if ssl == 0:
            raise _shim_error(lib, "tls: session creation")
        if session:
            var ticket = session.value().ticket.copy()
            if len(ticket) == 0 or len(ticket) > _MAX_SESSION_DER:
                lib.get_function[NoneType]("mts_ssl_free")(ssl)
                raise Error("tls: invalid session ticket")
            var session_rc = lib.get_function[c_int]("mts_ssl_set_session")(
                ssl, ticket.unsafe_ptr(), c_int(len(ticket))
            )
            if Int(session_rc) != 0:
                var err = _shim_error(lib, "tls: session resume")
                lib.get_function[NoneType]("mts_ssl_free")(ssl)
                raise err
        var host = String(sni)
        var rc = lib.get_function[c_int]("mts_ssl_set_connect_name")(
            ssl, host.as_c_string_slice()
        )
        if Int(rc) != 0:
            var err = _shim_error(lib, "tls: hostname configuration")
            lib.get_function[NoneType]("mts_ssl_free")(ssl)
            raise err
        return TLSHandshake(
            _lib=lib^,
            _ssl=ssl,
            _tcp=tcp^,
            _is_server=False,
            _complete=False,
            _open=True,
        )

    def accept(self, var tcp: TCPStream) raises -> TLSStream:
        """Runs the server handshake over an accepted TCP stream.

        Args:
            tcp: The accepted stream; ownership is taken.

        Returns:
            The established TLS stream.

        Raises:
            If the handshake fails (bad ClientHello, no ALPN overlap,
            protocol floor not met).
        """
        var handshake = self.start_accept(tcp^)
        if not handshake.advance():
            raise Error("tls: blocking handshake requested socket readiness")
        return handshake^.finish()

    def start_accept(self, var tcp: TCPStream) raises -> TLSHandshake:
        """Starts a server handshake that may be advanced incrementally.

        Args:
            tcp: The accepted stream; ownership is taken.

        Returns:
            A server handshake that advances with socket readiness.

        Raises:
            If the TLS session cannot be created.
        """
        var lib = OwnedDLHandle(_shim_path())
        var ssl = lib.get_function[UInt64]("mts_ssl_new")(self._ctx, tcp.fd)
        if ssl == 0:
            raise _shim_error(lib, "tls: session creation")
        return TLSHandshake(
            _lib=lib^,
            _ssl=ssl,
            _tcp=tcp^,
            _is_server=True,
            _complete=False,
            _open=True,
        )

    def __deinit__(deinit self):
        """Frees the underlying SSL context."""
        try:
            self._lib.get_function[NoneType]("mts_ctx_free")(self._ctx)
        except:
            pass


@fieldwise_init
struct TLSHandshake(Movable):
    """A client or server TLS handshake advanced by socket readiness.

    `advance()` performs one libssl handshake step. A false result is not a
    failure: inspect `wants_read()` and `wants_write()`, wait for that
    readiness on `descriptor()`, then call `advance()` again. Once complete,
    `finish()` consumes the handshake and returns an established `TLSStream`.
    """

    var _lib: OwnedDLHandle
    var _ssl: UInt64
    var _tcp: TCPStream
    var _is_server: Bool
    var _complete: Bool
    var _open: Bool

    def descriptor(self) -> c_int:
        """Returns the socket descriptor to register with `Poller`.

        Returns:
            The owned TCP descriptor.
        """
        return self._tcp.descriptor()

    def wants_read(self) raises -> Bool:
        """Reports whether the next handshake step needs readability.

        Returns:
            True after libssl reports WANT_READ.

        Raises:
            If the shim symbol cannot be resolved.
        """
        return Bool(
            self._lib.get_function[c_int]("mts_ssl_wants_read")(self._ssl)
        )

    def wants_write(self) raises -> Bool:
        """Reports whether the next handshake step needs writability.

        Returns:
            True after libssl reports WANT_WRITE.

        Raises:
            If the shim symbol cannot be resolved.
        """
        return Bool(
            self._lib.get_function[c_int]("mts_ssl_wants_write")(self._ssl)
        )

    def is_complete(self) -> Bool:
        """Reports whether the handshake has completed.

        Returns:
            True when `finish()` may be called.
        """
        return self._complete

    def advance(mut self) raises -> Bool:
        """Performs one handshake step without hiding readiness direction.

        Returns:
            True when the TLS handshake is complete, or false when the
            descriptor must first satisfy `wants_read()` or `wants_write()`.

        Raises:
            On certificate, protocol, or transport failure, including a
            post-handshake alert that rejects the client certificate.
        """
        if self._complete:
            return True
        var rc: c_int
        if self._is_server:
            rc = self._lib.get_function[c_int]("mts_ssl_accept")(self._ssl)
        else:
            rc = self._lib.get_function[c_int]("mts_ssl_connect")(self._ssl)
        if Int(rc) == 0:
            if not self._is_server:
                var confirm = self._lib.get_function[c_int](
                    "mts_ssl_confirm_connect"
                )(self._ssl)
                if Int(confirm) != 0:
                    if Int(confirm) == _SYSCALL_ERROR:
                        raise os_error("tls handshake")
                    raise _shim_error(self._lib, "tls: handshake failed")
            self._complete = True
            return True
        if Int(rc) == _WANT_READ:
            return False
        if Int(rc) == _WANT_WRITE:
            return False
        if Int(rc) == _SYSCALL_ERROR:
            raise os_error("tls handshake")
        raise _shim_error(self._lib, "tls: handshake failed")

    def finish(deinit self) raises -> TLSStream:
        """Consumes a completed handshake and returns its TLS stream.

        Returns:
            The established stream, retaining the TCP non-blocking mode.

        Raises:
            If the handshake has not completed.
        """
        if not self._complete:
            if self._open:
                self._lib.get_function[NoneType]("mts_ssl_free")(self._ssl)
                self._tcp.close()
            raise Error("tls: handshake is not complete")
        return TLSStream(
            _lib=self._lib^,
            _ssl=self._ssl,
            _tcp=self._tcp^,
            _open=True,
        )

    def __deinit__(deinit self):
        """Releases an abandoned in-progress handshake."""
        if self._open:
            try:
                self._lib.get_function[NoneType]("mts_ssl_free")(self._ssl)
            except:
                pass


@fieldwise_init
struct TLSStream(ReadinessStream):
    """An established TLS session over a TCP stream.

    Conforms to `ReadinessStream` as well as `IOStream`. On a non-blocking
    socket, `read()` and `write_some()` raise the standard typed would-block
    error when libssl needs readiness. Inspect `wants_read()` and
    `wants_write()` before updating the Poller interest because either TLS
    operation can require the opposite transport direction.
    """

    var _lib: OwnedDLHandle
    var _ssl: UInt64
    var _tcp: TCPStream
    var _open: Bool

    def _raise_io_state(self, rc: Int, var context: String) raises:
        if rc == _WANT_READ:
            if self._tcp.nonblocking:
                raise Error(WOULD_BLOCK_ERROR)
            raise os_error(context^)
        if rc == _WANT_WRITE:
            if self._tcp.nonblocking:
                raise Error(WOULD_BLOCK_ERROR)
            raise os_error(context^)
        if rc == _SYSCALL_ERROR:
            var err = os_error(context^)
            if self._tcp.nonblocking and is_timeout_error(err):
                raise Error(WOULD_BLOCK_ERROR)
            raise err
        context += " failed"
        raise _shim_error(self._lib, context^)

    def _read_some(self, mut buf: List[Byte]) raises -> Int:
        var n = self._lib.get_function[c_int]("mts_ssl_read")(
            self._ssl, buf.unsafe_ptr(), c_int(len(buf))
        )
        if Int(n) >= 0:
            return Int(n)
        self._raise_io_state(Int(n), "tls read")
        return 0

    def descriptor(self) -> c_int:
        """Returns the TCP descriptor carrying this TLS session.

        Returns:
            The descriptor to register with `Poller`.
        """
        return self._tcp.descriptor()

    def set_nonblocking(mut self, enabled: Bool) raises:
        """Switches the underlying TCP descriptor's blocking mode.

        Args:
            enabled: True for non-blocking mode, False for blocking mode.

        Raises:
            If the descriptor flags cannot be updated.
        """
        self._tcp.set_nonblocking(enabled)

    def wants_read(self) raises -> Bool:
        """Reports whether the blocked TLS operation needs readability.

        Returns:
            True after libssl reports WANT_READ.

        Raises:
            If the shim symbol cannot be resolved.
        """
        return Bool(
            self._lib.get_function[c_int]("mts_ssl_wants_read")(self._ssl)
        )

    def wants_write(self) raises -> Bool:
        """Reports whether the blocked TLS operation needs writability.

        Returns:
            True after libssl reports WANT_WRITE.

        Raises:
            If the shim symbol cannot be resolved.
        """
        return Bool(
            self._lib.get_function[c_int]("mts_ssl_wants_write")(self._ssl)
        )

    def read(self, mut buf: List[Byte]) raises -> Int:
        """Reads up to len(buf) bytes of plaintext.

        Args:
            buf: Buffer to read into; shrunk to the bytes actually read.

        Returns:
            The number of bytes read; 0 on a clean TLS close.

        Raises:
            On TLS or transport errors, including the typed timeout
            error when a read timeout on the underlying stream expires.
        """
        if len(buf) == 0:
            return 0
        var n = self._read_some(buf)
        buf.shrink(n)
        return n

    def read_exact(self, n: Int) raises -> List[Byte]:
        """Reads exactly n plaintext bytes, looping over short reads.

        Args:
            n: The exact number of bytes to read.

        Returns:
            A list of exactly n bytes.

        Raises:
            On a TLS close before n bytes arrive, on TLS or transport
            errors, or with the typed timeout error.
        """
        var out = List[Byte](capacity=n)
        while len(out) < n:
            var chunk = List[Byte]()
            chunk.resize(n - len(out), 0)
            var got = self._read_some(chunk)
            if got == 0:
                raise Error("connection closed mid-read (EOF)")
            out.extend(Span(chunk)[0:got])
        return out^

    def write_all(self, data: Span[Byte, _]) raises:
        """Writes the entire span as TLS records.

        Args:
            data: The plaintext bytes to send.

        Raises:
            On TLS or transport errors, including the typed timeout
            error when a write timeout on the underlying stream expires.
        """
        var sent = 0
        while sent < len(data):
            sent += self.write_some(data[sent : len(data)])

    def write_some(self, data: Span[Byte, _]) raises -> Int:
        """Performs one partial plaintext write through libssl.

        If this raises the typed would-block error, retry the same remaining
        plaintext after waiting for the direction reported by `wants_read()`
        or `wants_write()`.

        Args:
            data: Plaintext bytes to offer to libssl.

        Returns:
            Plaintext bytes accepted, or zero when data is empty.

        Raises:
            The typed would-block error with preserved TLS readiness state,
            or another TLS or transport error.
        """
        if len(data) == 0:
            return 0
        var n = self._lib.get_function[c_int]("mts_ssl_write")(
            self._ssl, data.unsafe_ptr(), c_int(len(data))
        )
        if Int(n) > 0:
            return Int(n)
        self._raise_io_state(Int(n), "tls write")
        return 0

    def set_read_timeout(self, nanos: Int64) raises:
        """Bounds blocking reads via the underlying stream's timeout.

        Args:
            nanos: Timeout in nanoseconds; 0 clears it.

        Raises:
            If the setsockopt call fails.
        """
        self._tcp.set_read_timeout(nanos)

    def set_write_timeout(self, nanos: Int64) raises:
        """Bounds blocking writes via the underlying stream's timeout.

        Args:
            nanos: Timeout in nanoseconds; 0 clears it.

        Raises:
            If the setsockopt call fails.
        """
        self._tcp.set_write_timeout(nanos)

    def set_nodelay(self, enabled: Bool) raises:
        """Applies the no-delay latency hint to the underlying stream.

        Args:
            enabled: True to send small writes immediately.

        Raises:
            If the setsockopt call fails.
        """
        self._tcp.set_nodelay(enabled)

    def negotiated_alpn(self) raises -> String:
        """Returns the ALPN protocol agreed during the handshake.

        Returns:
            The protocol name, or an empty string when none was
            negotiated.

        Raises:
            If the shim call fails.
        """
        var buf = List[Byte]()
        buf.resize(64, 0)
        var n = self._lib.get_function[c_int]("mts_ssl_get_alpn")(
            self._ssl, buf.unsafe_ptr(), c_int(64)
        )
        buf.shrink(Int(n))
        return String(from_utf8=buf)

    def version(self) raises -> String:
        """Returns the negotiated protocol version, e.g. "TLSv1.3".

        Returns:
            The version string.

        Raises:
            If the shim call fails.
        """
        var buf = List[Byte]()
        buf.resize(32, 0)
        var n = self._lib.get_function[c_int]("mts_ssl_version")(
            self._ssl, buf.unsafe_ptr(), c_int(32)
        )
        buf.shrink(Int(n))
        return String(from_utf8=buf)

    def session(self) raises -> Optional[TLSSession]:
        """Exports a resumable session ticket, if one is available.

        TLS 1.3 tickets are delivered after the handshake, so call this
        after some application I/O. Returns None when no resumable ticket
        exists yet. Early data is never enabled on the exported ticket.

        Returns:
            Opaque ticket bytes, or None.

        Raises:
            If the stream is closed or the ticket cannot be encoded.
        """
        if not self._open:
            raise Error("tls: session requested after close")
        var buf = List[Byte]()
        buf.resize(_MAX_SESSION_DER, 0)
        var n = self._lib.get_function[c_int]("mts_ssl_export_session")(
            self._ssl, buf.unsafe_ptr(), c_int(_MAX_SESSION_DER)
        )
        if Int(n) < 0:
            raise _shim_error(self._lib, "tls: exporting session")
        if Int(n) == 0:
            return None
        buf.shrink(Int(n))
        return TLSSession(ticket=buf^)

    def session_reused(self) raises -> Bool:
        """Reports whether this handshake resumed a previous ticket.

        Returns:
            True when OpenSSL reports `SSL_session_reused`.

        Raises:
            If the shim symbol cannot be resolved.
        """
        return Bool(
            self._lib.get_function[c_int]("mts_ssl_session_reused")(self._ssl)
        )

    def peer_certificate(self) raises -> Optional[PeerCertificate]:
        """Copies the peer's leaf certificate and verification status.

        Returns:
            An owned certificate snapshot, or None when the peer did not
            present a certificate. A server that does not request client
            authentication normally receives None.

        Raises:
            If the stream is closed, the certificate or its supported names
            exceed a bound, a supported name is malformed, or libssl cannot
            encode or copy the certificate.
        """
        if not self._open:
            raise Error("tls: peer certificate requested after close")

        var length = Int(
            self._lib.get_function[c_int]("mts_ssl_peer_certificate_der_size")(
                self._ssl
            )
        )
        if length == 0:
            return None
        if length == -2:
            raise Error("tls: peer certificate exceeds 1 MiB")
        if length < 0:
            raise _shim_error(self._lib, "tls: encoding peer certificate")

        var der = List[Byte](length=length, fill=0)
        var copied = Int(
            self._lib.get_function[c_int]("mts_ssl_peer_certificate_der")(
                self._ssl, der.unsafe_ptr(), c_int(length)
            )
        )
        if copied != length:
            raise _shim_error(self._lib, "tls: copying peer certificate")

        var verified_value = Int(
            self._lib.get_function[c_int]("mts_ssl_peer_certificate_verified")(
                self._ssl
            )
        )
        if verified_value != 0 and verified_value != 1:
            raise Error("tls: invalid peer verification result")

        var name_bytes = List[Byte](length=_MAX_PEER_NAME, fill=0)
        var name_length = Int(
            self._lib.get_function[c_int]("mts_ssl_peer_name")(
                self._ssl,
                name_bytes.unsafe_ptr(),
                c_int(_MAX_PEER_NAME),
            )
        )
        if name_length < 0 or name_length > _MAX_PEER_NAME:
            raise Error("tls: copying matched peer name")
        name_bytes.shrink(name_length)

        var san_bytes = List[Byte](length=_MAX_PEER_SAN_BYTES, fill=0)
        var san_length = Int(
            self._lib.get_function[c_int](
                "mts_ssl_peer_subject_alt_names"
            )(
                self._ssl,
                san_bytes.unsafe_ptr(),
                c_int(_MAX_PEER_SAN_BYTES),
            )
        )
        if san_length == -2:
            raise Error("tls: peer certificate has more than 256 names")
        if san_length == -3:
            raise Error("tls: peer certificate names exceed 64 KiB")
        if san_length == -4:
            raise Error("tls: malformed peer certificate name")
        if san_length < 0 or san_length > _MAX_PEER_SAN_BYTES:
            raise Error("tls: copying peer certificate names")
        san_bytes.shrink(san_length)

        var dns_names = List[String]()
        var uri_names = List[String]()
        var email_addresses = List[String]()
        var ip_addresses = List[String]()
        var offset = 0
        var san_count = 0
        while offset < san_length:
            if san_length - offset < 3:
                raise Error("tls: malformed peer certificate name copy")
            var kind = Int(san_bytes[offset])
            var value_length = (
                Int(san_bytes[offset + 1]) << 8
                | Int(san_bytes[offset + 2])
            )
            offset += 3
            if (
                value_length <= 0
                or value_length > _MAX_PEER_SAN_VALUE
                or value_length > san_length - offset
            ):
                raise Error("tls: malformed peer certificate name copy")
            san_count += 1
            if san_count > _MAX_PEER_SAN_COUNT:
                raise Error("tls: malformed peer certificate name count")
            var value = String(
                from_utf8=Span(san_bytes)[offset : offset + value_length]
            )
            offset += value_length
            if kind == 1:
                dns_names.append(value^)
            elif kind == 2:
                uri_names.append(value^)
            elif kind == 3:
                email_addresses.append(value^)
            elif kind == 4:
                ip_addresses.append(value^)
            else:
                raise Error("tls: malformed peer certificate name kind")

        return PeerCertificate(
            leaf_der=der^,
            verified=verified_value == 1,
            matched_name=String(from_utf8=name_bytes),
            subject_alt_names=SubjectAlternativeNames(
                dns_names=dns_names^,
                uri_names=uri_names^,
                email_addresses=email_addresses^,
                ip_addresses=ip_addresses^,
            ),
        )

    def close(mut self):
        """Sends close_notify and closes the underlying stream.

        Safe to call more than once.
        """
        if self._open:
            try:
                _ = self._lib.get_function[c_int]("mts_ssl_shutdown")(self._ssl)
                self._lib.get_function[NoneType]("mts_ssl_free")(self._ssl)
            except:
                pass
            self._open = False
        self._tcp.close()

    def __deinit__(deinit self):
        """Releases the TLS session if `close()` was never called."""
        if self._open:
            try:
                self._lib.get_function[NoneType]("mts_ssl_free")(self._ssl)
            except:
                pass
