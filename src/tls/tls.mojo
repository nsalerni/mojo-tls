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

Blocking I/O only, matching the rest of the family: timeouts set on the
underlying TCP stream apply (an expired read timeout surfaces as the
typed timeout error), and a clean TLS close (close_notify) reads as EOF.
"""

from std.ffi import OwnedDLHandle, c_int
from std.os import getenv
from std.pathlib import Path
from std.sys import CompilationTarget

from net import IOStream, TCPStream
from net.libc import os_error


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
struct TLSContext(Movable):
    """TLS configuration: role, trust anchors, certificates, and ALPN.

    Build one per client or server, then wrap connected TCP streams with
    `connect()` / `accept()`. TLS 1.2 is the floor on both roles.
    """

    var _lib: OwnedDLHandle
    var _ctx: UInt64
    var _is_server: Bool

    @staticmethod
    def client(
        *,
        verify: Bool = True,
        ca_file: String = "",
        alpn: List[String] = List[String](),
    ) raises -> TLSContext:
        """Builds a client-side context.

        Args:
            verify: Verify the server certificate chain (and, when SNI is
                given to `connect`, the hostname). Disable only in tests.
            ca_file: PEM bundle of trust anchors; empty uses the
                environment's default trust store.
            alpn: Protocols to offer, most preferred first (e.g. "h2").

        Returns:
            The configured context.

        Raises:
            If the shim, trust store, or ALPN configuration fails.
        """
        var lib = OwnedDLHandle(_shim_path())
        var ctx = lib.get_function[UInt64]("mts_ctx_new_client")()
        if ctx == 0:
            raise _shim_error(lib, "tls: context creation failed")
        var out = TLSContext(_lib=lib^, _ctx=ctx, _is_server=False)
        if verify:
            if ca_file != "":
                var path = ca_file.copy()
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
        out._set_alpn(alpn)
        return out^

    @staticmethod
    def server(
        cert_chain_pem: String,
        key_pem: String,
        *,
        alpn: List[String] = List[String](),
    ) raises -> TLSContext:
        """Builds a server-side context from a certificate chain and key.

        Args:
            cert_chain_pem: Path to the PEM certificate chain file.
            key_pem: Path to the PEM private key file.
            alpn: Protocols to accept, most preferred first; a client
                offering no overlap is rejected with a fatal alert.

        Returns:
            The configured context.

        Raises:
            If the shim fails or the certificate/key cannot be loaded.
        """
        var lib = OwnedDLHandle(_shim_path())
        var cert = cert_chain_pem.copy()
        var key = key_pem.copy()
        var ctx = lib.get_function[UInt64]("mts_ctx_new_server")(
            cert.as_c_string_slice(), key.as_c_string_slice()
        )
        if ctx == 0:
            raise _shim_error(lib, "tls: loading certificate/key")
        var out = TLSContext(_lib=lib^, _ctx=ctx, _is_server=True)
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

    def connect(self, var tcp: TCPStream, sni: StringSpan) raises -> TLSStream:
        """Runs the client handshake over a connected TCP stream.

        Args:
            tcp: The connected stream; ownership is taken.
            sni: Server name for SNI and hostname verification; empty
                skips both (the chain is still verified when the context
                verifies).

        Returns:
            The established TLS stream.

        Raises:
            If the handshake fails, including certificate rejection.
        """
        var lib = OwnedDLHandle(_shim_path())
        var ssl = lib.get_function[UInt64]("mts_ssl_new")(self._ctx, tcp.fd)
        if ssl == 0:
            raise _shim_error(lib, "tls: session creation")
        var host = String(sni)
        var rc = lib.get_function[c_int]("mts_ssl_connect")(
            ssl, host.as_c_string_slice()
        )
        if Int(rc) != 0:
            var err = _shim_error(lib, "tls: handshake failed")
            lib.get_function[NoneType]("mts_ssl_free")(ssl)
            raise err
        return TLSStream(_lib=lib^, _ssl=ssl, _tcp=tcp^, _open=True)

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
        var lib = OwnedDLHandle(_shim_path())
        var ssl = lib.get_function[UInt64]("mts_ssl_new")(self._ctx, tcp.fd)
        if ssl == 0:
            raise _shim_error(lib, "tls: session creation")
        var rc = lib.get_function[c_int]("mts_ssl_accept")(ssl)
        if Int(rc) != 0:
            var err = _shim_error(lib, "tls: handshake failed")
            lib.get_function[NoneType]("mts_ssl_free")(ssl)
            raise err
        return TLSStream(_lib=lib^, _ssl=ssl, _tcp=tcp^, _open=True)

    def __deinit__(deinit self):
        """Frees the underlying SSL context."""
        try:
            self._lib.get_function[NoneType]("mts_ctx_free")(self._ctx)
        except:
            pass


@fieldwise_init
struct TLSStream(IOStream):
    """An established TLS session over a TCP stream.

    Conforms to `IOStream`: protocol layers written against the trait run
    over TLS unchanged. Read/write timeouts set on the underlying stream
    apply to the TLS records carried over it.
    """

    var _lib: OwnedDLHandle
    var _ssl: UInt64
    var _tcp: TCPStream
    var _open: Bool

    def _read_some(self, mut buf: List[Byte]) raises -> Int:
        var n = self._lib.get_function[c_int]("mts_ssl_read")(
            self._ssl, buf.unsafe_ptr(), c_int(len(buf))
        )
        if Int(n) >= 0:
            return Int(n)
        # WANT_READ/WANT_WRITE (-2/-3) surface when a socket timeout
        # expires mid-record; SYSCALL (-5) carries a transport errno.
        # os_error turns the pending EAGAIN into the typed timeout error.
        if Int(n) == -2 or Int(n) == -3 or Int(n) == -5:
            raise os_error("tls read")
        raise _shim_error(self._lib, "tls: read failed")

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
            var remaining = data[sent : len(data)]
            var n = self._lib.get_function[c_int]("mts_ssl_write")(
                self._ssl, remaining.unsafe_ptr(), c_int(len(remaining))
            )
            if Int(n) > 0:
                sent += Int(n)
                continue
            if Int(n) == -2 or Int(n) == -3 or Int(n) == -5:
                raise os_error("tls write")
            raise _shim_error(self._lib, "tls: write failed")

    def set_read_timeout(self, nanos: Int64) raises:
        """Bounds blocking reads via the underlying stream's timeout.

        Args:
            nanos: Timeout in nanoseconds; 0 clears it.

        Raises:
            If the setsockopt call fails.
        """
        self._tcp.set_read_timeout(nanos)

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
