# Compliance tool: client identity context construction.
# Usage: tls_client_context <cert_pem> <key_pem>
# Performs no network I/O. A bad pair exits non-zero during construction.

from std.sys import argv

from tls import TLSContext


def main() raises:
    var args = argv()
    if len(args) != 3:
        raise Error("usage: tls_client_context <cert_pem> <key_pem>")
    _ = TLSContext.client(
        verify=False,
        cert_chain_pem=String(args[1]),
        key_pem=String(args[2]),
    )
    print("OK")
