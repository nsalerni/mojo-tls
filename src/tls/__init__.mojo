# ===----------------------------------------------------------------------=== #
# Copyright (c) 2026 the grpc-mojo contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ===----------------------------------------------------------------------=== #

"""TLS for Mojo 1.0 over libssl.

Client and server handshakes, SNI with hostname verification, ALPN on
both roles, and trust-store or custom-CA verification, wrapped around
mojo-net's `TCPStream`. `TLSHandshake` supports readiness-driven progress,
and `TLSStream` conforms to `ReadinessStream` as well as `IOStream`.

Example (client):

```mojo
from net import TCPStream
from tls import TLSContext

def main() raises:
    var ctx = TLSContext.client(alpn=["h2"])
    var tcp = TCPStream.connect("example.com", 443)
    var stream = ctx.connect(tcp^, "example.com")
    print(stream.version(), stream.negotiated_alpn())
```
"""

from .tls import TLSContext, TLSHandshake, TLSStream
