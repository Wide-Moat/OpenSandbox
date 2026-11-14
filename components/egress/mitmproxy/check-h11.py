# Copyright 2026 The OpenSandbox Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Wide Moat (WID-361): build-time check of the h11 installed over mitmproxy 11.0.2's h11<=0.14.0
# pin. mitmproxy reads HTTP/1 bodies with h11's private readers (proxy/layers/http/_http1.py), so
# they are driven here through mitmproxy's own make_body_reader: chunked and content-length bodies
# must still read, and a chunk whose footer is not CRLF must be refused -- the CVE-2025-43859
# request-smuggling fix, which h11 0.14.0 accepts. Exits non-zero on any failure.
import importlib.metadata

import h11
from h11._receivebuffer import ReceiveBuffer
from mitmproxy.proxy.layers.http._http1 import make_body_reader


def read_body(expected_size, wire):
    reader = make_body_reader(expected_size)
    buf = ReceiveBuffer()
    buf += wire
    out = b""
    while True:
        event = reader(buf)
        if event is None or isinstance(event, h11.EndOfMessage):
            return out, event
        out += bytes(event.data)


out, event = read_body(None, b"5\r\nhello\r\n0\r\n\r\n")
assert out == b"hello" and isinstance(event, h11.EndOfMessage), ("chunked", out, event)
out, event = read_body(5, b"hello")
assert out == b"hello" and isinstance(event, h11.EndOfMessage), ("content-length", out, event)
try:
    read_body(None, b"5\r\nhelloXX0\r\n\r\n")
except h11.ProtocolError:
    pass
else:
    raise SystemExit("h11 accepted a malformed chunk footer (CVE-2025-43859)")
print("h11", importlib.metadata.version("h11"), "mitmproxy", importlib.metadata.version("mitmproxy"),
      ": bodies read through mitmproxy's readers, malformed chunk refused")
