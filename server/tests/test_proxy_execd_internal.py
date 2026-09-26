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

"""WM-11: the sandbox proxy does not reach execd's /internal/ control-plane routes.

execd serves POST /internal/init without its access token -- the call has to work
before a token exists -- and it applies a RuntimeBinding: the access-token hash, the
environment and the lifecycle. The server proxy exempts /sandboxes/{id}/proxy/{port}
from its own API-key check in single-tenant mode, so without this refusal anyone who
knows a sandbox id can rebind that sandbox's execd.

Every test here goes through the HTTP or WebSocket route and asserts on what the
caller gets and on whether the backend was contacted. None of them imports anything
WM-11 adds, so on a tree without the change they build and fail on the answer: the
request is forwarded.
"""

import asyncio
from urllib.parse import unquote

import httpx
import pytest
from fastapi.testclient import TestClient

import opensandbox_server.api.proxy as proxy_api
from opensandbox_server.api import lifecycle
from opensandbox_server.api.schema import Endpoint
from tests.test_routes_proxy import (
    _FakeAsyncClient,
    _FakeBackendWebSocket,
    _FakeStreamingResponse,
    _FakeWebSocketConnector,
    _set_http_client,
)

SANDBOX = "sbx-123"


class _RecordingService:
    """Endpoint lookup that records whether the proxy got as far as resolving one."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []

    def get_endpoint(
        self,
        sandbox_id: str,
        port: int,
        resolve_internal: bool = False,
        use_proxy_host: bool = False,
    ) -> Endpoint:
        self.calls.append((sandbox_id, port))
        return Endpoint(endpoint=f"10.0.0.7:{port}")


@pytest.fixture
def wired(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    service = _RecordingService()
    http = _FakeAsyncClient()
    http.response = _FakeStreamingResponse(chunks=[b"backend"])
    connector = _FakeWebSocketConnector(_FakeBackendWebSocket(subprotocol=None))
    monkeypatch.setattr(lifecycle, "sandbox_service", service)
    monkeypatch.setattr(proxy_api.websockets, "connect", connector)
    _set_http_client(client, http)
    return client, service, http, connector


# ⚠ THE REFUSALS ARE SENT AS RAW ASGI, NOT THROUGH A CLIENT LIBRARY. Starlette's
# TestClient decodes the path a second time, so %2F arrives as "/" and an encoded
# spelling tests nothing the plain one does not -- with no decoding at all in the guard
# those cases still passed. httpx resolves dot segments before it sends. uvicorn, which
# the route really runs behind, does neither: it decodes the path exactly once. These
# scopes are what uvicorn hands the app.
def _scope(kind: str, raw_path: str, headers: dict, method: str = "POST") -> dict:
    scope = {
        "type": kind,
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "scheme": "http" if kind == "http" else "ws",
        "path": unquote(raw_path),
        "raw_path": raw_path.encode("ascii"),
        "root_path": "",
        "query_string": b"",
        "headers": [(b"host", b"testserver")]
        + [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 80),
    }
    if kind == "http":
        scope["method"] = method
    else:
        scope["subprotocols"] = []
    return scope


async def _http(app, raw_path: str, headers: dict, method: str = "POST") -> tuple[int, bytes]:
    sent: list[dict] = []
    delivered = False

    async def receive():
        nonlocal delivered
        if not delivered:
            delivered = True
            return {"type": "http.request", "body": b"{}", "more_body": False}
        await asyncio.Future()

    async def send(message):
        sent.append(message)

    await asyncio.wait_for(app(_scope("http", raw_path, headers, method), receive, send), 10)
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, body


async def _websocket(app, raw_path: str, headers: dict) -> list[dict]:
    """Open a WebSocket and hang up at the first frame; return what the app sent."""
    sent: list[dict] = []
    inbox: asyncio.Queue = asyncio.Queue()
    await inbox.put({"type": "websocket.connect"})

    async def receive():
        return await inbox.get()

    async def send(message):
        sent.append(message)
        if message["type"] in ("websocket.close", "websocket.send"):
            await inbox.put({"type": "websocket.disconnect", "code": 1000})

    await asyncio.wait_for(app(_scope("websocket", raw_path, headers), receive, send), 10)
    return sent


# Every way of spelling execd's /internal/ routes that execd would route there, as the
# client puts it on the wire. execd (gin, UseRawPath off) matches on the DECODED path,
# so what this server decodes once and forwards still encoded is decoded again there;
# and execd forwards /proxy/<port>/... to 127.0.0.1:<port>, its own port included.
_PREFIX = f"/sandboxes/{SANDBOX}/proxy/44772"
INTERNAL_SPELLINGS = [
    f"{_PREFIX}/internal/init",
    f"/v1/sandboxes/{SANDBOX}/proxy/44772/internal/init",
    f"{_PREFIX}/internal",
    f"{_PREFIX}/internal/",
    f"/sandboxes/{SANDBOX}/proxy/044772/internal/init",
    f"{_PREFIX}//internal/init",
    f"{_PREFIX}/./internal/init",
    f"{_PREFIX}/files/../internal/init",
    # Percent-encoded, once and twice.
    f"{_PREFIX}/internal%2Finit",
    f"{_PREFIX}/internal%252Finit",
    f"{_PREFIX}/%69nternal/init",
    f"{_PREFIX}/%2569nternal/init",
    f"{_PREFIX}/files/%2e%2e/internal/init",
    f"{_PREFIX}/files/%252e%252e/internal/init",
    # Through execd's own reverse proxy, onto itself.
    f"{_PREFIX}/proxy/44772/internal/init",
    f"{_PREFIX}/proxy/44772/proxy/44772/internal/init",
    f"{_PREFIX}/proxy/044772/internal/init",
    f"{_PREFIX}/proxy/44772/internal%252Finit",
    # Go's dialer reads any number of leading zeros as the same port, so the length of
    # the segment decides nothing -- including one too long for Python's int().
    f"{_PREFIX}/proxy/{'0' * 5000}44772/internal/init",
    # A "?" or "#" decoded from %3F or %23 ends the path the forwarded URL is split
    # into; ".." after it climbs out of nothing execd routes on.
    f"{_PREFIX}/internal/init%3F",
    f"{_PREFIX}/internal/init%3F/../x",
    f"{_PREFIX}/internal/init%3F/../../x",
    f"{_PREFIX}/internal/init%3F/../../../x",
    f"{_PREFIX}/internal/init%3F/%2E%2E/%2E%2E/x",
    f"{_PREFIX}/internal%2Finit%3F/../../x",
    f"{_PREFIX}/internal/init%23",
    f"{_PREFIX}/internal/init%23/../x",
    f"{_PREFIX}/internal/init%23/../../x",
    f"{_PREFIX}/internal/init%23/../../../x",
    f"{_PREFIX}/proxy/44772/internal/init%3F/../../../../z",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("path", INTERNAL_SPELLINGS)
@pytest.mark.parametrize("method", ["POST", "GET"])
async def test_wm11_http_proxy_refuses_execd_internal_routes(
    wired, auth_headers: dict, path: str, method: str
) -> None:
    client, service, http, _ = wired

    status, body = await _http(client.app, path, auth_headers, method)

    assert status == 403, (
        f"{method} {path} reached the backend: execd serves /internal/ without its "
        "access token, so the proxy is the only thing between a caller and a rebind"
    )
    assert b"EXECD_INTERNAL_PATH_FORBIDDEN" in body
    assert http.built is None, "the request must not be forwarded"
    # Refused before the endpoint is resolved, so a refused request neither costs a
    # lookup nor renews the sandbox's expiry.
    assert service.calls == []


# The threat as it arrives: no API key at all. In single-tenant mode the proxy route is
# exempt from the key, so for these the refusal here is the only thing in the way.
ANONYMOUS_SPELLINGS = [
    f"{_PREFIX}/internal/init",
    f"{_PREFIX}/internal%2Finit",
    f"{_PREFIX}/proxy/44772/internal/init",
    f"{_PREFIX}/internal/init%3F/../../x",
    f"{_PREFIX}/internal/init%23/../../x",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ANONYMOUS_SPELLINGS)
async def test_wm11_http_proxy_refuses_an_anonymous_caller(wired, path: str) -> None:
    client, service, http, _ = wired

    status, _ = await _http(client.app, path, {})

    assert status == 403, f"an anonymous POST {path} was not refused"
    assert http.built is None, "the request must not be forwarded"
    assert service.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    [
        f"{_PREFIX}/internal/init",
        f"/v1/sandboxes/{SANDBOX}/proxy/44772/internal%2Finit",
        f"{_PREFIX}/internal%252Finit",
        f"{_PREFIX}/proxy/44772/internal/init",
        f"{_PREFIX}/internal/init%3F/../../x",
        f"{_PREFIX}/internal/init%23/../../x",
    ],
)
@pytest.mark.parametrize("authenticated", [True, False])
async def test_wm11_websocket_proxy_refuses_execd_internal_routes(
    wired, auth_headers: dict, path: str, authenticated: bool
) -> None:
    client, service, _, connector = wired

    sent = await _websocket(client.app, path, auth_headers if authenticated else {})

    closes = [m for m in sent if m["type"] == "websocket.close"]
    assert [c.get("code") for c in closes] == [1008], (
        f"expected a policy-violation close, got {sent}"
    )
    assert connector.calls == [], "no backend WebSocket may be opened"
    assert service.calls == []


# The port in the URL is not always where the request goes. On Docker every port but
# 8080 resolves to execd itself, as <host>:<execd>/proxy/<port>; the path is appended to
# that, and httpx resolves dot segments before sending. So a request naming port 1234
# lands on execd's /internal/init if its path climbs out of /proxy/1234 -- with an API
# key, since the key check refuses a literal ".." from anyone else.
class _DockerShapedService(_RecordingService):
    def get_endpoint(self, sandbox_id, port, resolve_internal=False, use_proxy_host=False):
        self.calls.append((sandbox_id, port))
        if port == 8080:
            return Endpoint(endpoint="127.0.0.1:40002")
        return Endpoint(endpoint=f"127.0.0.1:40001/proxy/{port}")


@pytest.fixture
def docker_wired(wired, monkeypatch: pytest.MonkeyPatch):
    client, _, http, connector = wired
    service = _DockerShapedService()
    monkeypatch.setattr(lifecycle, "sandbox_service", service)
    return client, service, http, connector


_OTHER_PORT = f"/sandboxes/{SANDBOX}/proxy/1234"
CLIMBING_SPELLINGS = [
    f"{_OTHER_PORT}/../../internal/init",
    f"{_OTHER_PORT}/%2e%2e/%2e%2e/internal/init",
    f"{_OTHER_PORT}/a/../../../internal/init",
    f"{_OTHER_PORT}/../44772/internal/init",
    f"{_OTHER_PORT}/%252e%252e/44772/internal/init",
    f"/sandboxes/{SANDBOX}/proxy/8080/../../internal/init",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("path", CLIMBING_SPELLINGS)
async def test_wm11_a_path_climbing_out_of_its_port_is_not_forwarded(
    docker_wired, auth_headers: dict, path: str
) -> None:
    client, service, http, _ = docker_wired

    status, body = await _http(client.app, path, auth_headers)

    assert status == 400, (
        f"{path} was forwarded: behind a Docker-shaped endpoint it lands on "
        f"{http.built and httpx.URL(http.built['url'])}"
    )
    assert b"PROXY_PATH_LEAVES_PORT" in body
    assert http.built is None, "the request must not be forwarded"
    assert service.calls == []


@pytest.mark.asyncio
async def test_wm11_an_anonymous_climb_the_key_check_cannot_see_is_not_forwarded(
    docker_wired,
) -> None:
    # Encoded twice, the dots survive the key check's ".." test -- it sees %2e%2e -- and
    # the route is exempt from the key in single-tenant mode.
    client, service, http, _ = docker_wired

    status, _ = await _http(client.app, f"{_OTHER_PORT}/%252e%252e/44772/internal/init", {})

    assert status == 400
    assert http.built is None, "the request must not be forwarded"
    assert service.calls == []


@pytest.mark.asyncio
async def test_wm11_websocket_proxy_refuses_a_path_climbing_out_of_its_port(
    docker_wired, auth_headers: dict
) -> None:
    client, service, _, connector = docker_wired

    sent = await _websocket(client.app, f"{_OTHER_PORT}/../../internal/init", auth_headers)

    closes = [m for m in sent if m["type"] == "websocket.close"]
    assert [c.get("code") for c in closes] == [1008], f"expected a policy-violation close, got {sent}"
    assert connector.calls == [], "no backend WebSocket may be opened"
    assert service.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("path", "forwarded_to"),
    [
        (f"{_OTHER_PORT}/api/v1/items", "http://127.0.0.1:40001/proxy/1234/api/v1/items"),
        # Down and back up, never above the port's root.
        (f"{_OTHER_PORT}/api/../v1/items", "http://127.0.0.1:40001/proxy/1234/v1/items"),
    ],
)
async def test_wm11_docker_shaped_endpoints_still_forward_what_stays_inside_the_port(
    docker_wired, auth_headers: dict, path: str, forwarded_to: str
) -> None:
    # The guard for the check above, which must hold on upstream too.
    client, _, http, _ = docker_wired

    status, body = await _http(client.app, path, auth_headers, "GET")

    assert status == 200, body
    # What httpx will put on the wire, dot segments resolved.
    assert str(httpx.URL(http.built["url"])) == forwarded_to


# Guards. These must hold on upstream too: WM-11 narrows exactly one thing, and the
# browser relay depends on the first of them -- CDP is reached as
# /sandboxes/{id}/proxy/44772/proxy/9223/..., execd's own reverse proxy onto Chromium.


@pytest.mark.parametrize(
    ("path", "forwarded_to"),
    [
        (
            f"{_PREFIX}/proxy/9223/json/version",
            "http://10.0.0.7:44772/proxy/9223/json/version",
        ),
        (
            f"{_PREFIX}/proxy/9223/internal/init",
            "http://10.0.0.7:44772/proxy/9223/internal/init",
        ),
        (
            f"{_PREFIX}/files/internal/init",
            "http://10.0.0.7:44772/files/internal/init",
        ),
        (
            f"{_PREFIX}/internals",
            "http://10.0.0.7:44772/internals",
        ),
        (
            f"/sandboxes/{SANDBOX}/proxy/8080/internal/init",
            "http://10.0.0.7:8080/internal/init",
        ),
        # Encoded over and over, and never anything but a file path: forwarded. A cap on
        # the decoding is a reason to stop looking, not a reason to refuse.
        (
            f"{_PREFIX}/files/%252525252541",
            "http://10.0.0.7:44772/files/%25252541",
        ),
        # "4477²" is not a port to Go, which dials ASCII digits only, so execd answers
        # this one itself -- and it must reach execd, not end in a 500 here because
        # "²" passes str.isdigit() and then fails int().
        (
            f"{_PREFIX}/proxy/4477%C2%B2/internal/init",
            "http://10.0.0.7:44772/proxy/4477²/internal/init",
        ),
    ],
)
def test_wm11_http_proxy_still_forwards_everything_else(
    wired, auth_headers: dict, path: str, forwarded_to: str
) -> None:
    client, _, http, _ = wired

    response = client.get(path, headers=auth_headers)

    assert response.status_code == 200
    assert response.content == b"backend"
    assert http.built["url"] == forwarded_to


def test_wm11_websocket_proxy_still_reaches_cdp_through_execd(
    wired, auth_headers: dict
) -> None:
    client, _, _, connector = wired

    with client.websocket_connect(
        f"{_PREFIX}/proxy/9223/devtools/page/ABC",
        headers=auth_headers,
    ) as websocket:
        websocket.send_text("{}")

    assert [c["uri"] for c in connector.calls] == [
        "ws://10.0.0.7:44772/proxy/9223/devtools/page/ABC"
    ]
