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

"""execd's own token is on by default on Kubernetes, and the server's proxy carries it.

Before this, no Kubernetes sandbox got EXECD_ACCESS_TOKEN, and execd's middleware treats
an empty token as "no authentication": anyone who could reach the pod on 44772 could run
commands. The network policy was the only lock.

Unit tests of WM-23's own helpers and constants, so not declared as WM tests: they import
symbols upstream lacks and cannot run there. What hack/wm-fail-on-base.sh runs against
upstream for WM-23 is test_wm23_execd_token_behaviour.py, written with upstream symbols only.
"""

from datetime import datetime, timezone

import pytest

from opensandbox_server.api.proxy import _filter_proxy_headers
from opensandbox_server.api.schema import Endpoint
from opensandbox_server.config import RuntimeConfig
from opensandbox_server.services.constants import (
    EXECD_ACCESS_TOKEN_ENV,
    EXECD_ACCESS_TOKEN_HEADER,
    EXECD_PORT,
    SANDBOX_EXECD_ACCESS_TOKEN_METADATA_KEY,
)
from opensandbox_server.services.k8s.create_helpers import _build_create_workload_context
from opensandbox_server.services.k8s.endpoint_resolver import _attach_execd_access_headers


def _context(app_config, request, factory):
    return _build_create_workload_context(
        app_config,
        request,
        "sandbox-1",
        datetime.now(timezone.utc),
        lambda: "egress-token",
        lambda: "secure-token",
        factory,
    )


def test_execd_token_the_default_is_on():
    assert RuntimeConfig(type="kubernetes", execd_image="execd:x").execd_access_token is True


def test_execd_token_a_token_lands_in_the_container_env_and_the_annotation(k8s_app_config, create_sandbox_request):
    create_sandbox_request.env = {"USER_ENV": "value"}
    context = _context(k8s_app_config, create_sandbox_request, lambda: "execd-token")
    assert context.sandbox_env[EXECD_ACCESS_TOKEN_ENV] == "execd-token"
    assert context.annotations[SANDBOX_EXECD_ACCESS_TOKEN_METADATA_KEY] == "execd-token"
    assert context.sandbox_env["USER_ENV"] == "value"


@pytest.mark.parametrize("factory", [None, lambda: "server-token"])
def test_execd_token_a_caller_cannot_choose_execds_token(k8s_app_config, create_sandbox_request, factory):
    create_sandbox_request.env = {EXECD_ACCESS_TOKEN_ENV: "caller-picked"}
    context = _context(k8s_app_config, create_sandbox_request, factory)
    assert context.sandbox_env.get(EXECD_ACCESS_TOKEN_ENV) != "caller-picked"
    if factory is None:
        assert EXECD_ACCESS_TOKEN_ENV not in context.sandbox_env
        assert SANDBOX_EXECD_ACCESS_TOKEN_METADATA_KEY not in context.annotations


def _workload(token=None):
    annotations = {} if token is None else {SANDBOX_EXECD_ACCESS_TOKEN_METADATA_KEY: token}
    return {"metadata": {"annotations": annotations}}


def test_execd_token_the_execd_endpoint_carries_the_token():
    endpoint = Endpoint(endpoint="10.0.0.1:44772")
    _attach_execd_access_headers(endpoint, _workload("execd-token"), EXECD_PORT)
    assert endpoint.headers == {EXECD_ACCESS_TOKEN_HEADER: "execd-token"}


@pytest.mark.parametrize("port", [8080, 18080, 9223])
def test_execd_token_no_other_port_is_handed_execds_token(port):
    endpoint = Endpoint(endpoint=f"10.0.0.1:{port}")
    _attach_execd_access_headers(endpoint, _workload("execd-token"), port)
    assert not endpoint.headers


def test_execd_token_a_sandbox_without_a_token_gets_no_header():
    endpoint = Endpoint(endpoint="10.0.0.1:44772")
    _attach_execd_access_headers(endpoint, _workload(), EXECD_PORT)
    assert not endpoint.headers


def test_execd_token_the_proxy_sends_the_servers_token_not_the_callers():
    forwarded = _filter_proxy_headers(
        {"x-execd-access-token": "caller-guess", "content-type": "application/json"},
        {EXECD_ACCESS_TOKEN_HEADER: "execd-token"},
    )
    values = [v for k, v in forwarded.items() if k.lower() == EXECD_ACCESS_TOKEN_HEADER.lower()]
    assert values == ["execd-token"]
