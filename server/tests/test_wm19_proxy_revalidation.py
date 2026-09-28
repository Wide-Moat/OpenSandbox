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

"""WM-19: under ``[tenants] enforce_ownership`` the proxy asks the identity
endpoint itself, not its TTL cache, before it reaches a backend.

The caller here was authenticated from a cached grant; the endpoint now answers
that the key is revoked, or that it belongs to someone else. Upstream proxies
the request anyway, because it never asks again.

The tests run on upstream too: they call the proxy's own request handler, set
the subject on the tenant entry without the constructor field upstream lacks,
and fail there on what the handler does.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

import opensandbox_server.api.proxy as proxy_api
from opensandbox_server.api import lifecycle
from opensandbox_server.config import TenantsConfig
from opensandbox_server.middleware.auth import SANDBOX_API_KEY_HEADER
from opensandbox_server.tenants.context import get_current_tenant, set_current_tenant
from opensandbox_server.tenants.models import TenantEntry


def _entry(subject: str, namespace: str = "sandbox-shared") -> TenantEntry:
    entry = TenantEntry(name=namespace, namespace=namespace, api_keys=())
    object.__setattr__(entry, "subject", subject)
    return entry


@pytest.fixture
def strict(monkeypatch):
    config = proxy_api.get_config().model_copy(deep=True)
    config.tenants = TenantsConfig.model_validate(
        {
            "provider": "http",
            "endpoint": "http://identity.invalid/tenant",
            "max_stale_seconds": 0,
            "enforce_ownership": True,
        }
    )
    monkeypatch.setattr(proxy_api, "get_config", lambda: config)
    previous = get_current_tenant()
    set_current_tenant(_entry("alice"))
    try:
        yield
    finally:
        set_current_tenant(previous)


def _request(fresh):
    provider = SimpleNamespace(lookup=lambda key: _entry("alice"), lookup_fresh=fresh)
    return SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(tenant_provider=provider)),
        headers={SANDBOX_API_KEY_HEADER: "synthetic-key"},
    )


def _backend_must_not_be_reached(monkeypatch):
    def get_endpoint(*args, **kwargs):
        pytest.fail("the request reached backend resolution")

    monkeypatch.setattr(lifecycle, "sandbox_service", SimpleNamespace(get_endpoint=get_endpoint))


@pytest.mark.asyncio
async def test_wm19_a_revoked_key_is_refused_before_the_backend(strict, monkeypatch):
    _backend_must_not_be_reached(monkeypatch)
    with pytest.raises(HTTPException) as refused:
        await proxy_api._proxy_http_request(_request(lambda key: None), "sbx-1", 8080, "status")
    assert refused.value.status_code == 401


@pytest.mark.asyncio
async def test_wm19_a_key_now_naming_another_subject_is_refused(strict, monkeypatch):
    _backend_must_not_be_reached(monkeypatch)
    with pytest.raises(HTTPException) as refused:
        await proxy_api._proxy_http_request(
            _request(lambda key: _entry("bob")), "sbx-1", 8080, "status"
        )
    assert refused.value.status_code == 401
