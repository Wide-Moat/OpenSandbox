# SPDX-License-Identifier: Apache-2.0
"""Reject configurations that silently weaken authenticated owner enforcement."""
import pytest
from pydantic import ValidationError
from opensandbox_server.config import AppConfig, TenantsConfig


def test_owner_profile_is_explicit():
    assert TenantsConfig().enforce_ownership is False


@pytest.mark.parametrize("values", [
    {"provider": "file", "max_stale_seconds": 0},
    {"provider": "http", "endpoint": "http://keyauth/tenant/identity"},
])
def test_owner_profile_rejects_missing_identity_or_stale_cache(values):
    with pytest.raises(ValidationError, match="enforce_ownership"):
        TenantsConfig(enforce_ownership=True, **values)


def owner_tenants():
    return dict(provider="http", endpoint="http://keyauth/tenant/identity",
                enforce_ownership=True, max_stale_seconds=0)


@pytest.mark.parametrize("runtime,kubernetes", [
    ({"type": "docker"}, None),
    ({"type": "kubernetes"}, {"workload_provider": "agent-sandbox"}),
    ({"type": "kubernetes"}, {}),
])
def test_owner_profile_requires_explicit_supported_runtime(runtime, kubernetes):
    with pytest.raises(ValidationError, match="enforce_ownership"):
        AppConfig.model_validate(dict(runtime={**runtime, 'execd_image': 'example.invalid/execd:test'}, kubernetes=kubernetes, tenants=owner_tenants()))


def test_owner_profile_accepts_batchsandbox_http_without_stale():
    config = AppConfig.model_validate(dict(runtime={'type': 'kubernetes', 'execd_image': 'example.invalid/execd:test'}, kubernetes={'workload_provider': 'batchsandbox'}, tenants=owner_tenants()))
    assert config.tenants is not None
    assert config.tenants.enforce_ownership is True
    assert config.tenants.max_stale_seconds == 0


@pytest.mark.parametrize("subject", [None, "synthetic-owner"])
def test_application_provider_requires_identity_over_http(subject):
    import json
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread

    import httpx

    from opensandbox_server.main import _build_tenant_provider
    from opensandbox_server.tenants.provider import TenantProviderUnavailable

    payload = {"namespace": "sandbox-stage", "ttl": 60}
    if subject is not None:
        payload["subject"] = subject

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as endpoint:
        thread = Thread(target=endpoint.serve_forever, daemon=True)
        thread.start()
        try:
            tenants = owner_tenants()
            tenants["endpoint"] = f"http://127.0.0.1:{endpoint.server_port}/tenant/identity"
            config = AppConfig.model_validate(dict(runtime={'type': 'kubernetes', 'execd_image': 'example.invalid/execd:test'}, kubernetes={'workload_provider': 'batchsandbox'}, tenants=tenants))
            from opensandbox_server.tenants.http_provider import HTTPTenantProvider
            provider = _build_tenant_provider(config)
            assert isinstance(provider, HTTPTenantProvider)
            with httpx.Client(trust_env=False) as client:
                provider._client = client
                if subject is None:
                    with pytest.raises(TenantProviderUnavailable):
                        provider.lookup("synthetic-key")
                else:
                    entry = provider.lookup("synthetic-key")
                    assert entry is not None
                    assert entry.subject == subject
                    assert entry.namespace == "sandbox-stage"
        finally:
            endpoint.shutdown()
            thread.join(timeout=5)


@pytest.mark.parametrize('redis_enabled', [False, True])
def test_strict_profile_rejects_unauthenticated_redis_renewal(redis_enabled):
    values = dict(runtime={'type': 'kubernetes', 'execd_image': 'execd:test'}, kubernetes={'workload_provider': 'batchsandbox'}, tenants=owner_tenants(), renew_intent={'enabled': True, 'redis': {'enabled': redis_enabled, 'dsn': 'redis://localhost:6379/0'}})
    if redis_enabled:
        with pytest.raises(ValidationError, match='enforce_ownership.*Redis'):
            AppConfig.model_validate(dict(**values))
    else:
        assert AppConfig.model_validate(dict(**values)).renew_intent.enabled
