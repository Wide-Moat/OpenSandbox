# SPDX-License-Identifier: Apache-2.0
"""Coordinator regressions for strict expiry and legacy compatibility."""
import pytest
from tests.test_tenant_subject import make_provider, ok, NAMESPACE, SUBJECT
from opensandbox_server.tenants.provider import TenantProviderUnavailable


def test_strict_cache_expires_at_deadline():
    p, client, clock = make_provider([
        ok({"namespace": NAMESPACE, "subject": SUBJECT, "ttl": 60}),
        RuntimeError("gateway unavailable"),
    ], require_subject=True)
    p.lookup("key-a")
    clock.advance(60)
    with pytest.raises(TenantProviderUnavailable):
        p.lookup("key-a")
    assert len(client.calls) == 2


def test_strict_identity_requires_explicit_ttl():
    p, _, _ = make_provider([ok({"namespace": NAMESPACE, "subject": SUBJECT})], require_subject=True)
    with pytest.raises(TenantProviderUnavailable):
        p.lookup("key-a")


def test_legacy_numeric_string_ttl_remains_supported():
    p, _, _ = make_provider([ok({"namespace": NAMESPACE, "ttl": "600"})])
    entry = p.lookup("key-a")
    assert entry is not None
    assert entry.namespace == NAMESPACE
    assert p._cache["key-a"].ttl == 600


def test_legacy_malformed_refresh_retains_documented_stale_behavior():
    p, _, clock = make_provider([
        ok({"namespace": NAMESPACE, "ttl": 60}),
        ok([]),
    ])
    original = p.lookup("key-a")
    clock.advance(61)
    assert p.lookup("key-a") is original
