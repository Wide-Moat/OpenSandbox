# Copyright 2026 Alibaba Group Holding Ltd.
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

"""Transport-level authenticated subject in the HTTP tenant provider.

The real provider methods are exercised; only the external HTTP boundary is
replaced. The clock is deterministic so cache and TTL behaviour is asserted
rather than slept for.

Scope: O3 transport only. This does not establish owner isolation anywhere --
nothing here enforces ownership on a sandbox operation.
"""

from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional

import pytest

from opensandbox_server.tenants.http_provider import (
    HTTPTenantProvider,
    HTTPTenantProviderConfig,
)
from opensandbox_server.tenants.models import TenantEntry
from opensandbox_server.tenants.provider import TenantProviderUnavailable

NAMESPACE = "sandbox-stage"
SUBJECT = "user-1234"


class FakeClock:
    """Deterministic monotonic clock."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakeResponse:
    def __init__(self, status_code: int, payload: Any) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> Any:
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeHTTPClient:
    """The external boundary, and only that.

    ``script`` is consumed one entry per GET; the last entry repeats. An entry
    may be a FakeResponse or an Exception to raise.
    """

    def __init__(self, script: List[Any]) -> None:
        self._script = list(script)
        self.calls: List[str] = []
        self.before_get: Optional[Any] = None

    def get(self, url: str, headers: Dict[str, str]) -> FakeResponse:
        self.calls.append(headers.get("OPEN-SANDBOX-API-KEY", ""))
        if self.before_get is not None:
            self.before_get()
        item = self._script[0] if len(self._script) == 1 else self._script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def make_provider(
    script: List[Any],
    *,
    require_subject: bool = False,
    max_stale_seconds: float = 300.0,
    timeout_seconds: float = 5.0,
) -> tuple[HTTPTenantProvider, FakeHTTPClient, FakeClock]:
    config = HTTPTenantProviderConfig(
        endpoint="http://keyauth.invalid/tenant",
        max_stale_seconds=max_stale_seconds,
        timeout_seconds=timeout_seconds,
        require_subject=require_subject,
    )
    provider = HTTPTenantProvider(config)
    client = FakeHTTPClient(script)
    setattr(provider, "_client", client)  # Substitute only the external HTTP boundary.
    clock = FakeClock()
    provider._clock = clock  # deterministic time
    return provider, client, clock


def ok(payload: Any) -> FakeResponse:
    return FakeResponse(200, payload)


# --- the added field ---------------------------------------------------------


def test_tenant_entry_subject_defaults_to_none():
    entry = TenantEntry(name="ns", namespace="ns")
    assert entry.subject is None


def test_subject_is_carried_and_namespace_name_preserved():
    provider, _, _ = make_provider(
        [ok({"namespace": NAMESPACE, "ttl": 60, "subject": SUBJECT})],
        require_subject=True,
    )
    entry = provider.lookup("key-a")
    assert entry is not None
    assert entry.subject == SUBJECT
    # name stays the namespace: tenant identity is not the person.
    assert entry.name == NAMESPACE
    assert entry.namespace == NAMESPACE
    assert entry.api_keys == ("key-a",)


def test_legacy_mode_without_subject_still_works():
    provider, _, _ = make_provider([ok({"namespace": NAMESPACE, "ttl": 60})])
    entry = provider.lookup("key-a")
    assert entry is not None
    assert entry.subject is None
    assert entry.namespace == NAMESPACE


def test_rotation_two_keys_same_subject():
    provider, _, _ = make_provider(
        [ok({"namespace": NAMESPACE, "ttl": 60, "subject": SUBJECT})],
        require_subject=True,
    )
    first = provider.lookup("key-a")
    second = provider.lookup("key-b")
    assert first is not None and second is not None
    assert first.subject == second.subject == SUBJECT
    assert first.api_keys != second.api_keys


def test_opaque_subject_preserved_exactly():
    weird = "  Auth0|abc-DEF_123.xyz  "
    provider, _, _ = make_provider(
        [ok({"namespace": NAMESPACE, "ttl": 60, "subject": weird})],
        require_subject=True,
    )
    entry = provider.lookup("key-a")
    assert entry is not None
    # Nonblank check may strip for validation, but the stored value is exact.
    assert entry.subject == weird


# --- strict mode refuses bad identity ---------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        {"namespace": NAMESPACE, "ttl": 60},  # missing
        {"namespace": NAMESPACE, "ttl": 60, "subject": None},  # null
        {"namespace": NAMESPACE, "ttl": 60, "subject": ""},  # empty
        {"namespace": NAMESPACE, "ttl": 60, "subject": "   "},  # blank
        {"namespace": NAMESPACE, "ttl": 60, "subject": 42},  # wrong type
        {"namespace": NAMESPACE, "ttl": 60, "subject": True},  # bool is not a subject
        {"namespace": NAMESPACE, "ttl": 60, "subject": ["u"]},  # wrong type
    ],
)
def test_strict_mode_rejects_bad_subject_without_namespace_fallback(payload):
    provider, _, _ = make_provider([ok(payload)], require_subject=True)
    with pytest.raises(TenantProviderUnavailable):
        provider.lookup("key-a")
    # Nothing cached: a refused identity must not become a usable entry later.
    assert provider._cache == {}


def test_strict_mode_never_downgrades_to_namespace_only():
    """A missing subject must not yield a namespace-only entry."""
    provider, _, _ = make_provider(
        [ok({"namespace": NAMESPACE, "ttl": 60})], require_subject=True
    )
    with pytest.raises(TenantProviderUnavailable):
        provider.lookup("key-a")


# --- TTL validation ----------------------------------------------------------


@pytest.mark.parametrize(
    "ttl",
    [float("nan"), float("inf"), float("-inf"), -1.0, True, False, "60", None, [60]],
)
def test_invalid_ttl_is_refused(ttl):
    provider, _, _ = make_provider(
        [ok({"namespace": NAMESPACE, "ttl": ttl, "subject": SUBJECT})],
        require_subject=True,
    )
    with pytest.raises(TenantProviderUnavailable):
        provider.lookup("key-a")


def test_ttl_is_capped():
    provider, client, clock = make_provider(
        [ok({"namespace": NAMESPACE, "ttl": 100000, "subject": SUBJECT})],
        require_subject=True,
    )
    provider.lookup("key-a")
    assert provider._cache["key-a"].ttl == 300.0
    # Just inside the cap: still cached, no second call.
    clock.advance(299)
    provider.lookup("key-a")
    assert len(client.calls) == 1


def test_zero_ttl_means_no_cache_reuse():
    provider, client, clock = make_provider(
        [ok({"namespace": NAMESPACE, "ttl": 0, "subject": SUBJECT})],
        require_subject=True,
    )
    provider.lookup("key-a")
    assert len(client.calls) == 1
    # No time passes at all; a zero TTL must still refetch.
    provider.lookup("key-a")
    assert len(client.calls) == 2


# --- cache, staleness and invalidation --------------------------------------


def test_strict_mode_never_serves_stale_after_failed_refresh():
    """Even with max_stale_seconds configured, strict mode fails closed."""
    provider, _, clock = make_provider(
        [
            ok({"namespace": NAMESPACE, "ttl": 60, "subject": SUBJECT}),
            RuntimeError("upstream down"),
        ],
        require_subject=True,
        max_stale_seconds=300.0,
    )
    assert provider.lookup("key-a") is not None
    clock.advance(61)
    with pytest.raises(TenantProviderUnavailable):
        provider.lookup("key-a")


def test_strict_mode_failed_refresh_does_not_return_old_subject():
    provider, _, clock = make_provider(
        [
            ok({"namespace": NAMESPACE, "ttl": 60, "subject": SUBJECT}),
            RuntimeError("upstream down"),
        ],
        require_subject=True,
        max_stale_seconds=300.0,
    )
    provider.lookup("key-a")
    clock.advance(61)
    try:
        result = provider.lookup("key-a")
    except TenantProviderUnavailable:
        return
    assert result is None or result.subject != SUBJECT, "stale subject was served"


def test_legacy_mode_still_serves_stale_within_window():
    """The legacy profile is unchanged; it cannot satisfy S05."""
    provider, _, clock = make_provider(
        [
            ok({"namespace": NAMESPACE, "ttl": 60}),
            RuntimeError("upstream down"),
        ],
        max_stale_seconds=300.0,
    )
    provider.lookup("key-a")
    clock.advance(61)
    entry = provider.lookup("key-a")
    assert entry is not None and entry.namespace == NAMESPACE


def test_explicit_401_evicts_cache():
    provider, _, clock = make_provider(
        [
            ok({"namespace": NAMESPACE, "ttl": 60, "subject": SUBJECT}),
            FakeResponse(401, {}),
        ],
        require_subject=True,
    )
    assert provider.lookup("key-a") is not None
    clock.advance(61)
    assert provider.lookup("key-a") is None
    assert "key-a" not in provider._cache


def test_403_is_unavailable_not_silent_success():
    provider, _, _ = make_provider(
        [FakeResponse(403, {})],
        require_subject=True,
    )
    with pytest.raises(TenantProviderUnavailable):
        provider.lookup("key-a")


def test_malformed_json_body_is_unavailable():
    provider, _, _ = make_provider(
        [FakeResponse(200, ValueError("not json"))],
        require_subject=True,
    )
    with pytest.raises(TenantProviderUnavailable):
        provider.lookup("key-a")


# --- singleflight ------------------------------------------------------------


def test_follower_timeout_raises_instead_of_serving_stale():
    """A waiter that times out must not fall back to the cached entry.

    The previous implementation ignored the wait() result and read the cache,
    so a follower could return a stale entry the leader was in the middle of
    refreshing -- exactly what strict mode must not do.
    """
    provider, _, clock = make_provider(
        [
            ok({"namespace": NAMESPACE, "ttl": 60, "subject": SUBJECT}),
            ok({"namespace": NAMESPACE, "ttl": 60, "subject": SUBJECT}),
        ],
        require_subject=True,
        timeout_seconds=0.05,
    )
    # Seed the cache so a stale entry exists to be wrongly served.
    provider.lookup("key-a")
    clock.advance(61)

    # Occupy the singleflight slot as if a leader were mid-fetch.
    stuck = threading.Event()
    with provider._lock:
        from opensandbox_server.tenants.http_provider import _FlightEvent

        provider._inflight["key-a"] = _FlightEvent()

    try:
        with pytest.raises(TenantProviderUnavailable):
            provider.lookup("key-a")
    finally:
        with provider._lock:
            provider._inflight.pop("key-a", None)
        stuck.set()


def test_followers_share_a_successful_zero_ttl_fetch():
    """Concurrent followers may use the leader's result even at ttl=0.

    A later independent lookup must still refetch, which
    test_zero_ttl_means_no_cache_reuse covers.
    """
    provider, client, _ = make_provider(
        [ok({"namespace": NAMESPACE, "ttl": 0, "subject": SUBJECT})],
        require_subject=True,
        timeout_seconds=2.0,
    )

    results: List[Optional[TenantEntry]] = []
    errors: List[Exception] = []
    started = threading.Event()

    def slow_boundary() -> None:
        started.set()
        # Hold the leader inside the GET so the follower must wait on the flight.
        threading.Event().wait(0.2)

    client.before_get = slow_boundary

    def worker() -> None:
        try:
            results.append(provider.lookup("key-a"))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    leader = threading.Thread(target=worker)
    leader.start()
    started.wait(1.0)
    follower = threading.Thread(target=worker)
    follower.start()
    leader.join(5)
    follower.join(5)

    assert not errors, f"unexpected errors: {errors}"
    assert len(results) == 2
    assert all(r is not None and r.subject == SUBJECT for r in results)
    # One network call served both.
    assert len(client.calls) == 1
