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

"""HTTP-based TenantProvider with per-key in-memory TTL cache.

Endpoint contract:
    GET {endpoint}
    Header: OPEN-SANDBOX-API-KEY: <api_key>

    200 OK:
        {
            "namespace": "ns-a",
            "ttl": 60
        }
        - namespace: target K8s namespace for this key
        - ttl: suggested cache duration in seconds

    401 Unauthorized:
        {
            "code": "UNAUTHORIZED",
            "message": "..."
        }

Cache strategy:
    - Per-key cache entry with server-suggested TTL
    - lookup hit + within TTL → return cached
    - lookup hit + TTL expired → sync GET → refresh or serve stale within max_stale
    - lookup miss → sync GET → 200: cache + return; 401: return None
    - Network failure + beyond max_stale → raise TenantProviderUnavailable
"""

from __future__ import annotations

import logging
import math
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

import httpx

from opensandbox_server.tenants.models import TenantEntry
from opensandbox_server.tenants.provider import TenantProviderUnavailable

logger = logging.getLogger(__name__)


# A suggested TTL is advice from the endpoint, not an instruction. Capping it
# bounds how long a revoked key keeps working if the endpoint ever answers with
# an implausible value.
MAX_TTL_SECONDS = 300.0


@dataclass
class HTTPTenantProviderConfig:
    endpoint: str
    max_stale_seconds: float = 300.0
    timeout_seconds: float = 5.0
    auth_header: Optional[str] = None
    auth_token: Optional[str] = None
    # Strict owner mode. When true the endpoint MUST name a subject, and this
    # provider fails closed rather than producing a namespace-only entry.
    # Default false keeps the legacy profile byte-identical.
    require_subject: bool = False


@dataclass
class _CacheEntry:
    tenant: TenantEntry
    fetched_at: float
    ttl: float


class _FlightEvent(threading.Event):
    """Event with attached result/error for singleflight propagation."""

    result: Optional[TenantEntry] = None
    error: Optional[Exception] = None


class HTTPTenantProvider:
    """TenantProvider backed by a remote HTTP endpoint with per-key TTL cache.

    Each lookup that misses or expires in cache triggers a sync GET to the
    remote endpoint. The server response includes a suggested TTL for caching.
    Uses per-key locks to prevent thundering herd on TTL expiry.
    """

    def __init__(self, config: HTTPTenantProviderConfig) -> None:
        self._config = config
        self._lock = threading.Lock()
        self._cache: Dict[str, _CacheEntry] = {}
        self._inflight: Dict[str, _FlightEvent] = {}
        self._ready = False
        self._callbacks: List[Callable[[List[TenantEntry]], None]] = []
        self._client: Optional[httpx.Client] = None
        # Injectable so cache and TTL behaviour can be asserted rather than
        # slept for.
        self._clock: Callable[[], float] = time.monotonic

    @property
    def supports_enumeration(self) -> bool:
        """The HTTP provider only knows tenants seen in prior per-key lookups."""
        return False

    def lookup(self, api_key: str) -> Optional[TenantEntry]:
        now = self._clock()

        with self._lock:
            cached = self._cache.get(api_key)

        if cached is not None:
            age = now - cached.fetched_at
            # A zero TTL means exactly that: no reuse, however fresh the entry.
            if (age < cached.ttl if self._config.require_subject else age <= cached.ttl):
                return cached.tenant

            # TTL expired — sync refresh
            try:
                return self._fetch_and_cache(api_key, now)
            except _Unauthorized:
                with self._lock:
                    self._cache.pop(api_key, None)
                return None
            except Exception:
                # ⚠ STRICT MODE NEVER SERVES STALE. max_stale_seconds exists to
                # ride out an outage on namespace-only tenancy; reusing an old
                # entry here would keep asserting an owner the endpoint can no
                # longer confirm, which is the revocation window this mode is
                # meant to close. Fail closed instead, regardless of the
                # configured stale window.
                if self._config.require_subject:
                    with self._lock:
                        self._cache.pop(api_key, None)
                    raise TenantProviderUnavailable(
                        "HTTP tenant endpoint unreachable and strict owner mode "
                        "refuses to serve a stale identity"
                    )
                if age > cached.ttl + self._config.max_stale_seconds:
                    raise TenantProviderUnavailable(
                        f"HTTP tenant endpoint unreachable and cache stale "
                        f"beyond {self._config.max_stale_seconds}s"
                    )
                logger.warning("HTTP tenant fetch failed, serving stale entry (age=%.1fs)", age)
                return cached.tenant

        # Cache miss — sync fetch
        try:
            return self._fetch_and_cache(api_key, now)
        except _Unauthorized:
            return None
        except TenantProviderUnavailable:
            raise
        except Exception as e:
            raise TenantProviderUnavailable("HTTP tenant endpoint unreachable") from e

    def list_tenants(self) -> List[TenantEntry]:
        with self._lock:
            seen = {}
            for entry in self._cache.values():
                seen[entry.tenant.name] = entry.tenant
            return list(seen.values())

    def ready(self) -> bool:
        return self._ready

    def start(self) -> None:
        if self._config.endpoint and not self._config.endpoint.startswith("https://"):
            logger.warning(
                "HTTP tenant endpoint is not HTTPS (%s). "
                "API keys will be transmitted in cleartext.",
                self._config.endpoint,
            )
        self._client = httpx.Client(timeout=self._config.timeout_seconds)
        self._ready = True
        logger.info("HTTP tenant provider started, endpoint=%s", self._config.endpoint)

    def close(self) -> None:
        with self._lock:
            self._cache.clear()
            self._ready = False
        if self._client:
            self._client.close()
            self._client = None

    def on_reload(self, callback: Callable[[List[TenantEntry]], None]) -> None:
        self._callbacks.append(callback)

    def _fetch_and_cache(self, api_key: str, now: float) -> Optional[TenantEntry]:
        """Singleflight GET: only one fetch per key at a time, others wait.

        Propagates leader result (entry or exception) to all waiters so
        provider outages / 5xx errors don't masquerade as invalid credentials.
        """
        with self._lock:
            flight = self._inflight.get(api_key)
            if flight is not None:
                is_leader = False
            else:
                flight = _FlightEvent()
                self._inflight[api_key] = flight
                is_leader = True

        if not is_leader:
            # ⚠ THE WAIT RESULT IS THE CONTRACT. The previous version discarded
            # it and read the cache, so a follower whose wait TIMED OUT could
            # return the very stale entry the leader was refreshing. A timeout
            # means we do not know the answer, which is unavailable, not a hit.
            completed = flight.wait(timeout=self._config.timeout_seconds)
            if not completed:
                raise TenantProviderUnavailable(
                    "Timed out waiting for in-flight tenant lookup"
                )
            if flight.error is not None:
                raise flight.error
            # The leader finished successfully: share its result directly rather
            # than re-reading the cache, so a ttl=0 fetch (which is not cached
            # for reuse) still serves its own followers.
            if flight.result is not None:
                return flight.result
            with self._lock:
                cached = self._cache.get(api_key)
            if cached is not None and cached.ttl > 0:
                return cached.tenant
            raise TenantProviderUnavailable("In-flight tenant lookup produced no result")

        try:
            result = self._do_fetch(api_key, now)
            flight.result = result
            return result
        except Exception as e:
            flight.error = e
            raise
        finally:
            with self._lock:
                self._inflight.pop(api_key, None)
            flight.set()

    def _do_fetch(self, api_key: str, now: float) -> Optional[TenantEntry]:
        """GET the endpoint for a single api_key. Returns TenantEntry or raises."""
        assert self._client is not None

        headers: Dict[str, str] = {"OPEN-SANDBOX-API-KEY": api_key}
        if self._config.auth_header and self._config.auth_token:
            headers[self._config.auth_header] = self._config.auth_token

        resp = self._client.get(self._config.endpoint, headers=headers)

        if resp.status_code == 401:
            raise _Unauthorized()

        resp.raise_for_status()

        try:
            data = resp.json()
        except Exception as exc:  # noqa: BLE001
            raise TenantProviderUnavailable(
                "HTTP tenant endpoint returned a body that is not JSON"
            ) from exc
        if not isinstance(data, dict):
            raise TenantProviderUnavailable(
                "HTTP tenant endpoint returned an unexpected document"
            )

        namespace = (data.get("namespace") or "").strip()
        if not namespace:
            raise ValueError("HTTP tenant endpoint returned empty namespace for key")

        ttl = (_coerce_ttl(data.get("ttl")) if self._config.require_subject else float(data.get("ttl", 30)))
        subject = _coerce_subject(data.get("subject"), self._config.require_subject)

        entry = TenantEntry(
            name=namespace,
            namespace=namespace,
            api_keys=(api_key,),
            subject=subject,
        )

        with self._lock:
            self._cache[api_key] = _CacheEntry(tenant=entry, fetched_at=now, ttl=ttl)

        return entry


def _coerce_ttl(raw: object) -> float:
    """Validate a suggested TTL.

    ⚠ `bool` IS AN `int` IN PYTHON, so `True` would otherwise become a 1-second
    TTL and `False` a zero one. A boolean is not a duration; it is a malformed
    answer and is refused.
    """
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise TenantProviderUnavailable("HTTP tenant endpoint returned a non-numeric ttl")
    value = float(raw)
    if math.isnan(value) or math.isinf(value):
        raise TenantProviderUnavailable("HTTP tenant endpoint returned a non-finite ttl")
    if value < 0:
        raise TenantProviderUnavailable("HTTP tenant endpoint returned a negative ttl")
    return min(value, MAX_TTL_SECONDS)


def _coerce_subject(raw: object, required: bool) -> Optional[str]:
    """Validate the authenticated subject.

    Returned exactly as received when usable: the value is opaque, and
    normalising it here would make this service the author of an identity it
    only carries.
    """
    if raw is None:
        if required:
            raise TenantProviderUnavailable(
                "strict owner mode requires a subject and the endpoint named none"
            )
        return None
    # A bool is an int, not a name.
    if isinstance(raw, bool) or not isinstance(raw, str):
        raise TenantProviderUnavailable(
            "HTTP tenant endpoint returned a subject that is not a string"
        )
    if not raw.strip():
        raise TenantProviderUnavailable("HTTP tenant endpoint returned a blank subject")
    return raw


class _Unauthorized(Exception):
    pass
