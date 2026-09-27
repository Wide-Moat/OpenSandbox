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

"""WM-14: ``min_interval`` must throttle server-proxy renews when Redis is enabled too.

Ingress throttles its intents before it LPUSHes them, so the consumer renews every
Redis-sourced intent it pops. The server's own proxy has no such producer: it schedules
renew work on every ``/sandboxes/{id}/proxy/...`` hit, and ``min_interval`` is the only
throttle it has. The consumer applied it only when no Redis client was configured, so with
``[renew_intent.redis] enabled = true`` every proxied request became a renew. Measured on
a live installation: one sandbox renewed 39 times in a few minutes, several times a
second, each one a Kubernetes PATCH.

These tests drive the real pipeline -- ``submit_from_proxy``, the shared queue, all
processor tasks, a Redis BRPOP feeder over a fake client -- and count what reaches
``SandboxService.renew_expiration``, i.e. the PATCH.
"""

import asyncio
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import pytest_asyncio

from opensandbox_server.config import (
    AppConfig,
    RenewIntentConfig,
    RenewIntentRedisConfig,
    RuntimeConfig,
    ServerConfig,
)
from opensandbox_server.integrations.renew_intent import consumer as consumer_module
from opensandbox_server.integrations.renew_intent.consumer import RenewIntentConsumer

SANDBOX_ID = "sbx-proxied"
MIN_INTERVAL = 60


class _FakeRedis:
    """BRPOP over an in-memory list; blocks (briefly) when the list is empty."""

    def __init__(self) -> None:
        self.items: list[str] = []

    async def brpop(self, _key, _timeout):
        if self.items:
            return ("queue", self.items.pop())
        await asyncio.sleep(0.01)
        return None

    async def aclose(self) -> None:
        return None


class _Clock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def _app_config() -> AppConfig:
    return AppConfig(
        server=ServerConfig(),
        renew_intent=RenewIntentConfig(
            enabled=True,
            min_interval_seconds=MIN_INTERVAL,
            redis=RenewIntentRedisConfig(enabled=True, dsn="redis://fake:6379/0"),
        ),
        runtime=RuntimeConfig(type="docker", execd_image="opensandbox/execd:latest"),
    )


def _sandbox_service() -> MagicMock:
    """A running sandbox whose renew always succeeds; ``renew_expiration`` counts PATCHes."""
    svc = MagicMock()
    sandbox = MagicMock()
    sandbox.status.state = "Running"
    sandbox.expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    svc.get_sandbox.return_value = sandbox
    return svc


def _extension_service() -> MagicMock:
    ext = MagicMock()
    ext.get_access_renew_extend_seconds.return_value = 1800
    return ext


@pytest.fixture
def clock(monkeypatch) -> _Clock:
    # Replace the module's ``time``, not ``time.monotonic`` itself: the event loop reads
    # the same function, and a frozen clock would stop every ``asyncio.sleep`` here.
    c = _Clock(1000.0)
    monkeypatch.setattr(consumer_module, "time", SimpleNamespace(monotonic=c))
    return c


@pytest_asyncio.fixture
async def pipeline():
    """A consumer with Redis enabled (fake client), its feeders and processors running."""
    redis = _FakeRedis()
    svc = _sandbox_service()
    consumer = RenewIntentConsumer(_app_config(), svc, _extension_service(), redis_client=redis)
    assert consumer._processor_count > 1, "several processors, as in production"
    consumer._spawn_tasks()
    try:
        yield consumer, redis, svc
    finally:
        await consumer.stop()


async def _drain(consumer: RenewIntentConsumer, redis: _FakeRedis) -> None:
    for _ in range(500):
        if not redis.items:
            break
        await asyncio.sleep(0.01)
    assert not redis.items, "the feeders never popped the fake queue"
    # submit_from_proxy enqueues from a task of its own; let those run first.
    await asyncio.sleep(0.05)
    await asyncio.wait_for(consumer._work_queue.join(), timeout=10)


def _intent_json(sandbox_id: str) -> str:
    return json.dumps(
        {
            "sandbox_id": sandbox_id,
            "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "port": 8080,
            "request_uri": "/",
        }
    )


@pytest.mark.asyncio
async def test_wm14_proxy_hits_within_min_interval_renew_once_with_redis_enabled(
    pipeline, clock
):
    consumer, redis, svc = pipeline

    for _ in range(40):
        consumer.submit_from_proxy(SANDBOX_ID)
    await _drain(consumer, redis)
    assert svc.renew_expiration.call_count == 1

    # Still inside the window: nothing more.
    clock.now += MIN_INTERVAL - 1
    for _ in range(10):
        consumer.submit_from_proxy(SANDBOX_ID)
    await _drain(consumer, redis)
    assert svc.renew_expiration.call_count == 1

    # Past it: exactly one more.
    clock.now += 2
    for _ in range(10):
        consumer.submit_from_proxy(SANDBOX_ID)
    await _drain(consumer, redis)
    assert svc.renew_expiration.call_count == 2


@pytest.mark.asyncio
async def test_wm14_proxy_throttle_is_per_sandbox_with_redis_enabled(pipeline, clock):
    consumer, redis, svc = pipeline

    for _ in range(10):
        consumer.submit_from_proxy("sbx-a")
        consumer.submit_from_proxy("sbx-b")
    await _drain(consumer, redis)
    renewed = sorted(c.args[0] for c in svc.renew_expiration.call_args_list)
    assert renewed == ["sbx-a", "sbx-b"]


@pytest.mark.asyncio
async def test_wm14_redis_intents_are_still_renewed_each_time(pipeline, clock):
    consumer, redis, svc = pipeline

    # Ingress already throttled these before LPUSH; the consumer renews every one.
    redis.items.extend(_intent_json(SANDBOX_ID) for _ in range(5))
    await _drain(consumer, redis)
    assert svc.renew_expiration.call_count == 5
    assert svc.get_sandbox.call_count == 5
