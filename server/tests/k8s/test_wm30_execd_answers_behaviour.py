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

"""WM-30: a create answers when execd answers, not when the pod is reported Running.

Written with nothing upstream lacks, so it FAILS there rather than not building: the option
is set through AppConfig.model_validate (upstream ignores an unknown key) and execd is an
httpx transport. Upstream returns at the first Running/Allocated status without asking
execd at all, so the create answers while execd still refuses connections.
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import httpx
import pytest

from opensandbox_server.config import AppConfig

_ORIGINAL_CLIENT = httpx.AsyncClient
POD_IP = "10.42.1.7"


def _config():
    return AppConfig.model_validate(
        {
            "server": {"host": "0.0.0.0", "port": 8080, "api_key": "test-api-key"},
            "runtime": {"type": "kubernetes", "execd_image": "ghcr.io/opensandbox/execd:test"},
            "kubernetes": {
                "kubeconfig_path": "/tmp/test-kubeconfig",
                "namespace": "ns",
                "workload_provider": "batchsandbox",
                "wait_for_execd": True,
            },
        }
    )


def _service():
    with patch("opensandbox_server.services.k8s.kubernetes_service.K8sClient"), patch(
        "opensandbox_server.services.k8s.kubernetes_service.create_workload_provider"
    ) as factory:
        provider = MagicMock()
        factory.return_value = provider
        from opensandbox_server.services.k8s.kubernetes_service import KubernetesSandboxService

        service = KubernetesSandboxService(_config())
    provider.subscribe_workload.side_effect = Exception("no informer in this test")
    provider.get_workload.return_value = {
        "metadata": {"name": "sbx", "uid": "u", "annotations": {"sandbox.opensandbox.io/endpoints": f'["{POD_IP}"]'}},
        "status": {"replicas": 1, "ready": 0, "allocated": 1},
    }
    provider._parse_pod_ip.return_value = POD_IP
    provider.get_status.return_value = {
        "state": "Allocated",
        "reason": "IP_ASSIGNED",
        "message": "Pod has IP assigned but not ready",
        "last_transition_at": datetime.now(timezone.utc),
    }
    service.workload_provider = provider
    service._resolve_namespace = lambda: "ns"
    return service


@pytest.mark.asyncio
async def test_wm30_the_create_waits_until_execd_answers():
    pings = []

    def handler(request: httpx.Request) -> httpx.Response:
        pings.append((request.url.host, request.url.port, request.url.path))
        if len(pings) < 3:
            raise httpx.ConnectError("connection refused", request=request)
        return httpx.Response(200, text="pong")

    def client_factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return _ORIGINAL_CLIENT(*args, **kwargs)

    service = _service()
    with patch("httpx.AsyncClient", side_effect=client_factory):
        workload = await service._wait_for_sandbox_ready("sbx", timeout_seconds=5, poll_interval_seconds=0.2)

    assert workload is not None
    assert pings == [(POD_IP, 44772, "/ping")] * 3, "answered before execd did"


@pytest.mark.asyncio
async def test_wm30_execd_that_never_answers_is_a_timeout_not_a_sandbox():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    def client_factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return _ORIGINAL_CLIENT(*args, **kwargs)

    service = _service()
    from fastapi import HTTPException

    with patch("httpx.AsyncClient", side_effect=client_factory):
        with pytest.raises(HTTPException) as refused:
            await service._wait_for_sandbox_ready("sbx", timeout_seconds=1, poll_interval_seconds=0.2)
    assert refused.value.status_code == 504


def _cold_batchsandbox_service(get_calls):
    """A cold BatchSandbox as the controller writes it while the pod starts: phase Pending,
    one allocated, the pod's address already published -- read through the REAL
    BatchSandboxProvider.get_status, which is what decides the state the wait loop sees."""
    from opensandbox_server.services.k8s.batchsandbox_provider import BatchSandboxProvider

    service = _service()
    real = object.__new__(BatchSandboxProvider)
    workload = {
        "metadata": {
            "name": "sbx",
            "uid": "u",
            "annotations": {"sandbox.opensandbox.io/endpoints": f'["{POD_IP}"]'},
        },
        "status": {
            "phase": "Pending",
            "replicas": 1,
            "ready": 0,
            "allocated": 1,
            "conditions": [{"type": "Progressing", "status": "True", "reason": "Creating"}],
        },
    }

    def get_workload(**kwargs):
        get_calls.append(kwargs)
        return workload

    service.workload_provider.get_workload.side_effect = get_workload
    service.workload_provider.get_status.side_effect = lambda w: BatchSandboxProvider.get_status(real, w)
    service.workload_provider._parse_pod_ip.side_effect = lambda w: BatchSandboxProvider._parse_pod_ip(real, w)
    return service


@pytest.mark.asyncio
async def test_wm32_a_cold_batchsandbox_is_asked_once_its_pod_has_an_address():
    """Before WM-32, WM-30 asked execd only from Running/Allocated -- and a cold BatchSandbox is
    never Allocated: its phase is Pending until the pod is Ready, so the create waited for
    Ready after all and this test ran into its 504."""
    pings = []

    def handler(request: httpx.Request) -> httpx.Response:
        pings.append(request.url.path)
        return httpx.Response(200, text="pong")

    def client_factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return _ORIGINAL_CLIENT(*args, **kwargs)

    get_calls = []
    service = _cold_batchsandbox_service(get_calls)
    assert service.workload_provider.get_status(service.workload_provider.get_workload())["state"] == "Pending"
    with patch("httpx.AsyncClient", side_effect=client_factory):
        workload = await service._wait_for_sandbox_ready("sbx", timeout_seconds=2, poll_interval_seconds=0.2)

    assert workload is not None
    assert pings and pings[0] == "/ping"


@pytest.mark.asyncio
async def test_wm32_probing_rereads_the_workload_once_per_poll_interval_not_every_50ms():
    """Execd refuses for the whole second: the probe runs every 50 ms (about 20 times), but
    the workload is read about once per 0.2 s poll interval (about 5 times), not once per probe."""
    pings = []

    def handler(request: httpx.Request) -> httpx.Response:
        pings.append(request.url.path)
        raise httpx.ConnectError("connection refused", request=request)

    def client_factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return _ORIGINAL_CLIENT(*args, **kwargs)

    get_calls = []
    service = _cold_batchsandbox_service(get_calls)
    from fastapi import HTTPException

    with patch("httpx.AsyncClient", side_effect=client_factory):
        with pytest.raises(HTTPException) as refused:
            await service._wait_for_sandbox_ready("sbx", timeout_seconds=1, poll_interval_seconds=0.2)
    assert refused.value.status_code == 504
    assert len(pings) >= 10, f"execd was asked only {len(pings)} times in a second"
    assert len(get_calls) <= 8, f"the workload was read {len(get_calls)} times for {len(pings)} probes"


@pytest.mark.asyncio
async def test_wm32_a_pending_batchsandbox_without_an_address_is_not_asked():
    """The guard: no address, no probe -- the loop waits on the controller as before."""
    pings = []

    def handler(request: httpx.Request) -> httpx.Response:
        pings.append(request.url.path)
        return httpx.Response(200, text="pong")

    def client_factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return _ORIGINAL_CLIENT(*args, **kwargs)

    get_calls = []
    service = _cold_batchsandbox_service(get_calls)
    wl = service.workload_provider.get_workload()
    wl["metadata"]["annotations"] = {}
    get_calls.clear()
    from fastapi import HTTPException

    with patch("httpx.AsyncClient", side_effect=client_factory):
        with pytest.raises(HTTPException):
            await service._wait_for_sandbox_ready("sbx", timeout_seconds=1, poll_interval_seconds=0.2)
    assert pings == []
