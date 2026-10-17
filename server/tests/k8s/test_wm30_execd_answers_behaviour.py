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
