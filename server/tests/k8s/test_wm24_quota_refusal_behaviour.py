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

"""WM-24 behaviour, written with nothing upstream lacks, so it FAILS there rather than not building.

hack/wm-fail-on-base.sh requires a change to keep a test that fails against unmodified upstream
on behaviour, and an AttributeError is not behaviour: the provider's new method is looked up with
a default that answers what upstream answers -- no refusal. Upstream finds no refusal in the
BatchSandbox's FailedCreate Event, and its readiness wait runs out its budget (504) where this
fork answers 403 at once. The guards (stale Events, other FailedCreates, the marker inside the
pod spec, unreadable Events) are beside the other provider and service tests.
"""

import time
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from opensandbox_server.services.k8s.batchsandbox_provider import BatchSandboxProvider

QUOTA_EVENT = (
    'failed to create pod: pods "sbx-0" is forbidden: exceeded quota: sandbox-quota, '
    "requested: limits.memory=2688Mi, used: limits.memory=32256Mi, limited: limits.memory=34Gi, "
    'pod: {"metadata":{"name":"sbx-0"},"spec":{"containers":[]}}'
)


def test_wm24_the_refusal_is_read_from_the_quota_failed_create_event():
    client = MagicMock()
    client.list_events.return_value = [SimpleNamespace(message=QUOTA_EVENT)]
    client.read_pod.return_value = None
    provider = BatchSandboxProvider(client)
    workload = {
        "status": {"replicas": 1, "ready": 0, "allocated": 0},
        "metadata": {"namespace": "sbx-ns", "name": "sbx", "uid": "uid-1"},
    }

    refusal = getattr(provider, "pod_admission_refusal", lambda _workload: None)(workload)

    assert refusal is not None and "exceeded quota: sandbox-quota" in refusal
    assert ", pod:" not in refusal  # the controller's pod dump is cut off
    client.list_events.assert_called_once_with(
        namespace="sbx-ns", field_selector="involvedObject.uid=uid-1,reason=FailedCreate"
    )


@pytest.mark.asyncio
async def test_wm24_the_wait_fails_fast_on_a_batchsandbox_quota_refusal(k8s_service):
    k8s_service.workload_provider.get_workload.return_value = MagicMock()
    k8s_service.workload_provider.get_status.return_value = {
        "state": "Pending",
        "reason": "BATCHSANDBOX_PENDING",
        "message": "BatchSandbox is pending allocation",
        "last_transition_at": datetime.now(timezone.utc),
    }
    k8s_service.workload_provider.pod_admission_refusal.return_value = QUOTA_EVENT.split(", pod: ")[0]

    started = time.monotonic()
    with pytest.raises(HTTPException) as exc_info:
        await k8s_service._wait_for_sandbox_ready(
            "test-sandbox-id",
            timeout_seconds=3,
            poll_interval_seconds=0.1,
        )

    assert exc_info.value.status_code == 403  # upstream: 504, after the whole budget
    assert exc_info.value.detail["code"] == "KUBERNETES::QUOTA_EXCEEDED"
    assert time.monotonic() - started < 2
