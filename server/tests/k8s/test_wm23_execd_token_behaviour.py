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

"""WM-23 behaviour, written with nothing upstream lacks, so it FAILS there rather than not building.

String literals stand for the new constants on purpose: hack/wm-fail-on-base.sh requires a
change to keep a test that fails against unmodified upstream on behaviour, and an
ImportError is not behaviour. Upstream creates the same sandbox with no execd token and
resolves the execd endpoint with no header -- both assertions below fail there.
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from opensandbox_server.api.schema import Endpoint

TOKEN_ENV = "EXECD_ACCESS_TOKEN"
TOKEN_ANNOTATION = "opensandbox.io/execd-access-token"
TOKEN_HEADER = "X-EXECD-ACCESS-TOKEN"
EXECD_PORT = 44772


def _running(k8s_service):
    k8s_service.workload_provider.create_workload.return_value = {"name": "test-id", "uid": "uid-1"}
    k8s_service.workload_provider.get_workload.return_value = MagicMock()
    k8s_service.workload_provider.get_status.return_value = {
        "state": "Running", "reason": "", "message": "",
        "last_transition_at": datetime.now(timezone.utc),
    }


@pytest.mark.asyncio
async def test_wm23_a_default_create_gives_execd_a_token(k8s_service, create_sandbox_request):
    _running(k8s_service)
    await k8s_service.create_sandbox(create_sandbox_request)
    _, kwargs = k8s_service.workload_provider.create_workload.call_args
    token = (kwargs["env"] or {}).get(TOKEN_ENV)
    assert token and len(token) >= 32
    assert (kwargs["annotations"] or {}).get(TOKEN_ANNOTATION) == token


def test_wm23_the_execd_endpoint_carries_the_sandboxs_token(k8s_service):
    k8s_service.workload_provider.get_workload.return_value = {
        "metadata": {"annotations": {TOKEN_ANNOTATION: "execd-token"}}
    }
    k8s_service.workload_provider.get_internal_endpoint.return_value = Endpoint(endpoint="10.0.0.1:44772")
    endpoint = k8s_service.get_endpoint("sbx-1", EXECD_PORT, resolve_internal=True)
    assert (endpoint.headers or {}).get(TOKEN_HEADER) == "execd-token"


@pytest.mark.asyncio
async def test_wm23_switched_off_no_token_is_issued(k8s_service, create_sandbox_request):
    # A GUARD (hack/wm-fail-on-base.sh is_guard): switched off is upstream's behaviour, so
    # it must pass there too. model_copy rather than an attribute write, because upstream's
    # RuntimeConfig has no such field and pydantic refuses to set one -- which would read as
    # a failure on upstream for a reason that is not behaviour.
    runtime = k8s_service.app_config.runtime
    k8s_service.app_config.runtime = runtime.model_copy(update={"execd_access_token": False})
    _running(k8s_service)
    await k8s_service.create_sandbox(create_sandbox_request)
    _, kwargs = k8s_service.workload_provider.create_workload.call_args
    assert TOKEN_ENV not in (kwargs["env"] or {})
    assert TOKEN_ANNOTATION not in (kwargs["annotations"] or {})
