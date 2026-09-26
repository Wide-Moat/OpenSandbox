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

"""WM-2 and WM-8 from the configuration and the request to the submitted pod.

The unit tests hand each piece its input directly: ``apply_egress_to_spec`` a settings
object, each validator an ``egress_config``. Nothing there notices when the wiring
between them is lost -- ``create_helpers`` not copying a field, the service or a
provider not passing ``egress_config`` on -- which is what a rebase drops silently.
These tests go through ``create_sandbox`` with a real provider rendering into a mocked
cluster, and read the workload it submits.

Every configuration value here is passed by keyword to a pydantic model, which ignores
a field it does not know. On a tree without WM-2 or WM-8 the tests therefore build and
fail on the answer: the create is refused, or the pod lacks what it should carry.
"""

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from opensandbox_server.api.schema import CredentialProxyConfig, NetworkPolicy, NetworkRule
from opensandbox_server.config import EgressConfig, SecureRuntimeConfig
from opensandbox_server.services.k8s.agent_sandbox_provider import AgentSandboxProvider
from opensandbox_server.services.k8s.batchsandbox_provider import BatchSandboxProvider

# Literal names, not the imported constants: a tree without the change must still
# import this file and fail on what the pod carries.
_ENFORCEMENT_ENV = "OPENSANDBOX_EGRESS_ENFORCEMENT"
_SEED_ENV = "OPENSANDBOX_EGRESS_CREDENTIAL_VAULT_SEED"


def _gvisor_with_external_enforcement(service):
    """gVisor, and egress enforced by the CNI -- with disable_ipv6 off, which external
    enforcement requires and a deployment under it has to set."""
    service.app_config.egress = EgressConfig(
        image="opensandbox/egress:test", mode="dns", enforcement="external", disable_ipv6=False
    )
    service.app_config.secure_runtime = SecureRuntimeConfig(
        type="gvisor", k8s_runtime_class="gvisor"
    )


async def _create(service, provider, request):
    """create_sandbox, with ``provider`` rendering the workload into a mocked cluster."""
    wrapper = MagicMock()
    wrapper.create_workload.side_effect = provider.create_workload
    wrapper.get_workload.return_value = MagicMock()
    wrapper.get_status.return_value = {
        "state": "Running",
        "reason": "",
        "message": "",
        "last_transition_at": datetime.now(timezone.utc),
    }
    service.workload_provider = wrapper
    with patch(
        "opensandbox_server.services.k8s.kubernetes_service.generate_egress_token",
        return_value="egress-token",
    ):
        try:
            await service.create_sandbox(request)
        except HTTPException as exc:
            pytest.fail(f"create was refused: {exc.status_code} {exc.detail}")
    return provider.k8s_client.create_custom_object.call_args.kwargs["body"]


def _containers(pod_spec):
    by_name = {c["name"]: c for c in pod_spec["containers"]}
    return by_name["egress"], by_name["sandbox"]


def _env(container):
    return {e["name"]: e.get("value") for e in container.get("env", [])}


def _assert_external_sidecar(pod_spec):
    assert pod_spec.get("runtimeClassName") == "gvisor"
    sidecar, _ = _containers(pod_spec)
    assert _env(sidecar).get(_ENFORCEMENT_ENV) == "external", (
        "the sidecar was not told enforcement is external, so it installs redirects and "
        "crash-loops on the netfilter gVisor does not have"
    )
    # The reason for WM-2: nothing in the pod is privileged or asks for a capability --
    # not the sidecar, and not an init container either (disable_ipv6 would add one).
    for container in pod_spec.get("initContainers", []) + pod_spec["containers"]:
        context = container.get("securityContext") or {}
        assert not context.get("privileged"), f"{container['name']} is privileged"
        added = (context.get("capabilities") or {}).get("add") or []
        assert added == [], f"{container['name']} asks for capabilities: {added}"


@pytest.mark.asyncio
async def test_wm2_external_enforcement_reaches_the_batchsandbox_pod(
    k8s_service, create_sandbox_request, mock_k8s_client
):
    _gvisor_with_external_enforcement(k8s_service)
    create_sandbox_request.network_policy = NetworkPolicy(default_action="deny", egress=[])
    provider = BatchSandboxProvider(mock_k8s_client, k8s_service.app_config)

    body = await _create(k8s_service, provider, create_sandbox_request)

    _assert_external_sidecar(body["spec"]["template"]["spec"])


@pytest.mark.asyncio
async def test_wm2_external_enforcement_reaches_the_agent_sandbox_pod(
    k8s_service, create_sandbox_request, mock_k8s_client
):
    _gvisor_with_external_enforcement(k8s_service)
    create_sandbox_request.network_policy = NetworkPolicy(default_action="deny", egress=[])
    provider = AgentSandboxProvider(mock_k8s_client, k8s_service.app_config)

    body = await _create(k8s_service, provider, create_sandbox_request)

    _assert_external_sidecar(body["spec"]["podTemplate"]["spec"])


@pytest.mark.asyncio
async def test_wm8_seed_reaches_the_sidecar_through_create(
    k8s_service, create_sandbox_request, mock_k8s_client
):
    """credentialProxy.seed from the request ends up on the sidecar, and only there.

    Sidecar enforcement with dns+nft, the credential proxy's own requirement, so this
    exercises WM-8 alone.
    """
    k8s_service.app_config.egress = EgressConfig(image="opensandbox/egress:test", mode="dns+nft")
    seed = {
        "credentials": [{"name": "k", "source": {"type": "inline", "value": "s3cret-value"}}],
        "bindings": [],
    }
    create_sandbox_request.network_policy = NetworkPolicy(
        default_action="deny",
        egress=[NetworkRule(action="allow", target="files.example.com")],
    )
    create_sandbox_request.credential_proxy = CredentialProxyConfig(enabled=True, seed=seed)
    provider = BatchSandboxProvider(mock_k8s_client, k8s_service.app_config)

    body = await _create(k8s_service, provider, create_sandbox_request)

    sidecar, sandbox = _containers(body["spec"]["template"]["spec"])
    sidecar_env = _env(sidecar)
    assert _SEED_ENV in sidecar_env, f"the sidecar was not given the seed: {sorted(sidecar_env)}"
    assert json.loads(sidecar_env[_SEED_ENV]) == seed
    assert "s3cret-value" not in json.dumps(sandbox), "the sandbox container can read the credential"
