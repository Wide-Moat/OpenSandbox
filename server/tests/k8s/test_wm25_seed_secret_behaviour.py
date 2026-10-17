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

"""WM-25: on Kubernetes the credential-vault seed lives in a Secret, never in a spec.

Anyone who may `get pods` or `get batchsandboxes` in the sandbox namespace reads every
plain-text env value of every sandbox. A seed holds a person's credentials, so it goes
into a per-sandbox Secret owned by the workload, and the sidecar reads it through
`valueFrom.secretKeyRef`.

Written with nothing upstream lacks, so it FAILS there rather than not building: the
seed is passed by keyword to a pydantic model, which ignores a field it does not know,
and the first assertion is that a Secret holding it was created -- upstream creates none.
On a tree with WM-8 but not this change the Secret is missing and the value sits in the
workload body, which is the defect itself.
"""

import base64
import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from opensandbox_server.api.schema import CredentialProxyConfig, NetworkPolicy, NetworkRule
from opensandbox_server.config import EgressConfig
from opensandbox_server.services.k8s.agent_sandbox_provider import AgentSandboxProvider
from opensandbox_server.services.k8s.batchsandbox_provider import BatchSandboxProvider

_SEED_ENV = "OPENSANDBOX_EGRESS_CREDENTIAL_VAULT_SEED"
_SECRET_VALUE = "sk-person-gateway-key-0123456789"
_SEED = {
    "credentials": [{"name": "gw", "source": {"type": "inline", "value": _SECRET_VALUE}}],
    "bindings": [
        {
            "name": "gw",
            "match": {"hosts": ["gateway.example.com"]},
            "auth": {"type": "bearer", "credential": "gw"},
        }
    ],
}


def _seeded_request(service, request):
    service.app_config.egress = EgressConfig(image="opensandbox/egress:test", mode="dns+nft")
    request.network_policy = NetworkPolicy(
        default_action="deny",
        egress=[NetworkRule(action="allow", target="gateway.example.com")],
    )
    request.credential_proxy = CredentialProxyConfig(enabled=True, seed=_SEED)
    return request


def _install(service, provider):
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


async def _create(service, provider, request):
    _install(service, provider)
    with patch(
        "opensandbox_server.services.k8s.kubernetes_service.generate_egress_token",
        return_value="egress-token",
    ):
        try:
            await service.create_sandbox(request)
        except HTTPException as exc:
            pytest.fail(f"create was refused: {exc.status_code} {exc.detail}")
    return provider.k8s_client.create_custom_object.call_args.kwargs["body"]


def _to_dict(obj):
    if isinstance(obj, dict):
        return obj
    return obj.to_dict()


def _seed_secrets(k8s_client):
    """Every Secret the provider created whose data decodes to something holding the seed."""
    found = []
    for call in k8s_client.create_secret.call_args_list:
        body = _to_dict(call.kwargs.get("body", call.args[-1] if call.args else None))
        data = body.get("data") or {}
        for key, value in data.items():
            decoded = base64.b64decode(value).decode()
            if _SECRET_VALUE in decoded:
                found.append((body, key, decoded))
    return found


def _assert_seed_only_in_a_secret(k8s_client, workload, pod_spec, owner_kind):
    # The defect: the value must appear nowhere in what `get pods` / `get <workload>` shows.
    # Alone this passes upstream, where there is no seed at all -- the Secret below is what
    # makes it fail there.
    rendered = json.dumps(workload)
    assert _SECRET_VALUE not in rendered, "the seed is readable in the workload spec"

    secrets = _seed_secrets(k8s_client)
    assert len(secrets) == 1, (
        f"expected exactly one Secret holding the seed, found {len(secrets)} "
        f"(create_secret calls: {k8s_client.create_secret.call_count})"
    )
    secret, key, decoded = secrets[0]
    assert json.loads(decoded) == _SEED

    sidecar = next(c for c in pod_spec["containers"] if c["name"] == "egress")
    entries = [e for e in sidecar.get("env", []) if e["name"] == _SEED_ENV]
    assert len(entries) == 1, f"the sidecar names the seed {len(entries)} times"
    entry = entries[0]
    assert "value" not in entry
    ref = entry["valueFrom"]["secretKeyRef"]
    meta = secret["metadata"]
    assert ref["name"] == meta["name"] and ref["key"] == key

    # Owned by the workload, so it goes when the workload goes.
    owners = meta.get("owner_references") or meta.get("ownerReferences") or []
    assert len(owners) == 1
    owner = owners[0]
    assert owner.get("kind") == owner_kind
    assert owner.get("uid") == "uid"


@pytest.mark.asyncio
async def test_wm25_the_seed_reaches_the_batchsandbox_only_through_a_secret(
    k8s_service, create_sandbox_request, mock_k8s_client
):
    request = _seeded_request(k8s_service, create_sandbox_request)
    provider = BatchSandboxProvider(mock_k8s_client, k8s_service.app_config)

    body = await _create(k8s_service, provider, request)

    _assert_seed_only_in_a_secret(
        mock_k8s_client, body, body["spec"]["template"]["spec"], "BatchSandbox"
    )


@pytest.mark.asyncio
async def test_wm25_the_seed_reaches_the_agent_sandbox_only_through_a_secret(
    k8s_service, create_sandbox_request, mock_k8s_client
):
    request = _seeded_request(k8s_service, create_sandbox_request)
    provider = AgentSandboxProvider(mock_k8s_client, k8s_service.app_config)

    body = await _create(k8s_service, provider, request)

    _assert_seed_only_in_a_secret(
        mock_k8s_client, body, body["spec"]["podTemplate"]["spec"], "Sandbox"
    )


@pytest.mark.asyncio
async def test_wm25_a_seed_secret_that_cannot_be_created_rolls_the_workload_back(
    k8s_service, create_sandbox_request, mock_k8s_client
):
    """A workload left behind without its Secret would sit in CreateContainerConfigError
    until it expired, holding its quota. The create is refused and the workload deleted."""
    request = _seeded_request(k8s_service, create_sandbox_request)
    provider = BatchSandboxProvider(mock_k8s_client, k8s_service.app_config)
    mock_k8s_client.create_secret.side_effect = RuntimeError("secrets is forbidden")
    _install(k8s_service, provider)

    with pytest.raises(HTTPException):
        await k8s_service.create_sandbox(request)

    assert mock_k8s_client.create_secret.called, "no Secret was attempted for the seed"
    assert mock_k8s_client.delete_custom_object.called, "the workload was left behind"
