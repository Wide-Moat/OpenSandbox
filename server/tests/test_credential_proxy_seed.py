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

"""WM-8: a create request's credentialProxy.seed is refused where it would be lost.

A seed is loaded by the egress sidecar of a sandbox with a networkPolicy and transparent
MITM, and nowhere else. Accepted anywhere else, the create is answered 201 and the
sandbox starts without the credential it was asked to start with, the reason in a
sidecar log line nobody reads -- or, without a networkPolicy, nowhere at all.

The requests are built from plain JSON, as a client sends them. On a tree without WM-8
the model ignores the field it does not know, so these tests still import and run
there, and fail on the answer: the request is accepted.
"""

import pytest
from pydantic import ValidationError

from opensandbox_server.api.schema import CreateSandboxRequest

SEED = {
    "credentials": [{"name": "k", "source": {"type": "inline", "value": "secret-value"}}],
    "bindings": [
        {
            "name": "b",
            "match": {"hosts": ["files.example.com"]},
            "auth": {"type": "bearer", "credential": "k"},
        }
    ],
}
POLICY = {"defaultAction": "deny", "egress": [{"action": "allow", "target": "files.example.com"}]}


def _request(**fields):
    body = {
        "image": {"uri": "python:3.11"},
        "entrypoint": ["python"],
        "resourceLimits": {},
        "timeout": 60,
    }
    body.update(fields)
    return CreateSandboxRequest.model_validate(body)


def test_wm8_a_seed_where_the_sidecar_loads_it_is_accepted_as_sent():
    # The positive control: without it, a validator refusing every seed would pass the
    # refusals below.
    request = _request(
        networkPolicy=POLICY, credentialProxy={"enabled": True, "seed": SEED}
    )
    dumped = request.model_dump(by_alias=True, exclude_none=True)["credentialProxy"]
    assert dumped.get("seed") == SEED


def test_wm8_a_seed_with_a_misspelt_key_is_refused_by_create():
    # The sidecar decodes a seed with the API's own strict decoder and refuses this one
    # -- after the sandbox has started, as a log line. Refused here, the caller hears.
    misspelt = {"credentials": SEED["credentials"], "bindngs": SEED["bindings"]}
    with pytest.raises(ValidationError):
        _request(networkPolicy=POLICY, credentialProxy={"enabled": True, "seed": misspelt})


def test_wm8_a_seed_without_the_credential_proxy_is_refused():
    # enabled false: the sidecar gets the seed but no transparent MITM, and refuses it.
    with pytest.raises(ValidationError, match="credentialProxy.seed requires credentialProxy.enabled"):
        _request(networkPolicy=POLICY, credentialProxy={"enabled": False, "seed": SEED})


def test_wm8_a_seed_without_a_network_policy_is_refused():
    # No networkPolicy: no sidecar is created at all, and the seed goes nowhere.
    with pytest.raises(ValidationError, match="credentialProxy.seed requires credentialProxy.enabled"):
        _request(credentialProxy={"seed": SEED})


def test_wm8_a_seed_with_a_pool_is_refused():
    # Pooled pods are created before the request exists, sidecar included.
    with pytest.raises(ValidationError, match="credentialProxy.seed cannot be used together with poolRef"):
        CreateSandboxRequest.model_validate(
            {
                "extensions": {"poolRef": "default/pool"},
                "timeout": 60,
                "credentialProxy": {"seed": SEED},
            }
        )
