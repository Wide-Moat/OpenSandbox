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

"""A sandbox must not be Ready before its agent can answer (WM-10).

The create path returns to the caller once the workload reports Running, and
Running for a BatchSandbox means PodsReady. With no probe the kubelet has nothing
to ask, so a pod is Ready as soon as its process starts -- before execd listens.

The numbers are asserted as literals. Compared with the values on the object under
test, the kubelet's defaults (every 10 s, for the startup probe too) would pass.
And the probes are asserted on the pod the providers SUBMIT, not only on the
container object: between the two sit the serialiser, the template merge and the
Windows profile, and each of them can drop a field without a word.
"""

from unittest.mock import MagicMock

import pytest

from opensandbox_server.api.schema import ImageSpec, PlatformSpec
from opensandbox_server.services.k8s.agent_sandbox_provider import AgentSandboxProvider
from opensandbox_server.services.k8s.batchsandbox_provider import BatchSandboxProvider
from opensandbox_server.services.k8s.provider_common import (
    _build_main_container,
    _container_to_dict,
)

# What the pod must carry, as the kubelet reads it.
STARTUP_PROBE = {
    "httpGet": {"path": "/ping", "port": 44772},
    "periodSeconds": 1,
    "failureThreshold": 600,
}
READINESS_PROBE = {
    "httpGet": {"path": "/ping", "port": 44772},
    "periodSeconds": 10,
    "failureThreshold": 3,
}


def _container():
    return _build_main_container(
        image_spec=ImageSpec(uri="example.invalid/image@sha256:" + "0" * 64),
        entrypoint=["sleep", "30"],
        env={},
        resource_limits={"cpu": "250m", "memory": "512Mi"},
    )


def _submitted_sandbox_container(
    provider_class, *, platform=None, image="python:3.11", resource_limits=None
):
    """The sandbox container of the workload body a provider sends to the API server."""
    client = MagicMock()
    client.create_custom_object.return_value = {"metadata": {"name": "t", "uid": "u"}}
    provider = provider_class(client)
    kwargs = {"platform": platform} if platform is not None else {}
    provider.create_workload(
        sandbox_id="t",
        namespace="ns",
        image_spec=ImageSpec(uri=image),
        entrypoint=["sleep", "30"],
        env={},
        resource_limits=resource_limits or {"cpu": "1", "memory": "1Gi"},
        labels={"opensandbox.io/id": "t"},
        expires_at=None,
        execd_image="execd:latest",
        **kwargs,
    )
    body = client.create_custom_object.call_args.kwargs["body"]
    spec = body["spec"]
    pod_spec = (spec.get("template") or spec.get("podTemplate"))["spec"]
    return pod_spec["containers"][0]


def test_wm10_the_sandbox_container_asks_execd_before_it_is_ready():
    container = _container()
    assert container.startup_probe is not None, "a sandbox with no probe is Ready before execd is"
    assert container.readiness_probe is not None, "a Ready sandbox whose execd died stays Ready"
    for probe in (container.startup_probe, container.readiness_probe):
        assert probe.http_get.path == "/ping"
        assert probe.http_get.port == 44772
    assert (container.startup_probe.period_seconds, container.startup_probe.failure_threshold) == (1, 600)
    assert (container.readiness_probe.period_seconds, container.readiness_probe.failure_threshold) == (10, 3)


def test_wm10_the_probes_survive_serialisation_into_the_pod_spec():
    # ⚠ Building a probe and serialising it are two separate changes. _container_to_dict
    # writes the pod spec field by field, so a probe it does not name is a silent no-op:
    # the source reads as fixed and the rendered pod carries no probe at all.
    serialised = _container_to_dict(_container())
    assert serialised.get("startupProbe") == STARTUP_PROBE
    assert serialised.get("readinessProbe") == READINESS_PROBE


@pytest.mark.parametrize("provider_class", [BatchSandboxProvider, AgentSandboxProvider])
def test_wm10_the_submitted_pod_carries_the_probes(provider_class):
    sandbox = _submitted_sandbox_container(provider_class)
    assert sandbox.get("startupProbe") == STARTUP_PROBE
    assert sandbox.get("readinessProbe") == READINESS_PROBE


def test_wm10_a_windows_pod_carries_no_execd_probe():
    # The guard. execd runs inside the Windows guest, which answers only after Windows
    # has booted or installed -- far past the create timeout. With the probes kept, every
    # default Windows create would be rolled back. Upstream has no probe, so this holds
    # there too, and must keep holding here.
    sandbox = _submitted_sandbox_container(
        BatchSandboxProvider,
        platform=PlatformSpec(os="windows", arch="amd64"),
        image="dockurr/windows:latest",
        resource_limits={"cpu": "4", "memory": "8G", "disk": "64G"},
    )
    assert "startupProbe" not in sandbox
    assert "readinessProbe" not in sandbox


def test_wm10_serialised_probe_is_absent_when_the_container_has_none():
    # The negative control. Without it the serialiser could unconditionally emit a
    # probe and the tests above would still pass.
    container = _container()
    container.startup_probe = None
    container.readiness_probe = None
    serialised = _container_to_dict(container)
    assert "startupProbe" not in serialised
    assert "readinessProbe" not in serialised
