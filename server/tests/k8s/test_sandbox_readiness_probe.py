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

"""A sandbox must not be Ready before its agent can answer.

The create path returns to the caller once the workload reports Running, and
Running for a BatchSandbox means PodsReady. With no probe the kubelet has nothing
to ask, so a pod is Ready as soon as its process starts -- before execd listens.

These tests are deliberately about the SERIALISED pod, not the V1Container object.
`_container_to_dict` writes the pod spec field by field, so a probe that is built
correctly and not serialised is a silent no-op: the source reads as fixed and the
rendered pod carries no probe at all.
"""

from opensandbox_server.api.schema import ImageSpec
from opensandbox_server.services.k8s.provider_common import (
    _build_main_container,
    _container_to_dict,
)

EXECD_PORT = 44772


def _container():
    return _build_main_container(
        image_spec=ImageSpec(uri="example.invalid/image@sha256:" + "0" * 64),
        entrypoint=["sleep", "30"],
        env={},
        resource_limits={"cpu": "250m", "memory": "512Mi"},
    )


def test_sandbox_container_declares_a_readiness_probe():
    probe = _container().readiness_probe
    assert probe is not None, "a sandbox with no probe is Ready before execd is"
    assert probe.http_get.path == "/ping"
    assert probe.http_get.port == EXECD_PORT


def test_probe_survives_serialisation_into_the_pod_spec():
    # ⚠ THE ASSERTION THAT MATTERS. Building the probe and serialising it are two
    # separate changes; this is the one that fails if only the first was made.
    serialised = _container_to_dict(_container())
    assert "readinessProbe" in serialised, (
        "the probe was built but never written into the pod spec -- "
        "_container_to_dict serialises by hand and drops fields it does not name"
    )
    assert serialised["readinessProbe"]["httpGet"] == {
        "path": "/ping",
        "port": EXECD_PORT,
    }


def test_probe_allows_a_full_minute_before_giving_up():
    # execd comes up in about 5 s; the headroom is for a cold node. Asserting the
    # product rather than each field so a 2 s period with 30 failures is equally
    # acceptable -- what must not silently shrink is the total wait.
    probe = _container().readiness_probe
    assert probe.period_seconds * probe.failure_threshold >= 60


def test_serialised_probe_is_absent_when_the_container_has_none():
    # The negative control. Without it the serialiser could unconditionally emit a
    # probe and all three tests above would still pass.
    container = _container()
    container.readiness_probe = None
    assert "readinessProbe" not in _container_to_dict(container)
