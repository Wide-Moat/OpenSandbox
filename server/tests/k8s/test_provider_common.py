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

import pytest
from fastapi import HTTPException

from opensandbox_server.services.constants import SandboxErrorCodes
from opensandbox_server.services.k8s.provider_common import (
    _translate_resource_limits_for_k8s,
    _workload_platform_constraint_scope,
)


# ---------------------------------------------------------------------------
# Helpers for _workload_platform_constraint_scope tests
# ---------------------------------------------------------------------------

def _analyzer(pod_spec):
    """Return whether pod_spec has nodeSelector / nodeName (platform constraints)."""
    has_platform = bool(pod_spec.get("nodeSelector") or pod_spec.get("nodeName"))
    has_non_platform = bool(pod_spec.get("affinity"))
    return has_platform, has_non_platform


def test_translate_resource_limits_passes_gpu_count():
    result = _translate_resource_limits_for_k8s(
        {"cpu": "1", "memory": "1Gi", "gpu": "2"}
    )
    assert result["nvidia.com/gpu"] == "2"


def test_translate_resource_limits_strips_raw_gpu_key():
    # Regression guard: the raw "gpu" key must not leak into the pod's
    # V1ResourceRequirements where Kubernetes would treat it as an
    # unknown extended resource.
    result = _translate_resource_limits_for_k8s({"gpu": "2"})
    assert "gpu" not in result
    assert result == {"nvidia.com/gpu": "2"}


def test_translate_resource_limits_preserves_cpu_memory():
    result = _translate_resource_limits_for_k8s({"cpu": "500m", "memory": "512Mi"})
    assert result == {"cpu": "500m", "memory": "512Mi"}


def test_translate_resource_limits_no_gpu_key_unchanged():
    inputs = {"cpu": "2", "memory": "4Gi"}
    result = _translate_resource_limits_for_k8s(inputs)
    assert result == inputs
    # Must be a new dict — callers pass it to both limits= and requests=,
    # and we don't want surprise mutation of the input.
    assert result is not inputs


def test_translate_resource_limits_rejects_all():
    with pytest.raises(HTTPException) as excinfo:
        _translate_resource_limits_for_k8s({"gpu": "all"})
    assert excinfo.value.status_code == 400
    detail = excinfo.value.detail
    assert detail["code"] == SandboxErrorCodes.INVALID_PARAMETER
    assert "positive integer" in detail["message"]


@pytest.mark.parametrize("bad_value", ["0", "-1", "bad", ""])
def test_translate_resource_limits_drops_invalid_gpu(bad_value):
    result = _translate_resource_limits_for_k8s(
        {"cpu": "1", "gpu": bad_value}
    )
    assert "nvidia.com/gpu" not in result
    assert "gpu" not in result
    assert result == {"cpu": "1"}


def test_translate_resource_limits_empty_dict():
    assert _translate_resource_limits_for_k8s({}) == {}


# ---------------------------------------------------------------------------
# _workload_platform_constraint_scope
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("workload", [
    {"spec": {"template": None, "poolRef": "pool-runc"}},  # key exists, value None (pool mode)
    {"spec": {"poolRef": "pool-runc"}},                    # key absent entirely
    {"spec": None},                                         # spec itself is None
    {},                                                     # empty workload
    {"spec": {"template": {"spec": None}}},                # template present, inner spec is None
])
def test_platform_constraint_scope_no_crash_on_null_fields(workload):
    # Regression: chained .get(key, {}) raises AttributeError when any level
    # is explicitly None.  `or {}` must handle all these shapes safely.
    result = _workload_platform_constraint_scope(workload, "template", _analyzer)
    assert result == (False, False)


def test_platform_constraint_scope_detects_node_selector():
    workload = {
        "spec": {
            "template": {
                "spec": {
                    "nodeSelector": {"kubernetes.io/arch": "amd64"},
                }
            }
        }
    }
    has_platform, has_non_platform = _workload_platform_constraint_scope(
        workload, "template", _analyzer
    )
    assert has_platform is True
    assert has_non_platform is False


def test_platform_constraint_scope_pod_template_key_alias():
    # AgentSandbox uses "podTemplate" instead of "template"
    workload = {
        "spec": {
            "podTemplate": {
                "spec": {"nodeSelector": {"kubernetes.io/os": "linux"}}
            }
        }
    }
    has_platform, _ = _workload_platform_constraint_scope(
        workload, "podTemplate", _analyzer
    )
    assert has_platform is True


# ---------------------------------------------------------------------------
# Resource names Kubernetes cannot accept (regression: lab stage 2026-09-15)
# ---------------------------------------------------------------------------


def test_translate_resource_limits_rejects_unknown_names():
    """memoryMB/diskMB must fail HERE, not sixty seconds later as a pod event.

    Measured on lab stage: a create request carrying these names returned 202,
    the pod was refused by the API server with "must be a standard resource
    type or fully qualified", and the caller saw KUBERNETES::POD_READY_TIMEOUT
    after 60s with the real reason only in namespace events.
    """
    with pytest.raises(HTTPException) as exc:
        _translate_resource_limits_for_k8s(
            {"cpu": "1", "memoryMB": "1024", "diskMB": "2048"}
        )
    assert exc.value.status_code == 400
    message = exc.value.detail["message"]
    # Both offending names are reported, not just the first one found.
    assert "memoryMB" in message and "diskMB" in message
    # The message must say what IS acceptable, or it only tells the caller they
    # are wrong without telling them what to write instead.
    assert "ephemeral-storage" in message and "512Mi" in message


def test_translate_resource_limits_allows_native_names():
    """The control: valid names must still pass, or the guard rejects everything."""
    result = _translate_resource_limits_for_k8s(
        {"cpu": "500m", "memory": "512Mi", "ephemeral-storage": "2Gi"}
    )
    assert result == {"cpu": "500m", "memory": "512Mi", "ephemeral-storage": "2Gi"}


def test_translate_resource_limits_allows_qualified_extended_resources():
    """A vendor-qualified name is legal to Kubernetes and must not be refused."""
    result = _translate_resource_limits_for_k8s({"cpu": "1", "amd.com/gpu": "1"})
    assert result == {"cpu": "1", "amd.com/gpu": "1"}


def test_translate_resource_limits_still_translates_portable_gpu():
    """The portable 'gpu' key is this API's own spelling and must survive the guard."""
    result = _translate_resource_limits_for_k8s({"cpu": "1", "gpu": "2"})
    assert result == {"cpu": "1", "nvidia.com/gpu": "2"}


def test_translate_resource_limits_allows_portable_disk_key():
    """'disk' is this API's own portable key, consumed by the Windows profile.

    It is not a Kubernetes resource name, so a guard derived only from
    Kubernetes rejects it -- which is exactly what happened when this guard was
    first written: five Windows-profile tests that had passed for months went
    red. It never reaches container resources, so it must pass through here.
    """
    result = _translate_resource_limits_for_k8s({"cpu": "1", "disk": "20Gi"})
    assert result == {"cpu": "1", "disk": "20Gi"}
