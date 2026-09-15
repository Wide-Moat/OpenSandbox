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

from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from fastapi import HTTPException, status
from kubernetes.client import (
    V1AppArmorProfile,
    V1Capabilities,
    V1Container,
    V1EnvVar,
    V1ResourceRequirements,
    V1SeccompProfile,
    V1SecurityContext,
    V1VolumeMount,
)

from opensandbox_server.api.schema import ImageSpec
from opensandbox_server.extensions.keys import ISOLATION_UPPER_MOUNT_PATH
from opensandbox_server.services.constants import SandboxErrorCodes
from opensandbox_server.services.helpers import parse_gpu_request
from opensandbox_server.services.k8s.egress_helper import (
    build_security_context_for_sandbox_container,
    prep_execd_init_for_egress,
)
from opensandbox_server.services.k8s.security_context import (
    build_security_context_from_dict,
    serialize_security_context_to_dict,
)

# Default entrypoint auto-filled by the SDK when user does not provide one.
DEFAULT_ENTRYPOINT = ["tail", "-f", "/dev/null"]

_GPU_RESOURCE_LIMIT_KEY = "gpu"
# Portable keys this API defines itself, which are consumed before the pod is
# built rather than passed to Kubernetes as resource names. ``gpu`` is
# translated to nvidia.com/gpu below; ``disk`` is read by the Windows profile
# (services/windows_common.py) and never reaches container resources.
_PORTABLE_RESOURCE_LIMIT_KEYS = frozenset({_GPU_RESOURCE_LIMIT_KEY, "disk"})
# Resource names Kubernetes accepts on a container without a vendor prefix.
# Anything else must be a fully qualified extended resource ("vendor.com/name"),
# or the API server refuses the pod with "must be a standard resource type or
# fully qualified" -- and it refuses it at pod CREATION, long after this request
# returned, so the caller sees a 60s readiness timeout rather than their mistake.
_K8S_NATIVE_RESOURCE_NAMES = frozenset(
    {"cpu", "memory", "ephemeral-storage", "hugepages-2Mi", "hugepages-1Gi"}
)
# Canonical extended-resource name advertised by the NVIDIA device plugin.
# Hardcoded for parity with the Docker runtime fix (#775), which targets
# NVIDIA only via DeviceRequest capabilities=[["gpu"]]. Other vendor keys
# (e.g. amd.com/gpu, gpu.intel.com/i915) can be added as a follow-up.
_K8S_NVIDIA_GPU_RESOURCE = "nvidia.com/gpu"


def _reject_unknown_resource_names(resource_limits: Dict[str, str]) -> None:
    """Refuse resource names Kubernetes cannot accept, at the API boundary.

    ``ResourceLimits`` is an open map in the published schema, so any key is
    accepted by request validation and carried through to the pod. Kubernetes
    then rejects the pod itself with ``must be a standard resource type or
    fully qualified``. That rejection happens during pod creation, after this
    request has already returned, so the caller is told
    ``KUBERNETES::POD_READY_TIMEOUT`` after sixty seconds and the real reason
    is visible only in namespace events.

    Measured on lab stage 2026-09-15: a request carrying ``memoryMB`` and
    ``diskMB`` -- plausible names, and neither of them real -- produced exactly
    that. The sandbox was billed sixty seconds of the caller's time to deliver
    an error that was knowable immediately.

    A name is acceptable if it is one Kubernetes defines natively, or if it is
    a fully qualified extended resource carrying a ``/``. The ``gpu`` key is
    this API's own portable spelling and is translated below; ``disk`` is read
    by the Windows profile before the pod is built. Both are allowed through.
    """
    unknown = sorted(
        key
        for key in resource_limits
        if key not in _PORTABLE_RESOURCE_LIMIT_KEYS
        and "/" not in key
        and key not in _K8S_NATIVE_RESOURCE_NAMES
    )
    if not unknown:
        return

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={
            "code": SandboxErrorCodes.INVALID_PARAMETER,
            "message": (
                "Kubernetes runtime cannot use resourceLimits "
                f"{unknown}: a resource name must be one of "
                f"{sorted(_K8S_NATIVE_RESOURCE_NAMES)}, a portable key "
                f"{sorted(_PORTABLE_RESOURCE_LIMIT_KEYS)}, "
                "or a fully qualified extended resource such as "
                "'nvidia.com/gpu'. Memory and disk are expressed as Kubernetes "
                "quantities, for example memory='512Mi' and "
                "ephemeral-storage='2Gi'."
            ),
        },
    )


def _translate_resource_limits_for_k8s(
    resource_limits: Dict[str, str],
) -> Dict[str, str]:
    """Translate request-level resource limits into Kubernetes resource keys.

    The lifecycle API exposes a portable ``gpu`` key on ``resourceLimits``.
    Kubernetes requires the canonical extended-resource name
    (``nvidia.com/gpu``) so the device plugin can schedule the request;
    otherwise the value is silently treated as an unknown extended resource.

    Args:
        resource_limits: Raw resource limits from the create request.

    Returns:
        A new dict with the ``gpu`` key translated to ``nvidia.com/gpu``
        and any unparseable GPU value dropped. Other keys (cpu, memory, ...)
        are passed through unchanged.

    Raises:
        HTTPException: If ``gpu`` is the ``"all"`` sentinel. Docker accepts
            ``"all"`` (mapped to an unbounded DeviceRequest), but Kubernetes
            extended resources require an integer count, so we surface a
            400 rather than silently scheduling without a GPU.
    """
    if not resource_limits:
        return {}

    _reject_unknown_resource_names(resource_limits)

    translated: Dict[str, str] = {
        key: value
        for key, value in resource_limits.items()
        if key != _GPU_RESOURCE_LIMIT_KEY
    }

    raw_gpu = resource_limits.get(_GPU_RESOURCE_LIMIT_KEY)
    if raw_gpu is None:
        return translated

    if raw_gpu.strip().lower() == "all":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": SandboxErrorCodes.INVALID_PARAMETER,
                "message": (
                    "Kubernetes runtime requires resourceLimits.gpu to be a "
                    "positive integer; 'all' is not supported."
                ),
            },
        )

    gpu_count = parse_gpu_request(raw_gpu)
    if gpu_count is None or gpu_count <= 0:
        # parse_gpu_request already logged a warning; drop the value rather
        # than emitting an invalid extended-resource key onto the pod.
        return translated

    # str(int) is intentional: V1ResourceRequirements is typed Dict[str, str]
    # in this codebase (cpu/memory are already strings like "1" / "512Mi"),
    # and the Kubernetes API server's quantity parser accepts string integers
    # for extended resources.
    translated[_K8S_NVIDIA_GPU_RESOURCE] = str(gpu_count)
    return translated
def _build_execd_init_container(
    execd_image: str,
    execd_init_resources: Any,
    *,
    disable_ipv6_for_egress: bool = False,
) -> V1Container:
    script = (
        "cp ./execd /opt/opensandbox/execd && "
        "cp ./bootstrap.sh /opt/opensandbox/bootstrap.sh && "
        "chmod +x /opt/opensandbox/execd && "
        "chmod +x /opt/opensandbox/bootstrap.sh && "
        "(cp /usr/local/bin/bwrap /opt/opensandbox/bwrap && "
        "chmod +x /opt/opensandbox/bwrap || true) && "
        "(test ! -e /usr/local/libexec/opensandbox-session-gate || "
        "(cp /usr/local/libexec/opensandbox-session-gate "
        "/opt/opensandbox/opensandbox-session-gate && "
        "chmod 0555 /opt/opensandbox/opensandbox-session-gate)) && "
        "(test ! -e /usr/local/libexec/opensandbox-launcher || "
        "(cp /usr/local/libexec/opensandbox-launcher "
        "/opt/opensandbox/opensandbox-launcher && "
        "chmod 0555 /opt/opensandbox/opensandbox-launcher))"
    )
    security_context = None
    if disable_ipv6_for_egress:
        script, sc_dict = prep_execd_init_for_egress(script)
        security_context = build_security_context_from_dict(sc_dict)

    resources = None
    if execd_init_resources:
        resources = V1ResourceRequirements(
            limits=execd_init_resources.limits,
            requests=execd_init_resources.requests,
        )

    return V1Container(
        name="execd-installer",
        image=execd_image,
        command=["/bin/sh", "-c"],
        args=[script],
        volume_mounts=[
            V1VolumeMount(
                name="opensandbox-bin",
                mount_path="/opt/opensandbox",
            )
        ],
        resources=resources,
        security_context=security_context,
    )


def _build_main_container(
    image_spec: ImageSpec,
    entrypoint: list[str],
    env: Dict[str, str],
    resource_limits: Dict[str, str],
    *,
    has_network_policy: bool = False,
    isolation_enabled: bool = False,
    image_pull_policy: Optional[str] = None,
    resource_requests: Optional[Dict[str, str]] = None,
) -> V1Container:
    env_vars = [V1EnvVar(name=k, value=v) for k, v in env.items()]
    env_vars.append(V1EnvVar(name="EXECD", value="/opt/opensandbox/execd"))

    translated_limits = _translate_resource_limits_for_k8s(resource_limits)
    resources = None
    if translated_limits:
        translated_requests = (
            _translate_resource_limits_for_k8s(resource_requests)
            if resource_requests
            else translated_limits
        )
        resources = V1ResourceRequirements(
            limits=translated_limits,
            requests=translated_requests,
        )

    volume_mounts = [
        V1VolumeMount(
            name="opensandbox-bin",
            mount_path="/opt/opensandbox",
        )
    ]

    security_context = None
    if has_network_policy:
        security_context_dict = build_security_context_for_sandbox_container(True)
        security_context = build_security_context_from_dict(security_context_dict)

    if isolation_enabled:
        security_context = security_context or V1SecurityContext()
        caps = ["SYS_ADMIN"]
        if security_context.capabilities:
            existing = security_context.capabilities.add or []
            caps = sorted(set(existing + caps))
            security_context.capabilities.add = caps
        else:
            security_context.capabilities = V1Capabilities(add=caps)
        security_context.seccomp_profile = V1SeccompProfile(type="Unconfined")
        security_context.app_armor_profile = V1AppArmorProfile(type="Unconfined")
        volume_mounts.append(
            V1VolumeMount(
                name="isolation-upper",
                mount_path=ISOLATION_UPPER_MOUNT_PATH,
            )
        )

    return V1Container(
        name="sandbox",
        image=image_spec.uri,
        image_pull_policy=image_pull_policy,
        command=["/opt/opensandbox/bootstrap.sh"] + entrypoint,
        env=env_vars if env_vars else None,
        resources=resources,
        volume_mounts=volume_mounts,
        security_context=security_context,
    )


def _container_to_dict(container: V1Container) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "name": container.name,
        "image": container.image,
    }
    if container.image_pull_policy:
        result["imagePullPolicy"] = container.image_pull_policy
    if container.command:
        result["command"] = container.command
    if container.args:
        result["args"] = container.args
    if container.env:
        result["env"] = [{"name": e.name, "value": e.value} for e in container.env]
    if container.resources:
        result["resources"] = {}
        if container.resources.limits:
            result["resources"]["limits"] = container.resources.limits
        if container.resources.requests:
            result["resources"]["requests"] = container.resources.requests
    if container.volume_mounts:
        result["volumeMounts"] = [
            {"name": vm.name, "mountPath": vm.mount_path}
            for vm in container.volume_mounts
        ]
    if container.security_context:
        security_context_dict = serialize_security_context_to_dict(container.security_context)
        if security_context_dict:
            result["securityContext"] = security_context_dict
    return result


def _workload_platform_constraint_scope(
    workload: Dict[str, Any],
    pod_template_key: str,
    analyzer: Callable[[Any], tuple[bool, bool]],
) -> tuple[bool, bool]:
    # Use `or {}` instead of `.get(key, {})`: when a CRD field is declared
    # without `omitempty`, Kubernetes serialises an absent value as explicit
    # null rather than omitting the key.  `.get(key, {})` only substitutes
    # the default when the key is absent — not when its value is None — so
    # chaining `.get()` on the result raises AttributeError.  `or {}` treats
    # both absent keys and explicit None as empty dicts.
    spec = workload.get("spec") or {}
    template = spec.get(pod_template_key) or {}
    pod_spec = template.get("spec") or {}
    return analyzer(pod_spec)


def _extract_platform_unschedulable_message_from_pod(
    pod: Any,
    workload_has_platform_constraints: bool,
    workload_has_non_platform_constraints: bool,
    checker: Callable[[Optional[str], Optional[str], bool, bool], bool],
) -> Optional[str]:
    if not workload_has_platform_constraints:
        return None
    pod_status = pod.get("status") if isinstance(pod, dict) else getattr(pod, "status", None)
    if pod_status is None:
        return None

    conditions = (
        pod_status.get("conditions", [])
        if isinstance(pod_status, dict)
        else getattr(pod_status, "conditions", []) or []
    )
    for condition in conditions:
        condition_type = (
            condition.get("type")
            if isinstance(condition, dict)
            else getattr(condition, "type", None)
        )
        condition_status = (
            condition.get("status")
            if isinstance(condition, dict)
            else getattr(condition, "status", None)
        )
        condition_reason = (
            condition.get("reason")
            if isinstance(condition, dict)
            else getattr(condition, "reason", None)
        )
        condition_message = (
            condition.get("message")
            if isinstance(condition, dict)
            else getattr(condition, "message", None)
        )
        if (
            condition_type == "PodScheduled"
            and str(condition_status).lower() == "false"
            and checker(
                condition_reason,
                condition_message,
                workload_has_platform_constraints,
                workload_has_non_platform_constraints,
            )
        ):
            return (
                condition_message
                if isinstance(condition_message, str) and condition_message
                else "Pod scheduling constraints cannot be satisfied."
            )

    pod_reason = (
        pod_status.get("reason")
        if isinstance(pod_status, dict)
        else getattr(pod_status, "reason", None)
    )
    pod_message = (
        pod_status.get("message")
        if isinstance(pod_status, dict)
        else getattr(pod_status, "message", None)
    )
    if checker(
        pod_reason,
        pod_message,
        workload_has_platform_constraints,
        workload_has_non_platform_constraints,
    ):
        return (
            pod_message
            if isinstance(pod_message, str) and pod_message
            else "Pod scheduling constraints cannot be satisfied."
        )
    return None
