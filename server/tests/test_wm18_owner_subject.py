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

"""WM-18: what ``[tenants] enforce_ownership`` adds to upstream's tenant label.

Upstream hides a workload whose ``opensandbox.io/tenant`` label names another
tenant, and shows an unlabelled one. The HTTP tenant provider names a tenant
after its namespace, so two callers the identity service tells apart by subject
but places in one namespace are ONE tenant to that check: each sees the other's
sandboxes. And an unlabelled workload is visible to everyone.

These tests run on upstream too. They set the subject on the tenant entry and
the flag on the config without naming a symbol upstream lacks, so there they
build, run, and fail on what the service returns.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from opensandbox_server.config import TenantsConfig, load_config
from opensandbox_server.services.constants import SANDBOX_ID_LABEL
from opensandbox_server.services.k8s.kubernetes_service import KubernetesSandboxService
from opensandbox_server.tenants.context import get_current_tenant, set_current_tenant
from opensandbox_server.tenants.models import TenantEntry

NAMESPACE = "sandbox-shared"
TENANT_LABEL = "opensandbox.io/tenant"
OWNER_SUBJECT_ANNOTATION = "opensandbox.io/owner-subject"


def _entry(subject: str) -> TenantEntry:
    # As the HTTP provider builds it: the tenant is named after the namespace.
    entry = TenantEntry(name=NAMESPACE, namespace=NAMESPACE, api_keys=())
    # Set without the constructor, which upstream's entry has no field for.
    object.__setattr__(entry, "subject", subject)
    return entry


ALICE = _entry("alice")
BOB = _entry("bob")


def _workload(sandbox_id: str, subject: Optional[str]) -> Dict[str, Any]:
    annotations = {OWNER_SUBJECT_ANNOTATION: subject} if subject is not None else {}
    return {
        "metadata": {
            "name": sandbox_id,
            "namespace": NAMESPACE,
            "labels": {SANDBOX_ID_LABEL: sandbox_id, TENANT_LABEL: NAMESPACE},
            "annotations": annotations,
            "creationTimestamp": "2026-09-27T07:00:00Z",
        },
        "spec": {
            "template": {
                "spec": {"containers": [{"image": "alpine:3.20", "command": ["sleep", "1"]}]}
            }
        },
        "status": {},
    }


class _Provider:
    def __init__(self, workloads: List[Dict[str, Any]]) -> None:
        self._workloads = workloads

    def get_workload(self, sandbox_id: str, namespace: str) -> Optional[Dict[str, Any]]:
        for workload in self._workloads:
            if namespace == NAMESPACE and workload["metadata"]["name"] == sandbox_id:
                return workload
        return None

    def list_workloads(self, namespace: str, label_selector: str) -> List[Dict[str, Any]]:
        return list(self._workloads) if namespace == NAMESPACE else []

    def get_expiration(self, workload: Any):
        return None

    def get_status(self, workload: Any) -> Dict[str, Any]:
        return {"state": "RUNNING", "reason": "", "message": "", "last_transition_at": None}


@pytest.fixture
def service():
    import opensandbox_server

    example = Path(opensandbox_server.__file__).parent / "examples" / "example.config.k8s.toml"
    import opensandbox_server.config as config_module

    # load_config also installs the result as THE process-wide configuration, which
    # every later test's get_config() would then read with the strict profile on.
    loaded = (config_module._config, config_module._config_path)
    config = load_config(example)
    config.tenants = TenantsConfig.model_validate(
        {
            "provider": "http",
            "endpoint": "http://identity.invalid/tenant",
            "max_stale_seconds": 0,
            "enforce_ownership": True,
        }
    )
    assert config.kubernetes is not None
    config.kubernetes.batchsandbox_template_file = str(
        example.parent / "example.batchsandbox-template.yaml"
    )
    try:
        with patch("opensandbox_server.services.k8s.kubernetes_service.K8sClient"):
            yield KubernetesSandboxService(config)
    finally:
        config_module._config, config_module._config_path = loaded


@pytest.fixture
def as_caller():
    previous = get_current_tenant()
    try:
        yield set_current_tenant
    finally:
        set_current_tenant(previous)


def test_wm18_another_subject_in_the_same_tenant_cannot_read_the_sandbox(service, as_caller):
    service.workload_provider = _Provider([_workload("sb-alice", "alice")])
    as_caller(BOB)
    with pytest.raises(HTTPException) as excinfo:
        service.get_sandbox("sb-alice")
    assert excinfo.value.status_code == 404


def test_wm18_an_ownerless_workload_is_hidden_not_adopted(service, as_caller):
    service.workload_provider = _Provider([_workload("sb-legacy", None)])
    as_caller(ALICE)
    with pytest.raises(HTTPException) as excinfo:
        service.get_sandbox("sb-legacy")
    assert excinfo.value.status_code == 404


def test_wm18_a_list_holds_only_the_callers_own_sandboxes(service, as_caller):
    service.workload_provider = _Provider(
        [_workload("sb-alice", "alice"), _workload("sb-bob", "bob"), _workload("sb-legacy", None)]
    )
    as_caller(BOB)
    assert [s.id for s in service.list_sandbox_objects()] == ["sb-bob"]
