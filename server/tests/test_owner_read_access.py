# Copyright 2025 Alibaba Group Holding Ltd.
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

"""Strict ownership checks through real Kubernetes service read paths."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from opensandbox_server.config import TenantsConfig, load_config  # noqa: E402
from opensandbox_server.services.constants import SANDBOX_ID_LABEL  # noqa: E402
from opensandbox_server.services.k8s.kubernetes_service import (  # noqa: E402
    KubernetesSandboxService,
)
from opensandbox_server.tenants.context import (  # noqa: E402
    get_current_tenant,
    set_current_tenant,
)
from opensandbox_server.tenants.models import TenantEntry  # noqa: E402

STAGE_NAMESPACE = "sandbox-stage"
OTHER_NAMESPACE = "sandbox-other"


def _workload(sandbox_id: str, owner_label: Optional[str]) -> Dict[str, Any]:
    """A workload shaped the way the real mapper reads it.

    ``owner_label`` is carried as ordinary user metadata. It exists so the test
    can tell whose sandbox was returned; the production code does not consult
    it, which is precisely the point under examination.
    """
    return {
        "metadata": {
            "name": sandbox_id,
            "namespace": STAGE_NAMESPACE,
            "labels": {SANDBOX_ID_LABEL: sandbox_id, "seeded-by": owner_label},
            "annotations": {"opensandbox.io/owner-subject": owner_label},
            "creationTimestamp": "2026-09-17T07:00:00Z",
        },
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {"image": "ghcr.io/example/img:v1", "command": ["sleep", "1"]}
                    ]
                }
            }
        },
        "status": {},
    }


class FakeWorkloadProvider:
    """The external Kubernetes boundary, and only that.

    It answers strictly within the namespace it is asked about, which is the
    behaviour a real namespaced API call has. Any cross-owner read observed by
    the test therefore comes from the service's own resolution, not from a
    permissive fake.
    """

    def __init__(self, by_namespace: Dict[str, List[Dict[str, Any]]]) -> None:
        self._by_namespace = by_namespace
        self.get_calls: List[tuple[str, str]] = []
        self.list_calls: List[str] = []

    def get_workload(self, sandbox_id: str, namespace: str) -> Optional[Dict[str, Any]]:
        self.get_calls.append((namespace, sandbox_id))
        for workload in self._by_namespace.get(namespace, []):
            if workload["metadata"]["labels"][SANDBOX_ID_LABEL] == sandbox_id:
                return workload
        return None

    def list_workloads(self, namespace: str, label_selector: str) -> List[Dict[str, Any]]:
        self.list_calls.append(namespace)
        return list(self._by_namespace.get(namespace, []))

    def get_expiration(self, workload: Any) -> Optional[datetime]:
        return None

    def get_status(self, workload: Any) -> Dict[str, Any]:
        return {
            "state": "RUNNING",
            "reason": "",
            "message": "",
            "last_transition_at": None,
        }


@pytest.fixture
def tenant_context():
    """Set and restore the real tenant ContextVar.

    The token is reset in a finally block so a failing assertion cannot leak a
    tenant into another test.
    """
    previous = get_current_tenant()

    def _set(entry: Optional[TenantEntry]):
        set_current_tenant(entry)

    try:
        yield _set
    finally:
        set_current_tenant(previous)


@pytest.fixture
def service():
    """A real KubernetesSandboxService with only the K8s client patched out."""
    # Resolved from the installed package, as tests/test_routes_create_resource_names.py:118-122 does.
    import opensandbox_server

    example = (
        Path(opensandbox_server.__file__).parent
        / "examples"
        / "example.config.k8s.toml"
    )
    config = load_config(example)
    config.tenants = TenantsConfig(provider="http", endpoint="http://example.invalid/identity", enforce_ownership=True, max_stale_seconds=0)
    assert config.kubernetes is not None
    config.kubernetes.batchsandbox_template_file = str(
        example.parent / "example.batchsandbox-template.yaml"
    )
    with patch(
        "opensandbox_server.services.k8s.kubernetes_service.K8sClient"
    ):
        yield KubernetesSandboxService(config)


# Two synthetic principals. Distinct names, distinct keys, and -- exactly as
# STAGE keyauth behaves -- the SAME namespace for both.
ALICE = TenantEntry(name="alice", subject="alice", namespace=STAGE_NAMESPACE, api_keys=("synthetic-key-a",))
BOB = TenantEntry(name="bob", subject="bob", namespace=STAGE_NAMESPACE, api_keys=("synthetic-key-b",))
# The negative control: a principal in a genuinely different namespace.
CAROL = TenantEntry(name="carol", subject="carol", namespace=OTHER_NAMESPACE, api_keys=("synthetic-key-c",))


def test_s05_cross_owner_get_in_shared_namespace(service, tenant_context):
    """Can B read A's sandbox? Acceptance: another owner must be denied."""
    provider = FakeWorkloadProvider(
        {STAGE_NAMESPACE: [_workload("sb-alice-1", owner_label="alice")]}
    )
    service.workload_provider = provider

    # A seeds nothing here -- the workload is pre-seeded as if A had created it.
    # B, a different principal with a different key, asks for A's sandbox id.
    tenant_context(BOB)
    with pytest.raises(HTTPException) as excinfo:
        service.get_sandbox("sb-alice-1")
    assert excinfo.value.status_code in (403, 404)


def test_s05_cross_owner_list_in_shared_namespace(service, tenant_context):
    """Acceptance: B must not list A's sandboxes."""
    provider = FakeWorkloadProvider(
        {
            STAGE_NAMESPACE: [
                _workload("sb-alice-1", owner_label="alice"),
                _workload("sb-bob-1", owner_label="bob"),
            ]
        }
    )
    service.workload_provider = provider

    tenant_context(BOB)
    sandboxes = service.list_sandbox_objects()

    owners = sorted(s.metadata["seeded-by"] for s in sandboxes if s.metadata)
    assert owners == ["bob"], (
        "S05 FAIL: principal 'bob' listed sandboxes owned by 'alice'. Listing is "
        "namespace-scoped with no owner filter."
    )
    assert provider.list_calls == [STAGE_NAMESPACE]


def test_negative_control_different_namespace_is_not_found(service, tenant_context):
    """A principal in a DIFFERENT namespace must not reach the sandbox.

    This is the control that proves the namespace boundary is real and that the
    fake provider is not simply returning everything to everyone. Without it,
    the two results above would be uninterpretable.
    """
    provider = FakeWorkloadProvider(
        {
            STAGE_NAMESPACE: [_workload("sb-alice-1", owner_label="alice")],
            OTHER_NAMESPACE: [],
        }
    )
    service.workload_provider = provider

    tenant_context(CAROL)
    with pytest.raises(HTTPException) as excinfo:
        service.get_sandbox("sb-alice-1")

    assert excinfo.value.status_code == 404
    # The lookup must have been attempted in Carol's namespace, not Alice's.
    assert (OTHER_NAMESPACE, "sb-alice-1") in provider.get_calls
    assert (STAGE_NAMESPACE, "sb-alice-1") not in provider.get_calls, (
        "the cross-namespace fallback reached another tenant's namespace"
    )


def test_negative_control_different_namespace_list_is_empty(service, tenant_context):
    """Listing from another namespace returns nothing from the stage namespace."""
    provider = FakeWorkloadProvider(
        {
            STAGE_NAMESPACE: [_workload("sb-alice-1", owner_label="alice")],
            OTHER_NAMESPACE: [],
        }
    )
    service.workload_provider = provider

    tenant_context(CAROL)
    assert service.list_sandbox_objects() == []
    assert provider.list_calls == [OTHER_NAMESPACE]


def test_tenant_context_is_restored(tenant_context):
    """The ContextVar must not leak between callers."""
    assert get_current_tenant() is None
    tenant_context(ALICE)
    assert get_current_tenant() is not None
    current = get_current_tenant()
    assert current is not None
    assert current.name == "alice"
    # The fixture's finally clause resets it; the assertion above proves it was
    # actually set, so the reset is meaningful rather than vacuous.


@pytest.mark.parametrize("caller", [BOB, CAROL], ids=["same-namespace-other-owner", "different-namespace-control"])
@pytest.mark.parametrize("mode", ["ordinary", "internal", "signed"])
def test_s05_endpoint_must_not_disclose_other_owner_access_token(service, tenant_context, caller, mode):
    from opensandbox_server.services.constants import (
        SANDBOX_SECURE_ACCESS_TOKEN_METADATA_KEY,
        OPEN_SANDBOX_SECURE_ACCESS_HEADER,
    )

    class EndpointProvider(FakeWorkloadProvider):
        def get_endpoint_info(self, workload, port, sandbox_id):
            pytest.fail("Foreign workload reached endpoint resolution")

        def get_internal_endpoint(self, workload, port, sandbox_id):
            pytest.fail("Foreign workload reached internal endpoint resolution")

    workload = _workload("sb-alice-1", owner_label="alice")
    workload["metadata"]["annotations"][SANDBOX_SECURE_ACCESS_TOKEN_METADATA_KEY] = "synthetic-alice-access-token"
    provider = EndpointProvider({STAGE_NAMESPACE: [workload]})
    service.workload_provider = provider
    tenant_context(caller)
    try:
        import time
        endpoint = service.get_endpoint("sb-alice-1", 44772, resolve_internal=mode == "internal", expires=int(time.time()) + 60 if mode == "signed" else None)
    except HTTPException as exc:
        assert exc.status_code in (403, 404)
    else:
        # Record the actual exposure without ever using a real credential or network.
        assert endpoint.headers[OPEN_SANDBOX_SECURE_ACCESS_HEADER] == "synthetic-alice-access-token"
        pytest.fail("S05: another owner received the sandbox secure-access token")


def test_own_owner_can_get_and_list(service, tenant_context):
    service.workload_provider = FakeWorkloadProvider({STAGE_NAMESPACE: [_workload("own", "alice"), _workload("foreign", "bob")]})
    tenant_context(ALICE)
    assert service.get_sandbox("own").id == "own"
    assert [item.id for item in service.list_sandbox_objects()] == ["own"]


def test_editable_labels_do_not_adopt_ownerless_workload(service, tenant_context):
    workload = _workload("ownerless", "alice")
    workload["metadata"]["annotations"] = {}
    workload["metadata"]["labels"]["owner"] = "alice"
    service.workload_provider = FakeWorkloadProvider({STAGE_NAMESPACE: [workload]})
    tenant_context(ALICE)
    with pytest.raises(HTTPException) as exc:
        service.get_sandbox("ownerless")
    assert exc.value.status_code == 404
    assert service.list_sandbox_objects() == []


@pytest.mark.parametrize("operation", ["get", "list", "endpoint"])
def test_absent_identity_denied_before_kubernetes_lookup(service, tenant_context, operation):
    provider = FakeWorkloadProvider({STAGE_NAMESPACE: [_workload("own", "alice")]})
    service.workload_provider = provider
    tenant_context(None)
    with pytest.raises(HTTPException) as exc:
        if operation == "get":
            service.get_sandbox("own")
        elif operation == "list":
            service.list_sandbox_objects()
        else:
            service.get_endpoint("own", 44772)
    assert exc.value.status_code == 401
    assert provider.get_calls == []
    assert provider.list_calls == []


class MutationProvider(FakeWorkloadProvider):
    def __init__(self, workloads):
        super().__init__({STAGE_NAMESPACE: workloads})
        self.effects = []

    def pause_sandbox(self, sandbox_id, namespace):
        self.effects.append('pause')

    def resume_sandbox(self, sandbox_id, namespace):
        self.effects.append('resume')

    def get_expiration(self, workload):
        from datetime import datetime, timezone
        return datetime.now(timezone.utc)

    def update_expiration(self, **kwargs):
        self.effects.append('renew')

    def patch_labels(self, name, namespace, labels):
        self.effects.append('metadata')
        workload = self.get_workload(name, namespace)
        assert workload is not None
        workload['metadata']['labels'] = {key: value for key, value in labels.items() if value is not None}
        return workload


def _mutate(service, operation):
    from datetime import datetime, timedelta, timezone
    from opensandbox_server.api.schema import RenewSandboxExpirationRequest
    if operation == 'renew':
        return service.renew_expiration('target', RenewSandboxExpirationRequest.model_validate(dict(expires_at=datetime.now(timezone.utc) + timedelta(hours=1))))
    if operation == 'metadata':
        return service.patch_sandbox_metadata('target', {'purpose': 'test'})
    return getattr(service, operation + '_sandbox')('target')


@pytest.mark.parametrize('operation', ['pause', 'resume', 'renew', 'metadata'])
@pytest.mark.parametrize('owner', ['bob', None])
def test_foreign_and_ownerless_mutations_have_no_effects(service, tenant_context, operation, owner):
    provider = MutationProvider([_workload('target', owner)])
    service.workload_provider = provider
    tenant_context(ALICE)
    with pytest.raises(HTTPException) as exc:
        _mutate(service, operation)
    assert exc.value.status_code == 404
    assert provider.effects == []


@pytest.mark.parametrize('operation', ['pause', 'resume', 'renew', 'metadata'])
def test_owner_mutations_remain_available(service, tenant_context, operation):
    provider = MutationProvider([_workload('target', 'alice')])
    service.workload_provider = provider
    tenant_context(ALICE)
    _mutate(service, operation)
    assert provider.effects == [operation]


@pytest.mark.parametrize('operation', ['pause', 'resume', 'renew', 'metadata'])
def test_mutations_without_identity_do_not_reach_provider(service, tenant_context, operation):
    provider = MutationProvider([_workload('target', 'alice')])
    service.workload_provider = provider
    tenant_context(None)
    with pytest.raises(HTTPException) as exc:
        _mutate(service, operation)
    assert exc.value.status_code == 401
    assert provider.get_calls == []
    assert provider.effects == []


class DeletionProvider(MutationProvider):
    def delete_workload(self, sandbox_id, namespace):
        self.effects.append('delete')


class VolumeClient:
    def __init__(self, owners):
        from types import SimpleNamespace
        self.pvcs = [SimpleNamespace(metadata=SimpleNamespace(name=name, annotations={'opensandbox.io/owner-subject': owner})) for name, owner in owners.items()]
        self.list_calls = []
        self.deleted = []

    def list_pvcs(self, namespace, label_selector):
        self.list_calls.append(namespace)
        return self.pvcs

    def delete_pvc(self, namespace, name):
        self.deleted.append((namespace, name))


@pytest.mark.parametrize('owner', ['bob', None, 'missing'])
def test_delete_denial_cannot_trigger_orphan_cleanup(service, tenant_context, owner):
    provider = DeletionProvider([] if owner == 'missing' else [_workload('target', owner)])
    volumes = VolumeClient({'foreign-volume': 'bob'})
    service.workload_provider = provider
    service.k8s_client = volumes
    tenant_context(ALICE)
    with pytest.raises(HTTPException) as exc:
        service.delete_sandbox('target')
    assert exc.value.status_code == 404
    assert provider.effects == []
    assert volumes.list_calls == []
    assert volumes.deleted == []


def test_delete_owned_workload_only_cleans_owned_volumes(service, tenant_context):
    provider = DeletionProvider([_workload('target', 'alice')])
    volumes = VolumeClient({'own': 'alice', 'foreign': 'bob', 'ownerless': None})
    service.workload_provider = provider
    service.k8s_client = volumes
    tenant_context(ALICE)
    service.delete_sandbox('target')
    assert provider.effects == ['delete']
    assert volumes.deleted == [(STAGE_NAMESPACE, 'own')]


def test_delete_without_identity_has_no_side_effects(service, tenant_context):
    provider = DeletionProvider([_workload('target', 'alice')])
    volumes = VolumeClient({'own': 'alice'})
    service.workload_provider = provider
    service.k8s_client = volumes
    tenant_context(None)
    with pytest.raises(HTTPException) as exc:
        service.delete_sandbox('target')
    assert exc.value.status_code == 401
    assert provider.effects == provider.get_calls == volumes.list_calls == volumes.deleted == []


def test_legacy_delete_retains_ownerless_volume_cleanup(service, tenant_context):
    service.app_config.tenants.enforce_ownership = False
    provider = DeletionProvider([_workload('target', None)])
    volumes = VolumeClient({'legacy': None})
    service.workload_provider = provider
    service.k8s_client = volumes
    tenant_context(ALICE)
    service.delete_sandbox('target')
    assert provider.effects == ['delete']
    assert provider.get_calls == []
    assert volumes.deleted == [(STAGE_NAMESPACE, 'legacy')]


class CreationProvider(MutationProvider):
    def get_status(self, workload):
        return {**super().get_status(workload), "state": "Running"}

    def create_workload(self, **kwargs):
        self.created = kwargs
        workload = _workload(kwargs['sandbox_id'], 'untrusted')
        workload['metadata']['annotations'] = kwargs['annotations']
        workload['metadata']['labels'] = kwargs['labels']
        self._by_namespace[STAGE_NAMESPACE].append(workload)
        self.effects.append('create')
        return {'name': kwargs['sandbox_id']}


@pytest.mark.asyncio
async def test_creation_stamps_trusted_subject_and_owner_label(service, tenant_context):
    from opensandbox_server.api.schema import CreateSandboxRequest
    provider = CreationProvider([])
    service.workload_provider = provider
    tenant_context(ALICE)
    request = CreateSandboxRequest.model_validate(dict(image={'uri': 'alpine:3.20'}, entrypoint=['sleep', '60'], timeout=60, resource_limits={'cpu': '1', 'memory': '512Mi'}))
    result = await service.create_sandbox(request)
    assert provider.created['annotations']['opensandbox.io/owner-subject'] == 'alice'
    assert provider.created['labels']['owner'] == 'alice'
    assert result.metadata['owner'] == 'alice'


@pytest.mark.asyncio
async def test_creation_rejects_forged_owner_before_provider(service, tenant_context):
    from opensandbox_server.api.schema import CreateSandboxRequest
    provider = CreationProvider([])
    service.workload_provider = provider
    tenant_context(ALICE)
    request = CreateSandboxRequest.model_validate(dict(image={'uri': 'alpine:3.20'}, entrypoint=['sleep', '60'], timeout=60, resource_limits={'cpu': '1', 'memory': '512Mi'}, metadata={'owner': 'bob'}))
    with pytest.raises(HTTPException) as exc:
        await service.create_sandbox(request)
    assert exc.value.status_code == 400
    assert provider.effects == []


@pytest.mark.parametrize('value', ['bob', None])
def test_owner_metadata_cannot_be_transferred_or_removed(service, tenant_context, value):
    provider = MutationProvider([_workload('target', 'alice')])
    service.workload_provider = provider
    tenant_context(ALICE)
    with pytest.raises(HTTPException) as exc:
        service.patch_sandbox_metadata('target', {'owner': value})
    assert exc.value.status_code == 400
    assert provider.effects == []


@pytest.mark.asyncio
@pytest.mark.parametrize('pool', [False, True])
async def test_opaque_subject_creation_is_label_safe_in_cold_and_pool_paths(service, tenant_context, pool):
    from opensandbox_server.api.schema import CreateSandboxRequest
    from opensandbox_server.services.k8s.client import POOL_AUTO_ASSIGN_REF
    from opensandbox_server.services.validators import ensure_metadata_labels
    subject = 'https://identity.example/users/' + 'x' * 100
    tenant_context(TenantEntry(name='alice', subject=subject, namespace=STAGE_NAMESPACE, api_keys=('synthetic',)))
    provider = CreationProvider([])
    service.workload_provider = provider
    request = CreateSandboxRequest.model_validate(dict(image={'uri': 'alpine:3.20'}, entrypoint=['sleep', '60'], timeout=60, resource_limits={'cpu': '1', 'memory': '512Mi'}, extensions={'poolRef': POOL_AUTO_ASSIGN_REF} if pool else None))
    result = await service.create_sandbox(request)
    assert provider.created['annotations']['opensandbox.io/owner-subject'] == subject
    ensure_metadata_labels({'owner': result.metadata['owner']})
    assert service.get_sandbox(result.id).id == result.id


@pytest.mark.asyncio
async def test_creation_without_identity_rejected_before_side_effects(service, tenant_context):
    from opensandbox_server.api.schema import CreateSandboxRequest
    provider = CreationProvider([])
    service.workload_provider = provider
    tenant_context(None)
    with pytest.raises(HTTPException) as exc:
        await service.create_sandbox(CreateSandboxRequest.model_validate(dict(image={'uri': 'alpine:3.20'}, entrypoint=['sleep', '60'], timeout=60, resource_limits={'cpu': '1', 'memory': '512Mi'})))
    assert exc.value.status_code == 401
    assert provider.effects == []


class ProvisioningClient(VolumeClient):
    def __init__(self, owners, race_owner=None, forbidden=False):
        super().__init__(owners)
        self.created = []
        self.race_owner = race_owner
        self.forbidden = forbidden

    def get_pvc(self, namespace, name):
        return next((p for p in self.pvcs if p.metadata.name == name), None)

    def create_pvc(self, namespace, body):
        from kubernetes.client import ApiException
        if self.forbidden:
            raise ApiException(status=403)
        if self.race_owner is not None:
            self.pvcs = VolumeClient({body.metadata.name: self.race_owner}).pvcs
            raise ApiException(status=409)
        self.created.append(body)
        self.pvcs.append(body)


def _volume_request(create=True):
    from opensandbox_server.api.schema import CreateSandboxRequest
    return CreateSandboxRequest.model_validate(dict(image={'uri': 'alpine:3.20'}, entrypoint=['sleep', '60'], timeout=60, resource_limits={'cpu': '1', 'memory': '512Mi'}, volumes=[{'name': 'data', 'mountPath': '/data', 'pvc': {'claimName': 'data', 'createIfNotExists': create}}]))


@pytest.mark.asyncio
@pytest.mark.parametrize('owner', ['bob', None])
@pytest.mark.parametrize('create', [False, True])
async def test_creation_denies_foreign_or_ownerless_pvc(service, tenant_context, owner, create):
    provider = CreationProvider([])
    client = ProvisioningClient({'data': owner})
    service.workload_provider = provider
    service.k8s_client = client
    tenant_context(ALICE)
    with pytest.raises(HTTPException) as exc:
        await service.create_sandbox(_volume_request(create))
    assert exc.value.status_code == 404
    assert provider.effects == client.created == client.deleted == []


@pytest.mark.asyncio
@pytest.mark.parametrize('existing', [False, True])
async def test_creation_can_provision_and_reuse_own_pvc(service, tenant_context, existing):
    provider = CreationProvider([])
    client = ProvisioningClient({'data': 'alice'} if existing else {})
    service.workload_provider = provider
    service.k8s_client = client
    tenant_context(ALICE)
    await service.create_sandbox(_volume_request())
    assert provider.effects == ['create']
    if not existing:
        assert client.created[0].metadata.annotations['opensandbox.io/owner-subject'] == 'alice'


@pytest.mark.asyncio
@pytest.mark.parametrize('mode', ['race', 'forbidden', 'missing'])
async def test_unverified_pvc_never_reaches_workload_creation(service, tenant_context, mode):
    provider = CreationProvider([])
    client = ProvisioningClient({}, race_owner='bob' if mode == 'race' else None, forbidden=mode == 'forbidden')
    service.workload_provider = provider
    service.k8s_client = client
    tenant_context(ALICE)
    with pytest.raises(HTTPException) as exc:
        await service.create_sandbox(_volume_request(mode != 'missing'))
    assert exc.value.status_code in (404, 503)
    assert provider.effects == client.deleted == []


@pytest.fixture
def owned_snapshots(service, tmp_path, monkeypatch):
    from opensandbox_server.repositories.snapshots.sqlite import SQLiteSnapshotRepository
    from opensandbox_server.services.snapshot_models import SnapshotRecord, SnapshotRestoreConfig, SnapshotStatusRecord, SnapshotState
    from opensandbox_server.services.snapshot_service import PersistedSnapshotService
    from tests.test_snapshot_service import StubSnapshotRuntime, CapturingExecutor
    repo = SQLiteSnapshotRepository(tmp_path / 'owners.db')
    for ident, owner in [('own', 'alice'), ('foreign', 'bob'), ('legacy', None)]:
        repo.create(SnapshotRecord(id=ident, source_sandbox_id='source', namespace=STAGE_NAMESPACE, owner_subject=owner, restore_config=SnapshotRestoreConfig(image='alpine:3.20'), status=SnapshotStatusRecord(state=SnapshotState.READY)))
    monkeypatch.setattr('opensandbox_server.services.snapshot_restore.get_snapshot_repository', lambda: repo)
    runtime = StubSnapshotRuntime()
    snapshots = PersistedSnapshotService(repo, service, runtime, CapturingExecutor(), recover_unfinished_snapshots=False, enforce_ownership=True)
    return snapshots, repo, runtime


@pytest.mark.parametrize('ident', ['foreign', 'legacy'])
@pytest.mark.parametrize('operation', ['get', 'delete'])
def test_snapshot_foreign_access_denied_before_effects(owned_snapshots, tenant_context, ident, operation):
    snapshots, repo, runtime = owned_snapshots
    tenant_context(ALICE)
    with pytest.raises(HTTPException) as exc:
        getattr(snapshots, operation + '_snapshot')(ident)
    assert exc.value.status_code == 404
    assert repo.get(ident) is not None
    assert runtime.delete_calls == []


def test_snapshot_list_filters_before_count_and_pagination(owned_snapshots, tenant_context):
    from opensandbox_server.api.schema import ListSnapshotsRequest, SnapshotFilter
    snapshots, repo, runtime = owned_snapshots
    tenant_context(ALICE)
    result = snapshots.list_snapshots(ListSnapshotsRequest.model_validate(dict(filter=SnapshotFilter.model_validate(dict()), pagination={'page': 1, 'pageSize': 1})))
    assert result.pagination.total_items == 1
    assert [s.id for s in result.items] == ['own']
    assert snapshots.get_snapshot('own').id == 'own'
    snapshots.delete_snapshot('own')
    assert repo.get('own') is None
    assert len(runtime.delete_calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('ident', ['foreign', 'legacy'])
async def test_restore_denies_foreign_snapshot_before_workload(owned_snapshots, service, tenant_context, ident):
    from opensandbox_server.api.schema import CreateSandboxRequest
    service.workload_provider = CreationProvider([])
    tenant_context(ALICE)
    with pytest.raises(HTTPException) as exc:
        await service.create_sandbox(CreateSandboxRequest.model_validate(dict(snapshotId=ident, timeout=60, resourceLimits={'cpu': '1', 'memory': '512Mi'})))
    assert exc.value.status_code == 404
    assert service.workload_provider.effects == []


@pytest.mark.asyncio
async def test_restore_own_snapshot_succeeds(owned_snapshots, service, tenant_context):
    from opensandbox_server.api.schema import CreateSandboxRequest
    provider = CreationProvider([])
    service.workload_provider = provider
    tenant_context(ALICE)
    result = await service.create_sandbox(CreateSandboxRequest.model_validate(dict(snapshotId='own', timeout=60, resourceLimits={'cpu': '1', 'memory': '512Mi'})))
    assert result.metadata['owner'] == 'alice'
    assert provider.created['image_spec'].uri == 'alpine:3.20'


@pytest.mark.parametrize('operation', ['get', 'delete', 'list'])
def test_snapshot_missing_identity_is_rejected(owned_snapshots, tenant_context, operation):
    from opensandbox_server.api.schema import ListSnapshotsRequest, SnapshotFilter
    snapshots, repo, runtime = owned_snapshots
    tenant_context(None)
    with pytest.raises(HTTPException) as exc:
        if operation == 'list':
            snapshots.list_snapshots(ListSnapshotsRequest.model_validate(dict(filter=SnapshotFilter.model_validate(dict()))))
        else:
            getattr(snapshots, operation + '_snapshot')('own')
    assert exc.value.status_code == 401
    assert runtime.delete_calls == []


def test_snapshot_creation_and_completion_preserve_owner(owned_snapshots, service, tenant_context):
    from opensandbox_server.api.schema import CreateSnapshotRequest
    from opensandbox_server.services.snapshot_models import SnapshotState
    from opensandbox_server.services.snapshot_runtime import SnapshotRuntimeStatus
    snapshots, repo, runtime = owned_snapshots
    service.workload_provider = CreationProvider([_workload('source', 'alice')])
    tenant_context(ALICE)
    snapshot = snapshots.create_snapshot('source', CreateSnapshotRequest(name='owned'))
    record = repo.get(snapshot.id)
    assert record.owner_subject == 'alice'
    snapshots._complete_snapshot(record, SnapshotRuntimeStatus(state=SnapshotState.READY, image='alpine:3.20'))
    assert repo.get(snapshot.id).owner_subject == 'alice'
    assert snapshots.get_snapshot(snapshot.id).id == snapshot.id
    deleting = snapshots._mark_snapshot_deleting(repo.get(snapshot.id))
    assert deleting.owner_subject == 'alice'
    assert repo.get(snapshot.id).owner_subject == 'alice'


def test_access_renew_extension_is_owner_scoped(service, tenant_context):
    from opensandbox_server.extensions.keys import ACCESS_RENEW_EXTEND_SECONDS_METADATA_KEY
    workload = _workload('foreign', 'bob')
    workload['metadata']['annotations'][ACCESS_RENEW_EXTEND_SECONDS_METADATA_KEY] = '60'
    service.workload_provider = MutationProvider([workload])
    tenant_context(ALICE)
    with pytest.raises(HTTPException) as exc:
        service.get_access_renew_extend_seconds('foreign')
    assert exc.value.status_code == 404


@pytest.mark.asyncio
@pytest.mark.parametrize('caller,expected', [(ALICE, ['renew']), (BOB, [])])
async def test_proxy_queue_preserves_owner_without_leaking_context(service, tenant_context, caller, expected):
    from opensandbox_server.extensions.keys import ACCESS_RENEW_EXTEND_SECONDS_METADATA_KEY
    from opensandbox_server.integrations.renew_intent.consumer import RenewIntentConsumer
    workload = _workload('target', 'alice')
    workload['metadata']['annotations'][ACCESS_RENEW_EXTEND_SECONDS_METADATA_KEY] = '60'
    provider = MutationProvider([workload])
    service.workload_provider = provider
    service.app_config.renew_intent.enabled = True
    consumer = RenewIntentConsumer(service.app_config, service, service, None)
    tenant_context(caller)
    await consumer._enqueue_proxy('target')
    work = await consumer._work_queue.get()
    assert work.tenant is not None
    assert work.tenant.api_keys == ()
    tenant_context(None)
    await consumer._process_work(work)
    assert provider.effects == expected
    assert get_current_tenant() is None


@pytest.mark.asyncio
async def test_stale_proxy_identity_is_not_reused(service, tenant_context):
    from datetime import datetime, timedelta, timezone
    from opensandbox_server.integrations.renew_intent.consumer import RenewIntentConsumer, RenewWorkItem
    from opensandbox_server.integrations.renew_intent.logutil import RENEW_SOURCE_SERVER_PROXY
    provider = MutationProvider([_workload('target', 'alice')])
    service.workload_provider = provider
    consumer = RenewIntentConsumer(service.app_config, service, service, None)
    tenant_context(BOB)
    work = RenewWorkItem(source=RENEW_SOURCE_SERVER_PROXY, sandbox_id='target', observed_at=datetime.now(timezone.utc) - timedelta(seconds=301), tenant=ALICE)
    await consumer._process_work(work)
    assert provider.get_calls == provider.effects == []
    assert get_current_tenant() == BOB


def test_rotated_key_same_subject_and_paginated_owner_count(service, tenant_context):
    from opensandbox_server.api.schema import ListSandboxesRequest
    provider = MutationProvider([_workload('own', 'alice'), _workload('foreign', 'bob')])
    service.workload_provider = provider
    tenant_context(TenantEntry(name='rotated-name', namespace=STAGE_NAMESPACE, subject='alice', api_keys=('new-synthetic-key',)))
    page = service.list_sandboxes(ListSandboxesRequest.model_validate(dict(pagination={'page': 1, 'pageSize': 1})))
    assert page.pagination.total_items == 1
    assert [item.id for item in page.items] == ['own']
    assert service.get_sandbox('own').id == 'own'


@pytest.mark.asyncio
@pytest.mark.parametrize("strict", [False, True])
async def test_strict_creation_rejects_shared_host_path_before_effects(service, tenant_context, strict):
    from opensandbox_server.api.schema import CreateSandboxRequest
    service.app_config.tenants.enforce_ownership = strict
    service.app_config.storage.allowed_host_paths = ['/tmp']
    provider = CreationProvider([])
    service.workload_provider = provider
    tenant_context(ALICE)
    request = CreateSandboxRequest.model_validate(dict(image={'uri': 'alpine:3.20'}, entrypoint=['sleep', '60'], timeout=60, resourceLimits={'cpu': '1'}, volumes=[{'name': 'host', 'mountPath': '/data', 'host': {'path': '/tmp'}}]))
    if not strict:
        await service.create_sandbox(request)
        assert provider.effects == ['create']
        return
    with pytest.raises(HTTPException) as exc:
        await service.create_sandbox(request)
    assert exc.value.status_code == 400
    assert provider.effects == []


@pytest.mark.parametrize('operation', ['get_sandbox_logs', 'get_sandbox_inspect', 'get_sandbox_events', 'get_sandbox_log_diagnostics', 'get_sandbox_event_diagnostics'])
@pytest.mark.parametrize('owner', ['bob', None])
def test_foreign_diagnostics_denied_before_pod_access(service, tenant_context, operation, owner):
    from unittest.mock import MagicMock
    client = MagicMock()
    client.list_pods.return_value = []
    service.k8s_client = client
    service.workload_provider = MutationProvider([_workload('target', owner)])
    tenant_context(ALICE)
    with pytest.raises(HTTPException) as exc:
        args = ('target', 'all') if operation.endswith('_diagnostics') else ('target',)
        getattr(service, operation)(*args)
    assert exc.value.status_code == 404
    client.list_pods.assert_not_called()
    client.get_core_v1_api.assert_not_called()


def test_owned_diagnostics_can_read_logs(service, tenant_context):
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    client = MagicMock()
    client.list_pods.return_value = [SimpleNamespace(metadata=SimpleNamespace(name='pod', namespace=STAGE_NAMESPACE), spec=SimpleNamespace(containers=[SimpleNamespace(name='sandbox')], init_containers=[]))]
    client.get_core_v1_api.return_value.read_namespaced_pod_log.return_value = 'owned logs'
    service.k8s_client = client
    service.workload_provider = MutationProvider([_workload('target', 'alice')])
    tenant_context(ALICE)
    assert service.get_sandbox_logs('target') == 'owned logs'


def test_strict_factory_does_not_add_unprotected_fsb_backend(service):
    from opensandbox_server.services.factory import create_sandbox_service
    with patch('opensandbox_server.services.k8s.kubernetes_service.K8sClient'):
        created = create_sandbox_service(config=service.app_config)
    assert isinstance(created, KubernetesSandboxService)


@pytest.mark.asyncio
async def test_strict_template_create_cannot_fall_through_to_container(service, tenant_context):
    from opensandbox_server.api.schema import CreateSandboxRequest
    provider = CreationProvider([])
    service.workload_provider = provider
    tenant_context(ALICE)
    with pytest.raises(HTTPException) as exc:
        await service.create_sandbox(CreateSandboxRequest.model_validate(dict(templateId='some-template', timeout=60)))
    assert exc.value.status_code == 400
    assert provider.effects == []


@pytest.mark.parametrize('module_name,getter', [('pool', '_get_pool_service'), ('templates', '_get_template_service')])
def test_strict_shared_admin_services_denied(service, tenant_context, monkeypatch, module_name, getter):
    import importlib
    module = importlib.import_module('opensandbox_server.api.' + module_name)
    monkeypatch.setattr(module, 'get_config', lambda: service.app_config)
    if module_name == 'templates':
        monkeypatch.setattr(module, '_service', object())
    tenant_context(ALICE)
    with pytest.raises(HTTPException) as exc:
        getattr(module, getter)()
    assert exc.value.status_code == 403
