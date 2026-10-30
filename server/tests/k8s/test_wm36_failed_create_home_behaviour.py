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

"""WM-36 behaviour, written with nothing upstream lacks, so it FAILS there rather than not building.

A create that makes a persistent claim (``createIfNotExists=true``, ``deleteOnSandboxTermination=
false`` -- a home meant to outlive its sandboxes) and then never becomes ready used to leave that
claim behind: the rollback swept only claims labelled for deletion, and a persistent one carries
no label by design. Measured 2026-10-30 in a 16-person room: one Bound 10 Gi claim per failed
create, 25 after two runs, and on 2026-10-16 a home quota of 80/80. The create returned no id, so
nobody could ever delete it through the API.

Now a claim the failed create itself made is deleted with the workload -- held to its uid and
the resourceVersion read, and only while it still carries that create's ``provisional-for``
mark, which any other create mounting the claim removes first. A claim that existed before the
create is never touched. A create that finds its claim still being deleted waits for it to go
and makes a fresh one, instead of mounting a claim no pod can start with.

The fake API below is a dict of claims; the names it is reached by are upstream's client methods
(``get_pvc``, ``create_pvc``, ``delete_pvc``) plus this change's ``patch_pvc_json``, which on
upstream is an attribute of a MagicMock: called nowhere, so the assertions fail on behaviour.
"""

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException
from kubernetes.client import ApiException

from opensandbox_server.api.schema import PVC, CreateSandboxRequest, ImageSpec, ResourceLimits, Volume

HOME = "osb-home-0123456789abcdef"
MARK = "opensandbox.io/provisional-for"


def _request() -> CreateSandboxRequest:
    return CreateSandboxRequest(
        image=ImageSpec(uri="python:3.11"),
        entrypoint=["/bin/bash", "-c", "sleep 3600"],
        timeout=3600,
        resourceLimits=ResourceLimits(root={"cpu": "1", "memory": "1Gi"}),
        volumes=[
            Volume(
                name="home",
                mountPath="/home/user",
                pvc=PVC(claimName=HOME, createIfNotExists=True, deleteOnSandboxTermination=False),
            )
        ],
    )


def _pvc(uid: str, annotations=None, deleting: bool = False, version: str = "7") -> SimpleNamespace:
    return SimpleNamespace(
        metadata=SimpleNamespace(
            name=HOME,
            uid=uid,
            resource_version=version,
            labels=None,
            annotations=dict(annotations) if annotations else None,
            deletion_timestamp=datetime.now(timezone.utc) if deleting else None,
        )
    )


class FakeClaims:
    """The namespace's claims: ``before`` is what get_pvc answers until a create makes one."""

    def __init__(self, k8s_service, before=None):
        self.before = list(before or [])
        self.made = None
        client = k8s_service.k8s_client
        client.get_pvc.side_effect = self.get
        client.create_pvc.side_effect = self.create

    def get(self, _namespace, _name):
        if self.made is not None:
            return self.made
        if len(self.before) > 1:
            return self.before.pop(0)
        return self.before[0] if self.before else None

    def create(self, _namespace, body):
        self.made = _pvc("home-uid", body.metadata.annotations)
        return self.made


async def _never_ready(*_args, **_kwargs):
    raise HTTPException(
        status_code=504,
        detail={"code": "KUBERNETES::POD_READY_TIMEOUT", "message": "pod never ready"},
    )


def _workload(k8s_service) -> None:
    k8s_service.workload_provider.create_workload.return_value = {
        "name": "sbx",
        "uid": "cr-uid",
        "apiVersion": "sandbox.opensandbox.io/v1alpha1",
        "kind": "BatchSandbox",
    }


async def _create(k8s_service, ready=_never_ready):
    _workload(k8s_service)
    with patch.object(k8s_service, "_wait_for_sandbox_ready", ready):
        return await k8s_service.create_sandbox(_request())


async def _fail_create(k8s_service) -> HTTPException:
    with pytest.raises(HTTPException) as exc_info:
        await _create(k8s_service)
    return exc_info.value


def _deleted(k8s_service) -> list:
    return [
        (c.args[1] if len(c.args) > 1 else c.kwargs.get("name"), c.kwargs.get("uid"), c.kwargs.get("resource_version"))
        for c in k8s_service.k8s_client.delete_pvc.call_args_list
    ]


def _this_sandbox(k8s_service) -> str:
    return k8s_service.workload_provider.create_workload.call_args.kwargs["sandbox_id"]


def _mark_ops(sandbox_id: str, version=None) -> list:
    path = "/metadata/annotations/opensandbox.io~1provisional-for"
    held = [{"op": "test", "path": "/metadata/resourceVersion", "value": version}] if version else []
    return held + [{"op": "test", "path": path, "value": sandbox_id}, {"op": "remove", "path": path}]


@pytest.mark.asyncio
async def test_wm36_a_home_made_by_a_create_that_never_became_ready_is_deleted(k8s_service):
    FakeClaims(k8s_service)

    assert (await _fail_create(k8s_service)).status_code == 504

    # Upstream: nothing deleted -- the claim stays Bound and counts against the quota for good.
    assert _deleted(k8s_service) == [(HOME, "home-uid", "7")]
    assert k8s_service.k8s_client.create_pvc.call_args.args[1].metadata.annotations[MARK] == _this_sandbox(k8s_service)


@pytest.mark.asyncio
async def test_wm36_a_home_that_existed_before_the_create_is_kept(k8s_service):
    # A person's real home: it was there before this create, so a failed create must not touch it.
    FakeClaims(k8s_service, before=[_pvc("their-home")])

    await _fail_create(k8s_service)

    k8s_service.k8s_client.create_pvc.assert_not_called()
    assert _deleted(k8s_service) == []


@pytest.mark.asyncio
async def test_wm36_a_new_home_another_create_has_taken_is_kept(k8s_service):
    # A second create of the same chat found the claim this create made and mounts it: it removed
    # this create's mark first, so the claim is no longer this create's to delete. (Taken after
    # the rollback's read instead, the delete is held to the resourceVersion read and refused.)
    claims = FakeClaims(k8s_service)
    k8s_service.k8s_client.get_pvc.side_effect = lambda ns, name: (
        _pvc("home-uid") if claims.made is not None else None
    )

    assert (await _fail_create(k8s_service)).status_code == 504

    assert _deleted(k8s_service) == []


@pytest.mark.asyncio
async def test_wm36_a_home_still_being_deleted_is_waited_out_and_made_again(k8s_service):
    # The retry that follows a failed create at once finds the claim that create deleted still
    # Terminating (its pod is going). Mounting it cannot work -- no pod starts on a claim being
    # deleted -- so the create waits for it to go and makes a fresh one.
    FakeClaims(k8s_service, before=[_pvc("old-uid", deleting=True), _pvc("old-uid", deleting=True), None])

    await _fail_create(k8s_service)

    # Upstream: the Terminating claim counts as existing, nothing is created, nothing deleted.
    k8s_service.k8s_client.create_pvc.assert_called_once()
    assert _deleted(k8s_service) == [(HOME, "home-uid", "7")]


@pytest.mark.asyncio
async def test_wm36_a_home_still_being_deleted_after_the_wait_is_a_503_before_any_workload(
    k8s_service, monkeypatch
):
    import opensandbox_server.services.k8s.kubernetes_service as module

    monkeypatch.setattr(module, "_TERMINATING_PVC_WAIT_SECONDS", 0.0, raising=False)
    FakeClaims(k8s_service, before=[_pvc("old-uid", deleting=True)])

    error = await _fail_create(k8s_service)

    # Upstream: the claim is mounted, a workload made, and the create times out with 504.
    assert error.status_code == 503
    assert error.detail["code"] == "KUBERNETES::API_ERROR"
    k8s_service.workload_provider.create_workload.assert_not_called()


@pytest.mark.asyncio
async def test_wm36_mounting_a_home_another_create_made_takes_its_mark(k8s_service, mock_workload):
    FakeClaims(k8s_service, before=[_pvc("their-new-home", {MARK: "the-other-create"})])
    k8s_service.workload_provider.get_status.return_value = {
        "state": "Running",
        "reason": "",
        "message": "",
        "last_transition_at": datetime.now(timezone.utc),
    }

    await _create(k8s_service, ready=AsyncMock(return_value=mock_workload))

    # The other create's rollback can no longer delete it. Upstream: the claim is left as found.
    k8s_service.k8s_client.patch_pvc_json.assert_any_call(
        k8s_service._resolve_namespace(), HOME, _mark_ops("the-other-create", "7")
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("after_the_rollback", ["gone", "held_by_a_finalizer"])
async def test_wm36_mounting_a_home_its_failed_creator_is_deleting_is_a_503(k8s_service, after_the_rollback):
    # The mark could not be taken: the rollback's DELETE landed first, which changed the claim's
    # resourceVersion, so the patch's test of it failed. The claim is gone, or still there held
    # by a finalizer with its mark intact. Mounting it cannot work; the create is refused to retry.
    after = None if after_the_rollback == "gone" else _pvc("their-new-home", {MARK: "the-other-create"}, deleting=True)
    FakeClaims(k8s_service, before=[_pvc("their-new-home", {MARK: "the-other-create"}), after])
    k8s_service.k8s_client.patch_pvc_json.side_effect = ApiException(status=422, reason="test failed")

    error = await _fail_create(k8s_service)

    # Upstream: the claim is mounted as found, a workload made, and the create times out (504).
    assert error.status_code == 503
    k8s_service.workload_provider.create_workload.assert_not_called()


@pytest.mark.asyncio
async def test_wm36_a_create_that_succeeds_clears_its_mark(k8s_service, mock_workload):
    FakeClaims(k8s_service)
    k8s_service.workload_provider.get_status.return_value = {
        "state": "Running",
        "reason": "",
        "message": "",
        "last_transition_at": datetime.now(timezone.utc),
    }

    await _create(k8s_service, ready=AsyncMock(return_value=mock_workload))

    sandbox_id = _this_sandbox(k8s_service)
    k8s_service.k8s_client.patch_pvc_json.assert_called_once_with(
        k8s_service._resolve_namespace(), HOME, _mark_ops(sandbox_id)
    )
    assert _deleted(k8s_service) == []


@pytest.mark.asyncio
async def test_wm36_a_create_that_loses_the_create_race_takes_the_winners_mark(k8s_service):
    # Both creates saw no claim; the other one made it first (409 here). It may still fail and
    # roll its claim back, so this create takes the mark before it mounts the claim.
    k8s_service.k8s_client.get_pvc.side_effect = [None, _pvc("their-new-home", {MARK: "the-other-create"})]
    k8s_service.k8s_client.create_pvc.side_effect = ApiException(status=409, reason="AlreadyExists")

    await _fail_create(k8s_service)

    k8s_service.k8s_client.patch_pvc_json.assert_any_call(
        k8s_service._resolve_namespace(), HOME, _mark_ops("the-other-create", "7")
    )
    assert _deleted(k8s_service) == []  # not this create's to delete: it made nothing


@pytest.mark.asyncio
async def test_wm36_a_create_race_winner_already_being_deleted_is_a_503(k8s_service):
    # The claim this create lost the race for is already Terminating: its creator failed and
    # rolled it back. Taking the mark would succeed (a claim a finalizer holds is patchable) and
    # mount a claim no pod can start with.
    k8s_service.k8s_client.get_pvc.side_effect = [
        None,
        _pvc("their-new-home", {MARK: "the-other-create"}, deleting=True),
    ]
    k8s_service.k8s_client.create_pvc.side_effect = ApiException(status=409, reason="AlreadyExists")

    error = await _fail_create(k8s_service)

    # Upstream: the claim is mounted as found, a workload made, and the create times out (504).
    assert error.status_code == 503
    k8s_service.workload_provider.create_workload.assert_not_called()
