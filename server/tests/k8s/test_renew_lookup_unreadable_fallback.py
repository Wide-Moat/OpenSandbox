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

"""WM-13: a background renew must find a tenant's sandbox when the server may not
read its configured (fallback) namespace.

The shape is the one measured on a live multi-tenant installation: RBAC grants the
server a Role in each tenant namespace and nothing else, and ``[kubernetes] namespace``
names a namespace that deliberately does not exist. Every read there is a 403, and
so is the cluster-wide LIST. Requests carry their tenant and never look there; the
renew worker has no tenant, and its lookup read the fallback first and let the 403
end the whole lookup -- before the tenant namespaces it knew about were tried. So a
proxied request scheduled a renew on every hit and the expiry never moved.

The 403s below are what ``K8sClient.get_custom_object`` does with any status but
404: it re-raises the ``ApiException``.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException
from kubernetes.client import ApiException

from opensandbox_server.integrations.renew_intent.controller import AccessRenewController
from opensandbox_server.integrations.renew_intent.intent import RenewIntent
from opensandbox_server.integrations.renew_intent.logutil import (
    RENEW_SOURCE_REDIS_QUEUE,
    RENEW_SOURCE_SERVER_PROXY,
)
from opensandbox_server.tenants.context import (
    reset_resolved_sandbox_ns,
    set_observed_namespace,
)
from opensandbox_server.tenants.models import TenantEntry

FALLBACK_NS = "fallback-that-does-not-exist"
TENANT_NS = "tenant-alpha"
SANDBOX_ID = "test-sandbox-123"


def _forbidden(namespace: str) -> ApiException:
    return ApiException(
        status=403,
        reason=(
            'Forbidden: cannot get resource "batchsandboxes" in API group '
            f'"sandbox.opensandbox.io" in the namespace "{namespace}"'
        ),
    )


def _stage_tenant_scoped_rbac(k8s_service, mock_workload, *, sandbox_ns: str = TENANT_NS):
    """The server can read the tenant namespace and nothing else; the sandbox is in
    ``sandbox_ns``. Returns the reads made, as (sandbox_id, namespace)."""
    # The lookup memoizes per context, and pytest runs every test in one: a
    # resolution left by the previous test would answer this one's lookup.
    reset_resolved_sandbox_ns()
    set_observed_namespace(None)
    k8s_service.namespace = FALLBACK_NS
    reads: list[tuple[str, str]] = []

    def get_workload(sandbox_id, namespace):
        reads.append((sandbox_id, namespace))
        if namespace != TENANT_NS:
            raise _forbidden(namespace)
        return mock_workload if namespace == sandbox_ns else None

    def list_all(*args, **kwargs):
        raise ApiException(status=403, reason="Forbidden: cannot list at cluster scope")

    provider = k8s_service.workload_provider
    provider.get_workload.side_effect = get_workload
    provider.list_workloads_all_namespaces.side_effect = list_all
    provider.get_status.return_value = {
        "state": "Running",
        "reason": "",
        "message": "Running",
        "last_transition_at": datetime.now(timezone.utc),
    }
    provider.get_endpoint_info.return_value = "10.0.0.1:8080"
    provider.get_expiration.return_value = datetime.now(timezone.utc) + timedelta(minutes=10)
    provider.update_expiration.return_value = None
    return reads


def _tenant_provider_knowing_the_tenant() -> MagicMock:
    """The HTTP provider after the proxied request itself was authenticated: the
    caller's tenant is in its cache, which is all ``list_tenants`` returns."""
    provider = MagicMock()
    provider.list_tenants.return_value = [
        TenantEntry(name=TENANT_NS, namespace=TENANT_NS, api_keys=("k",))
    ]
    return provider


def _controller(k8s_service) -> AccessRenewController:
    extension_service = MagicMock()
    extension_service.get_access_renew_extend_seconds.return_value = 600
    return AccessRenewController(k8s_service, extension_service)


def test_wm13_proxy_renew_reaches_the_tenant_namespace_past_a_forbidden_fallback(
    k8s_service, mock_workload
):
    reads = _stage_tenant_scoped_rbac(k8s_service, mock_workload)
    k8s_service.set_tenant_provider(_tenant_provider_knowing_the_tenant())

    ok = _controller(k8s_service).attempt_renew_sync(
        SANDBOX_ID, source=RENEW_SOURCE_SERVER_PROXY
    )

    assert ok is True, (
        f"the renew was dropped: a 403 on {FALLBACK_NS} ended the lookup before "
        f"{TENANT_NS} was tried (reads: {reads})"
    )
    assert (SANDBOX_ID, TENANT_NS) in reads
    k8s_service.workload_provider.update_expiration.assert_called_once()
    update = k8s_service.workload_provider.update_expiration.call_args
    assert TENANT_NS in list(update.args) + list(update.kwargs.values()), (
        f"renewed, but not in the sandbox's namespace: {update}"
    )


def test_wm13_queued_renew_uses_the_observed_namespace_past_a_forbidden_fallback(
    k8s_service, mock_workload
):
    """The Redis source carries the namespace ingress observed. It is tried after the
    fallback read, so a forbidden fallback hid it too -- even with no tenant known."""
    reads = _stage_tenant_scoped_rbac(k8s_service, mock_workload)
    tenants = MagicMock()
    tenants.list_tenants.return_value = []
    k8s_service.set_tenant_provider(tenants)

    intent = RenewIntent(
        sandbox_id=SANDBOX_ID,
        observed_at=datetime.now(timezone.utc),
        namespace=TENANT_NS,
    )
    asyncio.run(_controller(k8s_service).process_intent_after_lock(intent))

    assert (SANDBOX_ID, TENANT_NS) in reads, f"the observed namespace was never read: {reads}"
    k8s_service.workload_provider.update_expiration.assert_called_once()


def test_wm13_single_tenant_still_reports_the_configured_namespace_error(
    k8s_service, mock_workload
):
    """Without a tenant provider the configured namespace is the only one the server
    owns, so its error stays the answer, and nothing else is read."""
    reads = _stage_tenant_scoped_rbac(k8s_service, mock_workload)

    with pytest.raises(HTTPException) as err:
        k8s_service.get_sandbox(SANDBOX_ID)

    assert "403" in str(err.value.detail)
    # Once: the forbidden read is not skipped and then repeated.
    assert reads == [(SANDBOX_ID, FALLBACK_NS)]
    k8s_service.workload_provider.list_workloads_all_namespaces.assert_not_called()


class _CapturingHandler(logging.Handler):
    """The app's dictConfig stops propagation, so caplog cannot see these records."""

    def __init__(self) -> None:
        super().__init__(level=logging.WARNING)
        self.records: list = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def test_wm13_a_sandbox_in_no_readable_namespace_still_fails_with_the_403(
    k8s_service, mock_workload
):
    """Skipping the forbidden fallback must not turn a real failure into a quiet one:
    when no namespace resolves, the renew is dropped with the fallback's own 403 in
    the warning, as before."""
    _stage_tenant_scoped_rbac(k8s_service, mock_workload, sandbox_ns="elsewhere")
    k8s_service.set_tenant_provider(_tenant_provider_knowing_the_tenant())

    handler = _CapturingHandler()
    controller_logger = logging.getLogger(
        "opensandbox_server.integrations.renew_intent.controller"
    )
    controller_logger.addHandler(handler)
    try:
        ok = _controller(k8s_service).attempt_renew_sync(
            SANDBOX_ID, source=RENEW_SOURCE_REDIS_QUEUE
        )
    finally:
        controller_logger.removeHandler(handler)

    assert ok is False
    k8s_service.workload_provider.update_expiration.assert_not_called()
    failures = [r.getMessage() for r in handler.records if "get_sandbox_failed" in r.getMessage()]
    assert failures, "the dropped renew left no warning"
    assert "403" in failures[0] and FALLBACK_NS in failures[0]
