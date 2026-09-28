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

"""WM-15: with a tenant provider, an informer the API server will keep refusing is
reported once, not with a traceback per retry.

The shape is the one measured on a live multi-tenant installation (the same one as
WM-13): RBAC grants the server a Role in each tenant namespace and nothing else,
``[kubernetes] namespace`` names a fallback that deliberately does not exist, and the
``sandbox.fast.io`` CRDs are not installed. Four informers were then refused for as
long as the server ran, each logging a WARNING with a full traceback about every 30 s
-- 120 tracebacks in 15 minutes:

- ``sandboxsnapshots`` in ``sandbox.opensandbox.io`` and in ``sandbox.fast.io``, on
  the fallback, started by the snapshot status watch ("the given namespaces plus the
  configured default"): 403;
- ``batchsandboxes`` on the fallback, started lazily by the renew lookup's first read
  there (WM-13 lets that lookup go on past the 403; the informer it started stayed):
  403;
- ``sandboxes`` in ``sandbox.fast.io`` on the tenant namespace, started lazily by
  ``GET /sandboxes``: 404, the resource is not served. The read path already treats
  that as an empty list.

The informers are the real ones, driven through the entry points the server itself
uses; only the Kubernetes API underneath is a double, and the retry wait is skipped.
"""

import logging
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from kubernetes import client as k8s_api
from kubernetes.client import ApiException

from opensandbox_server.config import (
    AppConfig,
    KubernetesRuntimeConfig,
    RuntimeConfig,
    ServerConfig,
    TenantsConfig,
)
from opensandbox_server.services.k8s import client as k8s_client_module
from opensandbox_server.services.k8s.client import K8sClient
from opensandbox_server.services.k8s.informer import WorkloadInformer
from opensandbox_server.tenants.context import (
    reset_resolved_sandbox_ns,
    set_observed_namespace,
)
from opensandbox_server.tenants.models import TenantEntry

FALLBACK_NS = "fallback-that-does-not-exist"
TENANT_NS = "tenant-alpha"
INFORMER_LOGGER = "opensandbox_server.services.k8s.informer"
# How many times each informer is refused before the test stops it. Upstream logs one
# traceback per refusal, so anything above one tells "once" from "every time".
REFUSALS = 4


def _app_config(*, multi_tenant: bool) -> AppConfig:
    return AppConfig(
        server=ServerConfig(
            host="0.0.0.0",
            port=8080,
            # A tenant provider and a server API key are mutually exclusive.
            api_key=None if multi_tenant else "test-api-key",
        ),
        runtime=RuntimeConfig(type="kubernetes", execd_image="ghcr.io/opensandbox/execd:test"),
        kubernetes=KubernetesRuntimeConfig(namespace=FALLBACK_NS, workload_provider="batchsandbox"),
        tenants=TenantsConfig(provider="file") if multi_tenant else None,
    )


def _refusal(status: int, plural: str, group: str, namespace: str) -> ApiException:
    if status == 404:
        return ApiException(status=404, reason="Not Found")
    return ApiException(
        status=status,
        reason=(
            f'Forbidden: cannot list resource "{plural}" in API group "{group}" '
            f'in the namespace "{namespace}"'
        )
        if status == 403
        else "Internal Server Error",
    )


@pytest.fixture
def cluster(monkeypatch):
    """Real informers over a fake API. ``cluster.refuse[(group, plural, ns)] = status``
    makes every LIST there fail with that status; everything else lists empty.
    ``cluster.informers`` collects every informer K8sClient creates, unstarted."""
    state = SimpleNamespace(refuse={}, informers=[])

    class RecordedInformer(WorkloadInformer):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            state.informers.append(self)

        def start(self):  # driven by the test, not by a thread
            return None

    def list_namespaced_custom_object(group, version, namespace, plural, **kwargs):
        status = state.refuse.get((group, plural, namespace))
        if status is not None:
            raise _refusal(status, plural, group, namespace)
        return {"items": [], "metadata": {"resourceVersion": "1"}}

    api = MagicMock()
    api.list_namespaced_custom_object.side_effect = list_namespaced_custom_object
    api.get_namespaced_custom_object.side_effect = (
        lambda group, version, namespace, plural, name, **kw: (_ for _ in ()).throw(
            _refusal(state.refuse.get((group, plural, namespace), 404), plural, group, namespace)
        )
    )
    api.list_cluster_custom_object.side_effect = ApiException(status=403, reason="Forbidden")

    # tests/k8s/conftest.py stubs the informer out of K8sClient; these tests are about it.
    monkeypatch.setattr(k8s_client_module, "WorkloadInformer", RecordedInformer)
    monkeypatch.setattr(K8sClient, "_load_config", lambda self: None)
    monkeypatch.setattr(k8s_api, "CustomObjectsApi", lambda *a, **kw: api)
    monkeypatch.setattr(k8s_api, "CoreV1Api", lambda *a, **kw: MagicMock())
    # No real waiting between retries; the ladder itself is unchanged.
    monkeypatch.setattr(
        WorkloadInformer, "_wait_before_retry", lambda self, backoff: min(backoff * 2, 30.0)
    )
    return state


def _informer_on(cluster, plural: str, group: str, namespace: str) -> WorkloadInformer:
    matches = [
        informer
        for informer in cluster.informers
        if (informer.list_fn.keywords["group"], informer.list_fn.keywords["plural"],
            informer.list_fn.keywords["namespace"]) == (group, plural, namespace)
    ]
    assert len(matches) == 1, (
        f"expected one informer for {plural}.{group} in {namespace}, "
        f"found {[i.list_fn.keywords for i in cluster.informers]}"
    )
    return matches[0]


def _run_refused(informer: WorkloadInformer, refusals: int = REFUSALS) -> None:
    """Run the informer's own loop until its LIST has been refused ``refusals`` times."""
    list_fn = informer.list_fn
    calls = {"n": 0}

    def counted():
        calls["n"] += 1
        if calls["n"] >= refusals:
            informer.stop()
        return list_fn()

    informer.list_fn = counted
    informer._run()
    assert calls["n"] == refusals


class _Records(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.records: list = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.fixture
def informer_log():
    """The informer's own records. Not pytest's caplog: the app's logging dictConfig
    stops propagation below ``opensandbox_server``, so records never reach the root
    logger that caplog listens on."""
    handler = _Records()
    logger = logging.getLogger(INFORMER_LOGGER)
    previous = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        yield handler
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous)


def _informer_records(informer_log, levelno: int):
    return [r for r in informer_log.records if r.name == INFORMER_LOGGER and r.levelno == levelno]


def _assert_reported_once(informer_log, status: int) -> None:
    warnings = _informer_records(informer_log, logging.WARNING)
    assert not warnings, (
        f"{len(warnings)} WARNING(s) for a refusal this deployment makes on purpose, "
        f"{sum(1 for r in warnings if r.exc_info)} with a traceback: "
        f"{warnings[0].getMessage()[:200]!r}"
    )
    infos = [r for r in _informer_records(informer_log, logging.INFO) if f"({status} " in r.getMessage()]
    assert len(infos) == 1, [r.getMessage() for r in _informer_records(informer_log, logging.INFO)]
    assert infos[0].exc_info is None


# -- the four informers measured -------------------------------------------------------


@pytest.mark.parametrize(
    "group,plural",
    [("sandbox.opensandbox.io", "sandboxsnapshots"), ("sandbox.fast.io", "sandboxsnapshots")],
)
def test_wm15_snapshot_watch_on_a_forbidden_fallback_is_reported_once(cluster, informer_log, group, plural):
    from opensandbox_server.services.snapshot_runtime_factory import create_snapshot_runtime

    cluster.refuse[(group, plural, FALLBACK_NS)] = 403
    runtime = create_snapshot_runtime(_app_config(multi_tenant=True))
    runtime.start_status_watch(lambda snapshot_id, namespace: None, namespaces=[TENANT_NS])

    _run_refused(_informer_on(cluster, plural, group, FALLBACK_NS))

    _assert_reported_once(informer_log, 403)


def _multi_tenant_service():
    from opensandbox_server.services.k8s.kubernetes_service import KubernetesSandboxService

    service = KubernetesSandboxService(_app_config(multi_tenant=True))
    service.set_tenant_provider(
        SimpleNamespace(list_tenants=lambda: [TenantEntry(name="alpha", namespace=TENANT_NS, api_keys=["k"])])
    )
    return service


def test_wm15_renew_lookup_informer_on_a_forbidden_fallback_is_reported_once(cluster, informer_log):
    cluster.refuse[("sandbox.opensandbox.io", "batchsandboxes", FALLBACK_NS)] = 403
    service = _multi_tenant_service()
    reset_resolved_sandbox_ns()
    set_observed_namespace(None)
    # The renew worker's lookup: its first read, of the fallback, starts the informer.
    # Whether the lookup then goes on past the 403 is WM-13's business, not this one's.
    try:
        service._find_sandbox_namespace("sbx-missing")
    except ApiException as exc:
        assert exc.status == 403

    _run_refused(_informer_on(cluster, "batchsandboxes", "sandbox.opensandbox.io", FALLBACK_NS))

    _assert_reported_once(informer_log, 403)


def test_wm15_fsb_list_informer_for_an_api_not_served_is_reported_once(cluster, informer_log):
    from opensandbox_server.services.fast_sandbox.cr_reader import SandboxCRReader

    cluster.refuse[("sandbox.fast.io", "sandboxes", TENANT_NS)] = 404
    service = _multi_tenant_service()
    # GET /sandboxes in the tenant's context: the fsb half lists the tenant namespace.
    assert SandboxCRReader(service.app_config.kubernetes, service.k8s_client).list(TENANT_NS) == []

    _run_refused(_informer_on(cluster, "sandboxes", "sandbox.fast.io", TENANT_NS))

    _assert_reported_once(informer_log, 404)


def test_wm15_template_watch_on_a_forbidden_fallback_is_reported_once(cluster, informer_log):
    from opensandbox_server.services.templates.template_service import FastSandboxTemplateService

    cluster.refuse[("sandbox.fast.io", "sandboxtemplates", FALLBACK_NS)] = 403
    repository = MagicMock()
    repository.namespaces.return_value = [TENANT_NS]
    FastSandboxTemplateService(_app_config(multi_tenant=True), repository=repository).start_background_sync()

    _run_refused(_informer_on(cluster, "sandboxtemplates", "sandbox.fast.io", FALLBACK_NS))

    _assert_reported_once(informer_log, 403)


def test_wm15_a_refusal_after_a_successful_list_is_reported_again(cluster, informer_log):
    from opensandbox_server.services.snapshot_runtime_factory import create_snapshot_runtime

    group, plural = "sandbox.opensandbox.io", "sandboxsnapshots"
    key = (group, plural, FALLBACK_NS)
    runtime = create_snapshot_runtime(_app_config(multi_tenant=True))
    runtime.start_status_watch(lambda snapshot_id, namespace: None)
    informer = _informer_on(cluster, plural, group, FALLBACK_NS)
    # One LIST per cycle and no wait after a good one, so the sequence below is exact.
    informer.enable_watch = False
    informer.resync_period_seconds = 0

    # Refused, refused, granted, refused. The second refusal is the state already
    # reported and stays quiet; the one after the grant is news and is reported.
    script = [403, 403, None, 403]
    list_fn = informer.list_fn

    def scripted():
        status = script.pop(0)
        if not script:
            informer.stop()
        if status is None:
            cluster.refuse.pop(key, None)
        else:
            cluster.refuse[key] = status
        return list_fn()

    informer.list_fn = scripted
    informer._run()

    assert script == []
    assert not _informer_records(informer_log, logging.WARNING)
    reported = [r for r in _informer_records(informer_log, logging.INFO) if "(403 " in r.getMessage()]
    assert len(reported) == 2, [r.getMessage() for r in _informer_records(informer_log, logging.INFO)]


# -- guards: what must stay as upstream has it ------------------------------------------


def test_wm15_single_tenant_refusals_still_warn_with_a_traceback_each_time(cluster, informer_log):
    from opensandbox_server.services.snapshot_runtime_factory import create_snapshot_runtime

    group, plural = "sandbox.opensandbox.io", "sandboxsnapshots"
    cluster.refuse[(group, plural, FALLBACK_NS)] = 403
    runtime = create_snapshot_runtime(_app_config(multi_tenant=False))
    runtime.start_status_watch(lambda snapshot_id, namespace: None)

    _run_refused(_informer_on(cluster, plural, group, FALLBACK_NS))

    warnings = _informer_records(informer_log, logging.WARNING)
    assert len(warnings) == REFUSALS
    assert all(r.exc_info for r in warnings)


@pytest.mark.parametrize(
    "namespace,status",
    [
        # The namespace the server exists to serve: a 403 there is a real failure.
        (TENANT_NS, 403),
        # Anything but an expected refusal, even on the fallback.
        (FALLBACK_NS, 500),
    ],
)
def test_wm15_other_refusals_still_warn_with_a_traceback_each_time(cluster, informer_log, namespace, status):
    from opensandbox_server.services.snapshot_runtime_factory import create_snapshot_runtime

    group, plural = "sandbox.opensandbox.io", "sandboxsnapshots"
    cluster.refuse[(group, plural, namespace)] = status
    runtime = create_snapshot_runtime(_app_config(multi_tenant=True))
    runtime.start_status_watch(lambda snapshot_id, ns: None, namespaces=[TENANT_NS])

    _run_refused(_informer_on(cluster, plural, group, namespace))

    warnings = _informer_records(informer_log, logging.WARNING)
    assert len(warnings) == REFUSALS
    assert all(r.exc_info for r in warnings)
