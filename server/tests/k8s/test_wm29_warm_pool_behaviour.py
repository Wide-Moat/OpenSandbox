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

"""WM-29: a warm pod is claimed per person, and per-person state is pushed into it.

Written with nothing upstream lacks, so it FAILS there rather than not building: the pool
is configured through a dict that upstream's AppConfig ignores (an unknown key), the
service is reached only through create_sandbox, and the sidecar and execd are an httpx
transport. Upstream has no warm path, so the create goes cold: no claim, nothing pushed,
and the assertions on what was claimed fail on behaviour.
"""

import asyncio
import base64
import hashlib
import hmac
import json
import time
import threading
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import httpx
import pytest
from fastapi import HTTPException

from opensandbox_server.api.schema import CreateSandboxRequest
from opensandbox_server.config import AppConfig
from opensandbox_server.services.k8s.batchsandbox_provider import BatchSandboxProvider

POOL = "osb-warm"
NS = "sandbox-ns"
IMAGE = "registry.example/sandbox@sha256:" + "a" * 64
KEY = "pool-egress-key-0123456789"
SUBJECT = "person-subject-1"
POD = f"{POOL}-x7k2p"
POD_UID = "0b5c1a52-pod-uid"
POD_IP = "10.42.9.9"
HOME = "osb-home-" + "c" * 40
SECRET = "sk-person-gateway-key-SECRET"
PRE_SCRIPT = "/opt/wm/fuse-mount.sh"

_ORIGINAL_CLIENT = httpx.AsyncClient


@pytest.fixture(autouse=True)
def _fresh_key_cache():
    # The key is cached per process; each test brings its own cluster.
    yield
    try:
        from opensandbox_server.services.k8s import warm_pool

        warm_pool._KEY_CACHE.clear()
    except ImportError:
        pass


def _config(**warm):
    pool = {
        "enabled": True,
        "name": POOL,
        "namespace": NS,
        "size": 3,
        "pool_max": 24,
        "image": IMAGE,
        "entrypoint": ["tail", "-f", "/dev/null"],
        "resource_limits": {"cpu": "2", "memory": "2Gi"},
        "resource_requests": {"cpu": "100m", "memory": "256Mi"},
        "env": {"EXECD_BOOTSTRAP_PRE_SCRIPT": PRE_SCRIPT, "WM_FUSE_AWAIT_CLAIM": "1"},
        "home_mount_path": "/home/user",
        "home_storage": "10Gi",
        "home_storage_class": "sandbox-thin",
        "claim_prestart": ["/opt/wm/fuse-claim.sh"],
    }
    pool.update(warm)
    return AppConfig.model_validate(
        {
            "server": {"host": "0.0.0.0", "port": 8080, "api_key": "test-api-key"},
            "runtime": {"type": "kubernetes", "execd_image": "ghcr.io/opensandbox/execd:test"},
            "kubernetes": {
                "kubeconfig_path": "/tmp/test-kubeconfig",
                "namespace": NS,
                "workload_provider": "batchsandbox",
            },
            "egress": {"image": "opensandbox/egress:test", "mode": "dns", "enforcement": "external", "disable_ipv6": False},
            "warm_pool": pool,
        }
    )


def _request(home=HOME, **overrides):
    body = {
        "image": {"uri": IMAGE},
        "entrypoint": ["tail", "-f", "/dev/null"],
        "timeout": 3600,
        "resourceLimits": {"cpu": "2", "memory": "2Gi"},
        "resourceRequests": {"cpu": "100m", "memory": "256Mi"},
        "metadata": {"owner": SUBJECT, "chat": "chat-1"},
        "env": {"EXECD_BOOTSTRAP_PRE_SCRIPT": PRE_SCRIPT, "WM_CHAT_ID": "chat-1", "HTTP_PROXY": "http://127.0.0.1:18081"},
        "networkPolicy": {"defaultAction": "deny", "egress": [{"action": "allow", "target": "gateway.example"}]},
        "credentialProxy": {
            "enabled": True,
            "seed": {
                "credentials": [{"name": "gw", "source": {"type": "inline", "value": SECRET}}],
                "bindings": [
                    {"name": "gw", "match": {"hosts": ["gateway.example"]}, "auth": {"type": "bearer", "credential": "gw"}}
                ],
            },
        },
        "volumes": [
            {
                "name": "home",
                "pvc": {"claimName": home, "createIfNotExists": True, "deleteOnSandboxTermination": False,
                        "storage": "10Gi", "storageClass": "sandbox-thin"},
                "mountPath": "/home/user",
                "readOnly": False,
            }
        ],
        "extensions": {"opensandbox.extensions.warm-pool": POOL},
    }
    body.update(overrides)
    return CreateSandboxRequest.model_validate(body)


class _Pod(SimpleNamespace):
    pass


def _pod():
    return _Pod(
        metadata=SimpleNamespace(name=POD, uid=POD_UID, labels={"opensandbox.io/warm-pool": POOL}),
        spec=SimpleNamespace(volumes=[SimpleNamespace(name="home", ephemeral=SimpleNamespace())]),
        status=SimpleNamespace(pod_ip=POD_IP),
    )


class _Env:
    """The cluster and the pod, as the server sees them."""

    def __init__(self, *, allocate=True, existing_pvcs=None, alias_pvcs=None, execd_status=200, execd_delay=0.0):
        self.client = MagicMock()
        self.custom = MagicMock()
        self.core = MagicMock()
        self.client.get_custom_objects_api.return_value = self.custom
        self.client.get_core_v1_api.return_value = self.core
        # The pool key's Secret, as the server made it.
        self.core.read_namespaced_secret.return_value = SimpleNamespace(
            data={"key": base64.b64encode(KEY.encode()).decode()}
        )
        self.created = []
        self.client.create_custom_object.side_effect = self._create
        self.client.get_custom_object.return_value = None
        self.client.list_custom_objects.return_value = []
        self.client.list_pods.return_value = []
        self.client.read_pod.side_effect = lambda ns, name: self.pod()
        self.revision = ""
        # The pod's home as the ephemeral-volume controller made it: controlled by the pod.
        self.core.read_namespaced_persistent_volume_claim.return_value = SimpleNamespace(
            metadata=SimpleNamespace(
                name=f"{POD}-home",
                uid="home-uid",
                labels={"opensandbox.io/warm-pool-home": POOL},
                owner_references=[SimpleNamespace(uid=POD_UID, controller=True, kind="Pod", name=POD)],
            )
        )
        # Home-name anchors: none until a test (or the claim) makes one.
        self.anchors = {}
        self.core.create_namespaced_config_map.side_effect = self._create_anchor
        self.core.read_namespaced_config_map.side_effect = self._read_anchor
        self.core.delete_namespaced_config_map.side_effect = lambda name, namespace: self.anchors.pop(name, None)
        self.existing_pvcs = existing_pvcs or {}
        self.client.get_pvc.side_effect = lambda ns, name: self.existing_pvcs.get(name)
        self.alias_pvcs = alias_pvcs or []
        self.client.list_pvcs.side_effect = lambda ns, selector="": list(self.alias_pvcs) if "home-alias" in selector else []
        self.allocate = allocate
        self.custom.get_namespaced_custom_object.side_effect = self._get_claim
        self.requests = []
        self.execd_status = execd_status
        self.execd_delay = execd_delay

    def _create_anchor(self, namespace, body):
        name = body["metadata"]["name"]
        if name in self.anchors:
            error = Exception("AlreadyExists")
            error.status = 409
            raise error
        self.anchors[name] = body
        return SimpleNamespace(metadata=SimpleNamespace(uid="anchor-uid", name=name))

    def _read_anchor(self, name, namespace):
        if name not in self.anchors:
            error = Exception("NotFound")
            error.status = 404
            raise error
        body = self.anchors[name]
        return SimpleNamespace(metadata=SimpleNamespace(uid="anchor-uid", name=name, annotations=body["metadata"]["annotations"]))

    def anchor(self, home_name, claim, state="committed", claimed_at=None):
        name = "osb-warm-home-" + hashlib.sha256(home_name.encode()).hexdigest()[:40]
        if claimed_at is None:
            claimed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        self.anchors[name] = {"metadata": {"name": name, "annotations": {
            "opensandbox.io/warm-home": claim, "opensandbox.io/warm-home-state": state,
            "opensandbox.io/warm-claimed-at": claimed_at}}}

    def pod(self):
        pod = _pod()
        pod.metadata.labels["opensandbox.io/warm-pool-template"] = self.revision
        return pod

    def _create(self, **kwargs):
        body = kwargs["body"]
        self.created.append(body)
        return {"metadata": {"name": body["metadata"]["name"], "uid": "bs-uid"}}

    def _get_claim(self, group, version, namespace, plural, name):
        if not self.allocate:
            return {
                "metadata": {"name": name, "annotations": {}},
                "status": {"conditions": [{"type": "PoolAllocationPending", "status": "True"}]},
            }
        return {
            "metadata": {
                "name": name,
                "annotations": {
                    "sandbox.opensandbox.io/alloc-status": json.dumps({"pods": [POD], "poolRef": POOL}),
                    "sandbox.opensandbox.io/endpoints": json.dumps([POD_IP]),
                },
            },
            "status": {"replicas": 1, "ready": 1, "allocated": 1},
        }

    async def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        self.requests.append((request.method, request.url.host, request.url.port, request.url.path, dict(request.headers), body))
        if request.url.path == "/internal/init":
            if self.execd_delay:
                # A pod that takes its time. MockTransport ignores httpx's timeouts, as a
                # server trickling bytes defeats them: only a deadline of the caller's cuts it.
                await asyncio.sleep(self.execd_delay)
            return httpx.Response(self.execd_status, json={"status": "initialized"})
        return httpx.Response(200, json={"status": "ok"})

    def client_factory(self, *args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(self.handler)
        return _ORIGINAL_CLIENT(*args, **kwargs)


def _service(config, env):
    with patch("opensandbox_server.services.k8s.kubernetes_service.K8sClient") as client_cls, patch(
        "opensandbox_server.services.k8s.kubernetes_service.create_workload_provider"
    ) as factory:
        client_cls.return_value = env.client
        factory.return_value = MagicMock()
        from opensandbox_server.services.k8s.kubernetes_service import KubernetesSandboxService

        service = KubernetesSandboxService(config)
    service.k8s_client = env.client
    real = BatchSandboxProvider(env.client, config)
    wrapper = MagicMock(wraps=real)
    wrapper.get_workload.return_value = {"metadata": {"name": "x", "annotations": {}}, "status": {}}
    wrapper.get_status.return_value = {
        "state": "Running",
        "reason": "",
        "message": "",
        "last_transition_at": datetime.now(timezone.utc),
    }
    wrapper.subscribe_workload.side_effect = Exception("no informer in this test")
    service.workload_provider = wrapper
    service._resolve_namespace = lambda: NS
    service._required_owner = lambda: SUBJECT
    # The current rendering's revision, as the warm pods carry it (absent upstream).
    revision = getattr(service, "_warm_revision", None)
    env.revision = revision() if callable(revision) else ""
    return service


async def _create(service, env, request):
    with patch("httpx.AsyncClient", side_effect=env.client_factory):
        return await service.create_sandbox(request)


def _bodies(env):
    out = [json.dumps(b, default=str) for b in env.created]
    for call in env.client.patch_custom_object.call_args_list:
        out.append(json.dumps(call.args, default=str))
    for call in env.core.patch_namespaced_persistent_volume_claim.call_args_list:
        out.append(json.dumps(call.kwargs, default=str))
    for call in env.client.create_secret.call_args_list:
        out.append(str(call))
    return "\n".join(out)


@pytest.mark.asyncio
async def test_wm29_a_new_home_is_served_by_claiming_a_warm_pod():
    env = _Env()
    service = _service(_config(), env)

    response = await _create(service, env, _request())

    # One BatchSandbox, taking a pod of the pool, running nothing in it.
    assert len(env.created) == 1, [b.get("spec") for b in env.created]
    claim = env.created[0]
    assert claim["spec"].get("poolRef") == POOL
    assert "taskTemplate" not in claim["spec"] and "template" not in claim["spec"]

    calls = [(m, port, path) for m, _h, port, path, _hd, _b in env.requests]
    # The sidecar first (the policy, then the person's vault), execd last.
    assert calls[:2] == [("POST", 18080, "/policy"), ("POST", 18080, "/credential-vault")]
    assert ("POST", 44772, "/internal/init") in calls
    assert calls.index(("POST", 44772, "/internal/init")) > 1
    token = hmac.new(KEY.encode(), POD_UID.encode(), hashlib.sha256).hexdigest()
    for method, host, port, path, headers, body in env.requests:
        assert host == POD_IP
        if port == 18080:
            assert headers.get("opensandbox-egress-auth") == token
    policy = next(b for m, h, p, path, hd, b in env.requests if path == "/policy")
    assert policy == {"defaultAction": "deny", "egress": [{"action": "allow", "target": "gateway.example"}]}
    vault = next(b for m, h, p, path, hd, b in env.requests if path == "/credential-vault")
    assert vault["credentials"][0]["source"]["value"] == SECRET

    init = next(b for m, h, p, path, hd, b in env.requests if path == "/internal/init")
    execd_token = claim["metadata"]["annotations"]["opensandbox.io/execd-access-token"]
    assert init["accessTokenHash"] == "sha256:" + hashlib.sha256(execd_token.encode()).hexdigest()
    assert init["envs"]["WM_CHAT_ID"] == "chat-1"
    assert "EXECD_BOOTSTRAP_PRE_SCRIPT" not in init["envs"] and "EXECD_ACCESS_TOKEN" not in init["envs"]
    assert init["lifecycle"]["preStart"]["command"] == ["/opt/wm/fuse-claim.sh"]
    check = next(hd for m, h, p, path, hd, b in env.requests if path == "/v1/isolated/capabilities")
    assert check.get("x-execd-access-token") == execd_token
    # Never /metrics: execd samples the CPU for a second before answering it, a second
    # every warm open would wait for.
    assert not any(path.startswith("/metrics") for m, h, p, path, hd, b in env.requests)

    # The pod's home becomes this person's, guarded on still being that pod's: the pod stays
    # its controller (the kubelet requires it of an ephemeral volume) and an anchor owned by
    # the home becomes a second owner, so the home outlives the pod.
    anchor = env.anchors["osb-warm-home-" + hashlib.sha256(HOME.encode()).hexdigest()[:40]]
    assert anchor["metadata"]["ownerReferences"][0]["uid"] == "home-uid"
    assert anchor["metadata"]["annotations"]["opensandbox.io/warm-home"] == f"{POD}-home"
    # Committed only once execd is bound: until then the name hands out no home.
    committed = env.core.patch_namespaced_config_map.call_args.kwargs["body"]
    assert committed[0]["op"] == "test" and committed[0]["value"] == response.id
    assert committed[1] == {"op": "replace", "path": "/metadata/annotations/opensandbox.io~1warm-home-state", "value": "committed"}
    pvc_call = env.core.patch_namespaced_persistent_volume_claim.call_args
    assert pvc_call.kwargs["name"] == f"{POD}-home"
    ops = pvc_call.kwargs["body"]
    assert ops[0] == {"op": "test", "path": "/metadata/ownerReferences/0/uid", "value": POD_UID}
    assert not any(op["op"] == "remove" for op in ops), "the pod must stay the home's controller"
    added = [op for op in ops if op["path"] == "/metadata/ownerReferences/-"]
    assert added and added[0]["value"]["uid"] == "anchor-uid" and added[0]["value"]["controller"] is False
    alias = hashlib.sha256(HOME.encode()).hexdigest()[:40]
    assert {"op": "add", "path": "/metadata/labels/opensandbox.io~1home-alias", "value": alias} in ops
    assert {"op": "add", "path": "/metadata/annotations/opensandbox.io~1owner-subject", "value": SUBJECT} in ops

    # The derived egress token is what the endpoints API will hand the owner.
    patched = env.client.patch_custom_object.call_args.args
    assert patched[-1] == {"metadata": {"annotations": {"opensandbox.io/egress-auth-token": token}}}

    # Nothing secret is written to any object.
    assert SECRET not in _bodies(env)
    assert response.extensions.get("opensandbox.extensions.warm-claimed") == "true"
    assert response.status.state == "Running"


@pytest.mark.asyncio
async def test_wm29_an_empty_pool_goes_cold_and_leaves_no_claim():
    env = _Env(allocate=False)
    service = _service(_config(claim_timeout_seconds=0.3), env)

    await _create(service, env, _request())

    pool_claims = [b for b in env.created if b["spec"].get("poolRef")]
    cold = [b for b in env.created if not b["spec"].get("poolRef")]
    assert len(pool_claims) == 1, "the pool was not asked"
    assert env.client.delete_custom_object.called, "the unserved claim was left behind"
    assert len(cold) == 1, "the create did not go cold"
    assert pool_claims[0]["metadata"]["name"] != cold[0]["metadata"]["name"]


@pytest.mark.asyncio
async def test_wm29_a_refused_binding_deletes_the_claim_and_its_home_and_goes_cold():
    env = _Env(execd_status=409)
    service = _service(_config(), env)

    await _create(service, env, _request())

    assert env.client.delete_custom_object.called
    deleted = [c.args[1] if len(c.args) > 1 else c.kwargs.get("name") for c in env.client.delete_pvc.call_args_list]
    assert f"{POD}-home" in deleted, "the home taken from the pod was left behind"
    assert not env.anchors or all(
        a["metadata"]["annotations"].get("opensandbox.io/warm-home") != f"{POD}-home" for a in env.anchors.values()
    ), "the failed claim kept its home name reserved"
    assert [b for b in env.created if not b["spec"].get("poolRef")], "the create did not go cold"


def _pvc(name, labels=None, subject=SUBJECT, claimed_at="2026-10-17T10:00:00.000000Z"):
    return SimpleNamespace(
        metadata=SimpleNamespace(
            name=name,
            labels=labels or {},
            annotations={"opensandbox.io/owner-subject": subject, "opensandbox.io/warm-claimed-at": claimed_at},
            creation_timestamp=datetime(2026, 10, 17, tzinfo=timezone.utc),
        )
    )


@pytest.mark.asyncio
async def test_wm29_a_resumed_chat_mounts_the_home_its_warm_pod_was_given():
    alias = hashlib.sha256(HOME.encode()).hexdigest()[:40]
    claimed = _pvc(f"{POD}-home", {"opensandbox.io/warm-pool-home": POOL, "opensandbox.io/home-alias": alias})
    env = _Env()
    env.existing_pvcs[f"{POD}-home"] = claimed
    env.anchor(HOME, f"{POD}-home")
    service = _service(_config(), env)

    await _create(service, env, _request())

    assert not [b for b in env.created if b["spec"].get("poolRef")], "a resumed chat was given a fresh pod's home"
    assert env.requests == [] or all(p != "/internal/init" for _m, _h, _p, p, _hd, _b in env.requests)
    assert not env.client.create_pvc.called, "a new, empty home was made for a chat that has one"
    pod_spec = env.created[-1]["spec"]["template"]["spec"]
    claims = [v["persistentVolumeClaim"]["claimName"] for v in pod_spec["volumes"] if "persistentVolumeClaim" in v]
    assert claims == [f"{POD}-home"]


@pytest.mark.asyncio
async def test_wm29_a_pod_of_an_older_template_is_never_claimed():
    env = _Env()
    service = _service(_config(), env)
    env.revision = "an-older-rendering"

    await _create(service, env, _request())

    assert env.client.delete_custom_object.called, "the stale pod's claim was kept"
    assert not [r for r in env.requests if r[3] == "/internal/init"], "a stale pod was bound"
    assert [b for b in env.created if not b["spec"].get("poolRef")], "the create did not go cold"


@pytest.mark.asyncio
async def test_wm29_of_two_racing_claims_for_one_home_the_later_gives_way():
    """Both passed the "no home yet" check; the other reserved the name first."""
    earlier = _pvc("osb-warm-aaaaa-home", {"opensandbox.io/home-alias": hashlib.sha256(HOME.encode()).hexdigest()[:40]})
    env = _Env()
    env.existing_pvcs["osb-warm-aaaaa-home"] = earlier
    service = _service(_config(), env)
    real_read = env._read_anchor
    seen = {"n": 0}

    def read_after_the_check(name, namespace):
        # Nothing at the claim's own check; the rival's anchor lands right after it.
        seen["n"] += 1
        if seen["n"] == 1:
            error = Exception("NotFound")
            error.status = 404
            raise error
        return real_read(name, namespace)

    env.core.read_namespaced_config_map.side_effect = read_after_the_check
    env.anchor(HOME, "osb-warm-aaaaa-home")
    await _create(service, env, _request())

    assert not [r for r in env.requests if r[3] == "/internal/init"], "the later claim was bound anyway"
    assert not env.core.patch_namespaced_persistent_volume_claim.called, "the later claim relabelled its home"
    pod_spec = env.created[-1]["spec"]["template"]["spec"]
    claims = [v["persistentVolumeClaim"]["claimName"] for v in pod_spec["volumes"] if "persistentVolumeClaim" in v]
    assert claims == ["osb-warm-aaaaa-home"], "the cold create did not mount the reserved home"


@pytest.mark.asyncio
async def test_wm29_a_home_still_being_claimed_is_not_handed_out():
    env = _Env()
    env.anchor(HOME, f"{POD}-home", state="claiming")
    env.existing_pvcs[f"{POD}-home"] = _pvc(f"{POD}-home", {"opensandbox.io/warm-pool-home": POOL})
    service = _service(_config(), env)

    with pytest.raises(HTTPException) as refused:
        await _create(service, env, _request())
    assert refused.value.status_code == 503
    assert not [b for b in env.created if not b["spec"].get("poolRef")], "a cold sandbox got a home mid-claim"


@pytest.mark.asyncio
async def test_warm_pool_a_claim_that_died_mid_way_does_not_hold_the_name_for_ever():
    # Not a WM test: on upstream every create is cold, so this holds there too.
    env = _Env()
    env.anchor(HOME, f"{POD}-home", state="claiming", claimed_at="2000-01-01T00:00:00.000000Z")
    service = _service(_config(), env)

    await _create(service, env, _request())

    assert [b for b in env.created if not b["spec"].get("poolRef")], "the create did not go cold"
    assert env.client.create_pvc.called, "a stale reservation still blocked a new home"


@pytest.mark.asyncio
async def test_warm_pool_a_boot_time_setting_the_pool_lacks_goes_cold():
    # Not a WM test: on upstream every create is cold, so this holds there too.
    env = _Env()
    service = _service(_config(), env)
    request = _request()
    request.env["EXECD_ISOLATION_CONFIG"] = "/etc/execd/hardened.toml"

    await _create(service, env, request)

    assert not [b for b in env.created if b["spec"].get("poolRef")], "a pod booted without it was claimed"


@pytest.mark.asyncio
async def test_wm29_a_claim_is_cut_at_its_budget_even_when_the_pod_answers_slowly():
    env = _Env(execd_delay=1.5)
    service = _service(_config(claim_timeout_seconds=0.3), env)

    began = time.monotonic()
    await _create(service, env, _request())
    took = time.monotonic() - began

    assert [b for b in env.created if not b["spec"].get("poolRef")], "a claim past its budget did not go cold"
    assert env.client.delete_custom_object.called, "the claim past its budget was left behind"
    assert took < 1.2, f"the create waited {took:.2f}s for a pod answering in 1.5s, budget 0.3s"


@pytest.mark.asyncio
async def test_wm29_a_create_naming_another_execd_binary_goes_cold():
    env = _Env()
    service = _service(_config(), env)
    request = _request()
    request.env["EXECD"] = "/opt/other/execd"

    await _create(service, env, request)

    assert not [b for b in env.created if b["spec"].get("poolRef")], "a pod running the pool's execd was claimed"


@pytest.mark.asyncio
async def test_wm29_a_warm_home_is_never_mounted_by_its_own_name():
    unclaimed = _pvc(f"{POD}-home", {"opensandbox.io/warm-pool-home": POOL}, subject=SUBJECT)
    env = _Env(existing_pvcs={f"{POD}-home": unclaimed})
    service = _service(_config(), env)
    request = _request(home=f"{POD}-home", extensions={})

    with pytest.raises(HTTPException) as refused:
        await _create(service, env, request)

    assert refused.value.status_code == 404
    assert env.created == []


def test_wm29_the_pool_is_rendered_by_the_cold_builder_and_holds_nothing_of_anyone():
    env = _Env()
    # No key yet: the server makes the Secret the sidecars read, before the Pool.
    missing = Exception("not found")
    missing.status = 404
    env.core.read_namespaced_secret.side_effect = missing
    service = _service(_config(), env)
    created = threading.Event()
    env.custom.get_namespaced_custom_object.side_effect = _not_found
    env.custom.create_namespaced_custom_object.side_effect = lambda *a, **k: created.set()

    start = getattr(service, "start_warm_pool", None)
    assert callable(start), "the server keeps no warm pool"
    start()
    assert created.wait(5), "no Pool was written"

    secret = env.core.create_namespaced_secret.call_args.kwargs["body"]
    assert secret["metadata"]["name"] == "opensandbox-warm-pool-egress-key"
    assert len(base64.b64decode(secret["data"]["key"])) == 64
    pool = env.custom.create_namespaced_custom_object.call_args.args[-1]
    assert pool["kind"] == "Pool" and pool["metadata"]["name"] == POOL
    assert pool["spec"]["recycleStrategy"] == {"type": "Delete"}
    assert pool["spec"]["capacitySpec"]["bufferMin"] == 3 == pool["spec"]["capacitySpec"]["bufferMax"]
    spec = pool["spec"]["template"]["spec"]
    main = next(c for c in spec["containers"] if c["name"] != "egress")
    egress = next(c for c in spec["containers"] if c["name"] == "egress")
    main_env = {e["name"]: e for e in main["env"]}
    egress_env = {e["name"]: e for e in egress["env"]}
    assert main_env["EXECD_RUNTIME_INIT"]["value"] == "true"
    assert main_env["EXECD_RUNTIME_INIT_ONCE"]["value"] == "true"
    assert "OPENSANDBOX_ID" not in main_env and "EXECD_ACCESS_TOKEN" not in main_env
    assert main_env["EXECD_BOOTSTRAP_PRE_SCRIPT"]["value"] == PRE_SCRIPT
    assert "OPENSANDBOX_EGRESS_TOKEN" not in egress_env
    assert egress_env["OPENSANDBOX_EGRESS_TOKEN_KEY"]["valueFrom"]["secretKeyRef"]["name"]
    assert egress_env["OPENSANDBOX_EGRESS_TOKEN_SUBJECT"]["valueFrom"]["fieldRef"]["fieldPath"] == "metadata.uid"
    assert json.loads(egress_env["OPENSANDBOX_EGRESS_RULES"]["value"]) == {"defaultAction": "deny", "egress": []}
    assert "OPENSANDBOX_EGRESS_CREDENTIAL_VAULT_SEED" not in egress_env
    home = next(v for v in spec["volumes"] if v["name"] == "home")
    template = home["ephemeral"]["volumeClaimTemplate"]
    assert template["metadata"]["labels"] == {"opensandbox.io/warm-pool-home": POOL}
    assert template["spec"]["storageClassName"] == "sandbox-thin"
    # The same builder as a cold create: the execd installer and the probes it adds.
    assert spec["initContainers"] and main.get("startupProbe")
    service._warm_pool.stop()


def _not_found(*_args, **_kwargs):
    error = Exception("not found")
    error.status = 404
    raise error
