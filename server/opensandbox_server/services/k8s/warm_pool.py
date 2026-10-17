"""A warm pool whose pods are claimed per person (WM-29).

A pooled pod is started before anyone owns it, so it must be born holding nothing of
anyone and become one person's only when it is claimed:

* execd runs in runtime-init mode with EXECD_RUNTIME_INIT_ONCE: until the claim it answers
  /ping, /ready and one /internal/init, and nothing else; after the claim nobody can bind
  it again.
* the egress sidecar starts with a deny-all policy and an empty vault. Its token is derived
  from a key the sidecar reads from a Secret and from the pod's own uid, so every pod has a
  different token although the template is one; the server, which holds the key, derives it
  again at the claim.
* the person's home is the pod's own claim, created empty with the pod. At the claim the
  server takes it away from the pod (no ownerReference: it outlives the sandbox, as every
  home does), stamps the owner and records, as a label, which home name it now answers to.
  A later create naming that home is resolved through the label to this claim.

Everything per person is pushed into the running pod at the claim, in this order: the
egress policy and the vault seed to the sidecar; then execd's binding -- the token's hash,
the create's environment, a preStart hook -- in one /internal/init. Nothing secret is ever
in the pod spec: the seed travels over the sidecar's API, the execd token only as a hash.

Anything that does not match the pool, or a claim that cannot complete within its budget,
is created cold, exactly as before. A pod whose claim failed half-way is deleted, never
returned to the pool.
"""

from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import hmac
import json
import logging
import secrets
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from opensandbox_server.api.schema import (
    CreateSandboxRequest,
    ImageSpec,
    NetworkPolicy,
    Volume,
)
from opensandbox_server.config import AppConfig, WarmPoolConfig
from opensandbox_server.services.constants import (
    EXECD_ACCESS_TOKEN_HEADER,
    EXECD_PORT,
    OPEN_SANDBOX_EGRESS_AUTH_HEADER,
)
from opensandbox_server.services.k8s.client import (
    OPENSANDBOX_API_GROUP,
    OPENSANDBOX_API_VERSION,
    POOL_PLURAL,
)
from opensandbox_server.services.k8s.workload_provider import EgressWorkloadSettings

logger = logging.getLogger(__name__)

# The create opts in by naming the pool. Any other value, or none, is a cold create.
WARM_POOL_EXTENSION = "opensandbox.extensions.warm-pool"
# Set by the server on a sandbox it served from the pool; a caller's own value is dropped.
WARM_CLAIMED_EXTENSION = "opensandbox.extensions.warm-claimed"
WARM_CLAIMED_ANNOTATION = "opensandbox.io/extensions.warm-claimed"
# On every warm pod (and so on its claim).
WARM_POOL_POD_LABEL = "opensandbox.io/warm-pool"
# On every warm pod's home claim, from the volumeClaimTemplate. Such a claim is never
# mounted by naming it: only through the alias it was given when it was claimed.
WARM_POOL_HOME_LABEL = "opensandbox.io/warm-pool-home"
# On a claimed home: which home name it answers to, as a digest (a label value is at most
# 63 characters, and the name itself is a capability its owner's client derives).
HOME_ALIAS_LABEL = "opensandbox.io/home-alias"
WARM_CLAIMED_BY_ANNOTATION = "opensandbox.io/warm-claimed-by"
# When (RFC 3339, microseconds, UTC): two claims for one home name resolve to the earlier.
WARM_CLAIMED_AT_ANNOTATION = "opensandbox.io/warm-claimed-at"
# On each warm pod: the rendering it was made from. A pod of an older rendering is never
# claimed -- after a configuration change the controller replaces idle pods gradually.
WARM_TEMPLATE_LABEL = "opensandbox.io/warm-pool-template"
TEMPLATE_HASH_ANNOTATION = "opensandbox.io/warm-pool-template-sha256"

EGRESS_PORT = 18080
EGRESS_TOKEN_KEY_ENV = "OPENSANDBOX_EGRESS_TOKEN_KEY"
EGRESS_TOKEN_SUBJECT_ENV = "OPENSANDBOX_EGRESS_TOKEN_SUBJECT"
EGRESS_SANDBOX_ID_ENV = "OPENSANDBOX_EGRESS_SANDBOX_ID"
EGRESS_TOKEN_ENV = "OPENSANDBOX_EGRESS_TOKEN"
EXECD_RUNTIME_INIT_ENV = "EXECD_RUNTIME_INIT"
EXECD_RUNTIME_INIT_ONCE_ENV = "EXECD_RUNTIME_INIT_ONCE"
# Names execd refuses in /internal/init envs (components/execd/pkg/isolation/config.go),
# plus the boot-only ones that mean nothing once the pod is running.
_INIT_ENV_DROPPED = frozenset(
    {
        "EXECD_ACCESS_TOKEN",
        "JUPYTER_HOST",
        "JUPYTER_TOKEN",
        "EXECD_ISOLATION_CONFIG",
        "EXECD_ENVS",
        "OPENSANDBOX_LIFECYCLE",
        "EXECD_LIFECYCLE_CONFIG",
        "EXECD_RUNTIME_INIT",
        "EXECD_RUNTIME_INIT_ONCE",
        "EXECD_BOOTSTRAP_PRE_SCRIPT",
        "OPENSANDBOX_ID",
    }
)
_PLACEHOLDER_ID = "warm-pool-template"
_PLACEHOLDER_CLAIM = "warm-pool-template-home"


_BOOT_ONLY_EXTRA = frozenset({"OPENSANDBOX_CA_TRUST_BACKGROUND", "OPENSANDBOX_MITM_CA_FILE",
                              "OPENSANDBOX_MERGED_CA_FILE", "OPENSANDBOX_CA_TRUST_DONE_FILE",
                              "OPENSANDBOX_CA_TRUST_LOG"})


def _boot_only(name: str) -> bool:
    upper = name.upper()
    return (
        # EXECD itself: bootstrap.sh launches the binary it names.
        upper == "EXECD"
        or (upper in _INIT_ENV_DROPPED and upper != "OPENSANDBOX_ID")
        or upper in _BOOT_ONLY_EXTRA
        or upper.startswith(("EXECD_", "BOOTSTRAP_", "JUPYTER_"))
    )


def home_alias(claim_name: str) -> str:
    return hashlib.sha256(claim_name.encode("utf-8")).hexdigest()[:40]


def derive_egress_token(key: str, pod_uid: str) -> str:
    """The token a warm pod's sidecar runs with (egress WM-27): HMAC-SHA256(key, uid)."""
    return hmac.new(key.encode("utf-8"), pod_uid.encode("utf-8"), hashlib.sha256).hexdigest()


def execd_token_hash(token: str) -> str:
    return "sha256:" + hashlib.sha256(token.encode("utf-8")).hexdigest()


def wants_pool(request: CreateSandboxRequest, cfg: WarmPoolConfig) -> bool:
    return bool(cfg.enabled and (request.extensions or {}).get(WARM_POOL_EXTENSION) == cfg.name)


def _resources(model: Any) -> Dict[str, str]:
    root = getattr(model, "root", None) if model is not None else None
    return dict(root or {})


def incompatibility(request: CreateSandboxRequest, cfg: WarmPoolConfig) -> Optional[str]:
    """Why this create cannot be served by the pool, or None when it can.

    Every field that shapes the pod at boot must equal the pool's, because a warm pod was
    booted before the request existed. What is applied at the claim -- the env, the egress
    policy, the vault seed, metadata, the timeout -- may differ freely.
    """
    if request.image is None or request.image.uri != cfg.image:
        return "image differs from the pool's"
    if request.image.auth is not None:
        return "image credentials"
    if list(request.entrypoint or []) != list(cfg.entrypoint):
        return "entrypoint differs from the pool's"
    if _resources(request.resource_limits) != dict(cfg.resource_limits):
        return "resourceLimits differ from the pool's"
    if _resources(request.resource_requests) != dict(cfg.resource_requests):
        return "resourceRequests differ from the pool's"
    if request.network_policy is None:
        return "no networkPolicy (a warm pod always has the egress sidecar)"
    if not (request.credential_proxy and request.credential_proxy.enabled):
        return "credentialProxy is off (a warm pod's sidecar runs the credential proxy)"
    if request.secure_access or request.platform is not None or request.snapshot_id or request.template_id:
        return "secureAccess, platform, snapshot or template"
    if request.lifecycle is not None:
        return "a request lifecycle"
    env = request.env or {}
    if any(k.startswith("OPENSANDBOX_EGRESS_") for k in env):
        return "sidecar environment in the request"
    # What execd and bootstrap.sh read at START must be what the warm pod started with: such
    # a variable cannot be applied at the claim, and dropping it would answer a create that
    # asked for (say) a hardened isolation config with a pod running without one. Compared in
    # both directions: a pool-only boot setting is a difference too.
    for name in set(env) | set(cfg.env):
        if _boot_only(name) and env.get(name) != cfg.env.get(name):
            return f"{name} is read at boot and differs from the pool's"
    if request.timeout is None:
        # A claim must expire: one whose cleanup ever failed would otherwise hold a pod for good.
        return "no timeout"
    for key in request.extensions or {}:
        # Annotations only, or the renew window: neither shapes the pod. Anything else
        # (poolRef, execd isolation, ...) decides how the pod is built, and a warm pod
        # was built without it.
        if key.startswith("opensandbox.extensions.") or key == "access.renew.extend.seconds":
            continue
        return f"extension {key!r}"
    volumes = request.volumes or []
    if len(volumes) != 1:
        return "a warm pod has exactly one volume, its home"
    home = volumes[0]
    pvc = home.pvc
    if (
        pvc is None
        or home.host is not None
        or home.ossfs is not None
        or home.mount_path != cfg.home_mount_path
        or home.read_only
        or home.sub_path
        or not pvc.create_if_not_exists
        or pvc.delete_on_sandbox_termination
    ):
        return "the volume is not a new home at the pool's mount path"
    # Exact, not "unset matches": the cold path gives an unset size and class meanings of its
    # own (storage.volume_default_size, the cluster's default class), which the pool's may not be.
    if pvc.storage != cfg.home_storage:
        return "the home's size differs from the pool's"
    if pvc.storage_class != cfg.home_storage_class:
        return "the home's storage class differs from the pool's"
    if pvc.access_modes not in (None, ["ReadWriteOnce"]):
        return "the home's access modes differ from the pool's"
    return None


# ------------------------------------------------------------------ the pool template


def render_pool(provider: Any, app_config: AppConfig, execd_image: str) -> Dict[str, Any]:
    """The Pool, its pod template built by the cold create's own builder."""
    cfg = app_config.warm_pool
    egress = app_config.egress
    assert egress is not None
    settings = EgressWorkloadSettings(
        network_policy=NetworkPolicy.model_validate({"defaultAction": "deny", "egress": []}),
        image=egress.image,
        mode=egress.mode,
        auth_token=None,
        credential_proxy_enabled=True,
        credential_vault_seed=None,
        env={},
        disable_ipv6=egress.disable_ipv6,
        resource_requests=egress.requests,
        resource_limits=egress.limits,
        otlp_endpoint=egress.otlp_endpoint,
        upstream_proxy=egress.upstream_proxy,
        enforcement=egress.enforcement,
    )
    home = Volume.model_validate(
        {
            "name": cfg.home_volume_name,
            "pvc": {"claimName": _PLACEHOLDER_CLAIM},
            "mountPath": cfg.home_mount_path,
            "readOnly": False,
        }
    )
    batchsandbox = provider.create_workload(
        sandbox_id=_PLACEHOLDER_ID,
        namespace=cfg.namespace or app_config.kubernetes.namespace,
        image_spec=ImageSpec(uri=cfg.image),
        entrypoint=list(cfg.entrypoint),
        env=dict(cfg.env),
        resource_limits=dict(cfg.resource_limits),
        resource_requests=dict(cfg.resource_requests) or None,
        labels={WARM_POOL_POD_LABEL: cfg.name},
        expires_at=None,
        execd_image=execd_image,
        extensions={},
        egress_settings=settings,
        volumes=[home],
        platform=None,
        annotations=None,
        render_only=True,
    )
    template = copy.deepcopy(batchsandbox["spec"]["template"])
    _make_warm(template, cfg)
    manifest = {
        "apiVersion": f"{OPENSANDBOX_API_GROUP}/{OPENSANDBOX_API_VERSION}",
        "kind": "Pool",
        "metadata": {"name": cfg.name, "namespace": cfg.namespace or app_config.kubernetes.namespace},
        "spec": {
            "template": template,
            "capacitySpec": {
                "bufferMin": cfg.size,
                "bufferMax": cfg.size,
                "poolMin": 0,
                "poolMax": cfg.pool_max,
            },
            # Single use: a released pod is destroyed, never handed to a second person.
            "recycleStrategy": {"type": "Delete"},
        },
    }
    digest = _spec_digest(manifest["spec"])
    manifest["metadata"]["annotations"] = {TEMPLATE_HASH_ANNOTATION: digest}
    manifest["spec"]["template"]["metadata"]["labels"][WARM_TEMPLATE_LABEL] = digest[:40]
    return manifest


def template_revision(app_config: AppConfig, provider: Any, execd_image: str) -> str:
    """The label value a pod of the current rendering carries."""
    manifest = render_pool(provider, app_config, execd_image)
    return manifest["spec"]["template"]["metadata"]["labels"][WARM_TEMPLATE_LABEL]


def _spec_digest(spec: Dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(spec, sort_keys=True).encode()).hexdigest()


def _env_without(env: List[Dict[str, Any]], *names: str) -> List[Dict[str, Any]]:
    return [e for e in env if e.get("name") not in names]


def _make_warm(template: Dict[str, Any], cfg: WarmPoolConfig) -> None:
    # The installation's own pod labels and annotations (the base template) stay: network
    # policies and admission may select on them. Only per-sandbox keys go -- the builder was
    # given none but the pool's own label, and the sandbox id is set by the claim.
    metadata = template.setdefault("metadata", {})
    labels = dict(metadata.get("labels") or {})
    labels.pop("opensandbox.io/id", None)
    labels[WARM_POOL_POD_LABEL] = cfg.name
    metadata["labels"] = labels
    if not metadata.get("annotations"):
        metadata.pop("annotations", None)
    spec = template["spec"]
    found_main = found_egress = found_home = False
    for container in spec.get("containers", []):
        env = container.get("env") or []
        if container.get("name") == "egress":
            found_egress = True
            env = _env_without(env, EGRESS_TOKEN_ENV, EGRESS_SANDBOX_ID_ENV, EGRESS_TOKEN_KEY_ENV, EGRESS_TOKEN_SUBJECT_ENV)
            env.append(
                {
                    "name": EGRESS_TOKEN_KEY_ENV,
                    "valueFrom": {"secretKeyRef": {"name": cfg.egress_key_secret_name, "key": "key"}},
                }
            )
            env.append({"name": EGRESS_TOKEN_SUBJECT_ENV, "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}}})
        else:
            found_main = True
            env = _env_without(env, "OPENSANDBOX_ID", "EXECD_ACCESS_TOKEN", EXECD_RUNTIME_INIT_ENV, EXECD_RUNTIME_INIT_ONCE_ENV)
            env.append({"name": EXECD_RUNTIME_INIT_ENV, "value": "true"})
            env.append({"name": EXECD_RUNTIME_INIT_ONCE_ENV, "value": "true"})
        container["env"] = env
    claim_spec: Dict[str, Any] = {
        "accessModes": ["ReadWriteOnce"],
        "resources": {"requests": {"storage": cfg.home_storage}},
    }
    if cfg.home_storage_class is not None:
        claim_spec["storageClassName"] = cfg.home_storage_class
    for volume in spec.get("volumes", []):
        if volume.get("name") == cfg.home_volume_name:
            found_home = True
            volume.pop("persistentVolumeClaim", None)
            volume["ephemeral"] = {
                "volumeClaimTemplate": {
                    "metadata": {
                        "labels": {WARM_POOL_HOME_LABEL: cfg.name},
                        "annotations": {WARM_POOL_POD_LABEL: cfg.name},
                    },
                    "spec": claim_spec,
                }
            }
    if not (found_main and found_egress and found_home):
        raise ValueError(
            "warm pool template is missing a part the claim relies on "
            f"(sandbox container {found_main}, egress sidecar {found_egress}, home {found_home})"
        )


class WarmPoolReconciler:
    """Keeps the Pool equal to what this server would render. Idempotent, so every replica
    may run it; a replace carries the resourceVersion read, so two replicas cannot
    interleave half-written specs."""

    def __init__(self, provider: Any, k8s_client: Any, app_config: AppConfig, execd_image: str) -> None:
        self._provider = provider
        self._k8s = k8s_client
        self._config = app_config
        self._execd_image = execd_image
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def reconcile_once(self) -> str:
        cfg = self._config.warm_pool
        manifest = render_pool(self._provider(), self._config, self._execd_image)
        namespace = manifest["metadata"]["namespace"]
        # Before the Pool: a warm pod whose Secret does not exist does not start.
        egress_key(self._k8s, namespace, cfg)
        api = self._k8s.get_custom_objects_api()
        try:
            live = api.get_namespaced_custom_object(
                OPENSANDBOX_API_GROUP, OPENSANDBOX_API_VERSION, namespace, POOL_PLURAL, cfg.name
            )
        except Exception as exc:  # noqa: BLE001
            if getattr(exc, "status", None) != 404:
                raise
            api.create_namespaced_custom_object(
                OPENSANDBOX_API_GROUP, OPENSANDBOX_API_VERSION, namespace, POOL_PLURAL, manifest
            )
            logger.info("warm pool %s/%s created", namespace, cfg.name)
            return "created"
        live_hash = ((live.get("metadata") or {}).get("annotations") or {}).get(TEMPLATE_HASH_ANNOTATION)
        want = manifest["metadata"]["annotations"][TEMPLATE_HASH_ANNOTATION]
        # Both: the annotation says what was last written, and the spec itself, hashed the same
        # way, says whether anyone edited it since -- an edit that kept the annotation (and the
        # template's revision label) would otherwise pass every later look and every claim.
        if live_hash == want and _spec_digest(live.get("spec") or {}) == _spec_digest(manifest["spec"]):
            return "unchanged"
        manifest["metadata"]["resourceVersion"] = live["metadata"]["resourceVersion"]
        api.replace_namespaced_custom_object(
            OPENSANDBOX_API_GROUP, OPENSANDBOX_API_VERSION, namespace, POOL_PLURAL, cfg.name, manifest
        )
        logger.info("warm pool %s/%s replaced (template changed)", namespace, cfg.name)
        return "replaced"

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.reconcile_once()
            except Exception as exc:  # noqa: BLE001 - a pool it cannot write only means cold creates
                logger.warning("warm pool reconcile failed: %s", exc)
            self._stop.wait(self._config.warm_pool.reconcile_interval_seconds)

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._run, name="warm-pool", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)


# ------------------------------------------------------------------------ the claim


FREE_PODS_READ_TIMEOUT_SECONDS = 1.0


def free_pods(k8s_client: Any, namespace: str, cfg: WarmPoolConfig) -> Optional[int]:
    """The Pool's own count of ready, unallocated pods (status.available), or None when it
    cannot be read or carries no such count -- None means "ask the pool anyway" (WM-33)."""
    try:
        # Bounded: this read sits before the claim's own budget starts, and a stalled API
        # server must not hold a create that could go cold.
        obj = k8s_client.get_custom_objects_api().get_namespaced_custom_object(
            OPENSANDBOX_API_GROUP, OPENSANDBOX_API_VERSION, namespace, POOL_PLURAL, cfg.name,
            _request_timeout=FREE_PODS_READ_TIMEOUT_SECONDS,
        )
    except Exception as exc:  # noqa: BLE001 - an unreadable Pool only means asking it as before
        logger.debug("warm pool %s: could not read the Pool's status: %s", cfg.name, exc)
        return None
    value = ((obj or {}).get("status") or {}).get("available") if isinstance(obj, dict) else None
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


class ClaimFailed(Exception):
    """A claim that could not complete; the create goes cold."""


_KEY_CACHE: Dict[tuple, tuple] = {}
_KEY_TTL_SECONDS = 60.0


def egress_key(k8s_client: Any, namespace: str, cfg: WarmPoolConfig) -> str:
    """The key every warm sidecar derives its token from: the Secret the sidecars read,
    created by this server when it does not exist yet (32 random bytes, hex), and read back
    otherwise -- so every replica, and every pod, agrees on one value without anybody
    transcribing it. Cached for a minute: a rotated key (delete the Secret) reaches new
    claims within that, and a pod started on the old key fails its claim and is replaced.
    """
    cached = _KEY_CACHE.get((namespace, cfg.egress_key_secret_name))
    if cached is not None and time.monotonic() - cached[1] < _KEY_TTL_SECONDS:
        return cached[0]
    core = k8s_client.get_core_v1_api()
    key = _read_key(core, namespace, cfg.egress_key_secret_name)
    if key is None:
        value = secrets.token_hex(32)
        body = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": cfg.egress_key_secret_name,
                "namespace": namespace,
                "labels": {WARM_POOL_POD_LABEL: cfg.name},
            },
            "type": "Opaque",
            "data": {"key": base64.b64encode(value.encode()).decode()},
        }
        try:
            core.create_namespaced_secret(namespace=namespace, body=body)
            key = value
        except Exception as exc:  # noqa: BLE001
            if getattr(exc, "status", None) != 409:
                raise ClaimFailed(f"cannot create the warm pool key: {exc}") from exc
            key = _read_key(core, namespace, cfg.egress_key_secret_name)
    if not key:
        raise ClaimFailed("the warm pool key Secret has no `key`")
    _KEY_CACHE[(namespace, cfg.egress_key_secret_name)] = (key, time.monotonic())
    return key


def forget_egress_key(namespace: str, cfg: WarmPoolConfig) -> None:
    _KEY_CACHE.pop((namespace, cfg.egress_key_secret_name), None)


def _read_key(core: Any, namespace: str, name: str) -> Optional[str]:
    try:
        secret = core.read_namespaced_secret(name=name, namespace=namespace)
    except Exception as exc:  # noqa: BLE001
        if getattr(exc, "status", None) == 404:
            return None
        raise ClaimFailed(f"cannot read the warm pool key: {exc}") from exc
    data = getattr(secret, "data", None) or {}
    raw = data.get("key")
    return base64.b64decode(raw).decode() if raw else ""


def init_envs(sandbox_env: Dict[str, Optional[str]]) -> Dict[str, str]:
    return {k: (v or "") for k, v in sandbox_env.items() if k.upper() not in _INIT_ENV_DROPPED}


async def wait_for_allocation(
    k8s_client: Any,
    namespace: str,
    name: str,
    deadline: float,
    group: str,
    version: str,
    plural: str,
) -> tuple[str, str]:
    """The pod the controller handed this claim, and its address. Read from the API, not
    an informer: the cache may trail the controller by more than the whole claim takes."""
    api = k8s_client.get_custom_objects_api()
    while True:
        obj = await asyncio.to_thread(api.get_namespaced_custom_object, group, version, namespace, plural, name)
        annotations = (obj.get("metadata") or {}).get("annotations") or {}
        status = obj.get("status") or {}
        for condition in status.get("conditions") or []:
            if condition.get("type") == "PoolAllocationPending" and condition.get("status") == "True":
                raise ClaimFailed("the pool has no ready pod")
        alloc = annotations.get("sandbox.opensandbox.io/alloc-status")
        endpoints = annotations.get("sandbox.opensandbox.io/endpoints")
        if alloc and endpoints:
            pods = (json.loads(alloc) or {}).get("pods") or []
            ips = json.loads(endpoints) or []
            if len(pods) == 1 and ips:
                return pods[0], ips[0]
        if time.monotonic() >= deadline:
            raise ClaimFailed("no pod was allocated in time")
        await asyncio.sleep(0.02)


def home_claim_name(pod: Any, cfg: WarmPoolConfig) -> str:
    for volume in pod.spec.volumes or []:
        if volume.name == cfg.home_volume_name and volume.ephemeral is not None:
            return f"{pod.metadata.name}-{cfg.home_volume_name}"
    raise ClaimFailed("the allocated pod has no warm home volume")


def _escape(key: str) -> str:
    return key.replace("~", "~0").replace("/", "~1")


def anchor_name(claim_name: str) -> str:
    """The one object a home name can have: a ConfigMap named from the name's digest. Creating
    it is the reservation -- the API server lets exactly one create succeed -- and it records
    which claim the name resolves to."""
    return f"osb-warm-home-{home_alias(claim_name)}"


ANCHOR_STATE_ANNOTATION = "opensandbox.io/warm-home-state"
ANCHOR_HOME_ANNOTATION = "opensandbox.io/warm-home"


def take_home(
    k8s_client: Any,
    namespace: str,
    claim: str,
    pod_uid: str,
    alias_of: str,
    subject: Optional[str],
    sandbox_id: str,
    owner_annotation: str,
    claimed_at: str,
) -> None:
    """Reserve the home name for this pod's home, and make that home this person's.

    ⚠ THE RESERVATION IS AN OBJECT, NOT A LABEL. Two creates for one new home can pass the
    "no such home yet" check together; a label each would put on its own home leaves two homes
    answering to one name, and which one a later resume mounts depends on timing. The anchor
    ConfigMap is named from the home name, so only one create can make it (409 for the
    other, which goes cold); and the cold path reads the same anchor before it would make a
    home of its own. It is `claiming` until execd is bound, `committed` after.

    ⚠ THE POD STAYS THE HOME'S CONTROLLER. The home is a generic ephemeral volume, and the
    kubelet sets one up only while the claim is controlled by its pod -- removing the pod's
    ownerReference would leave a running sandbox whose home a kubelet restart refuses to mount.
    The anchor, owned by the home, becomes the home's SECOND owner instead: when the pod goes,
    the garbage collector finds an owner still present, drops the pod's reference and keeps
    the home; when the home is deleted (the reaper, by age), the anchor goes with it.
    """
    core = k8s_client.get_core_v1_api()
    pvc = core.read_namespaced_persistent_volume_claim(name=claim, namespace=namespace)
    owners = list(getattr(pvc.metadata, "owner_references", None) or [])
    if len(owners) != 1 or owners[0].uid != pod_uid or not owners[0].controller:
        raise ClaimFailed(f"home {claim} is not controlled by the claimed pod alone")
    name = anchor_name(alias_of)
    try:
        anchor = core.create_namespaced_config_map(
            namespace=namespace,
            body={
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {
                    "name": name,
                    "namespace": namespace,
                    "labels": {WARM_POOL_HOME_LABEL: (pvc.metadata.labels or {}).get(WARM_POOL_HOME_LABEL, "")},
                    "annotations": {
                        ANCHOR_HOME_ANNOTATION: claim,
                        ANCHOR_STATE_ANNOTATION: "claiming",
                        WARM_CLAIMED_BY_ANNOTATION: sandbox_id,
                        WARM_CLAIMED_AT_ANNOTATION: claimed_at,
                    },
                    "ownerReferences": [
                        {
                            "apiVersion": "v1",
                            "kind": "PersistentVolumeClaim",
                            "name": claim,
                            "uid": pvc.metadata.uid,
                            "controller": False,
                            "blockOwnerDeletion": False,
                        }
                    ],
                },
                "data": {},
            },
        )
    except Exception as exc:  # noqa: BLE001
        if getattr(exc, "status", None) == 409:
            raise ClaimFailed(f"home name already reserved by another claim ({name})") from exc
        raise
    anchor_uid = getattr(getattr(anchor, "metadata", None), "uid", None)
    if not anchor_uid:
        anchor_uid = core.read_namespaced_config_map(name=name, namespace=namespace).metadata.uid
    ops: List[Dict[str, Any]] = [
        {"op": "test", "path": "/metadata/ownerReferences/0/uid", "value": pod_uid},
        {
            "op": "add",
            "path": "/metadata/ownerReferences/-",
            "value": {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "name": name,
                "uid": anchor_uid,
                "controller": False,
                "blockOwnerDeletion": False,
            },
        },
        {"op": "add", "path": "/metadata/labels/" + _escape(HOME_ALIAS_LABEL), "value": home_alias(alias_of)},
        {"op": "add", "path": "/metadata/annotations/" + _escape(WARM_CLAIMED_BY_ANNOTATION), "value": sandbox_id},
        {"op": "add", "path": "/metadata/annotations/" + _escape(WARM_CLAIMED_AT_ANNOTATION), "value": claimed_at},
    ]
    if subject is not None:
        ops.append({"op": "add", "path": "/metadata/annotations/" + _escape(owner_annotation), "value": subject})
    core.patch_namespaced_persistent_volume_claim(name=claim, namespace=namespace, body=ops)


def release_home_name(k8s_client: Any, namespace: str, alias_of: str, claim: str) -> None:
    """Undo the reservation of a claim that failed -- only if it is this claim's. The garbage
    collector would remove the anchor with its home, but seconds later, and the cold create
    that follows at once would find the name still `claiming`."""
    core = k8s_client.get_core_v1_api()
    home, _state = resolve_anchor(k8s_client, namespace, alias_of)
    if home == claim:
        try:
            core.delete_namespaced_config_map(name=anchor_name(alias_of), namespace=namespace)
        except Exception as exc:  # noqa: BLE001
            if getattr(exc, "status", None) != 404:
                raise


def commit_home(k8s_client: Any, namespace: str, alias_of: str, sandbox_id: str) -> None:
    """The claim is bound: the home name now resolves to this home for everyone. A JSON patch
    whose first operation tests that the anchor is still THIS claim's, so a commit that lands
    late can never commit a later claim's reservation of the same name."""
    k8s_client.get_core_v1_api().patch_namespaced_config_map(
        name=anchor_name(alias_of),
        namespace=namespace,
        body=[
            {"op": "test", "path": "/metadata/annotations/" + _escape(WARM_CLAIMED_BY_ANNOTATION), "value": sandbox_id},
            {"op": "replace", "path": "/metadata/annotations/" + _escape(ANCHOR_STATE_ANNOTATION), "value": "committed"},
        ],
    )


def resolve_anchor(k8s_client: Any, namespace: str, claim_name: str) -> tuple[Optional[str], str]:
    """(home claim name, state) the anchor for this home name records, or (None, "") when there
    is no anchor."""
    try:
        anchor = k8s_client.get_core_v1_api().read_namespaced_config_map(
            name=anchor_name(claim_name), namespace=namespace
        )
    except Exception as exc:  # noqa: BLE001
        if getattr(exc, "status", None) == 404:
            return None, ""
        raise
    annotations = getattr(anchor.metadata, "annotations", None) or {}
    state = annotations.get(ANCHOR_STATE_ANNOTATION, "")
    if state == "claiming" and _older_than(annotations.get(WARM_CLAIMED_AT_ANNOTATION), STALE_CLAIM_SECONDS):
        # A claim that never committed and never cleaned up (its server died mid-claim): the
        # name is not held by anyone any more.
        state = "stale"
    return annotations.get(ANCHOR_HOME_ANNOTATION), state


STALE_CLAIM_SECONDS = 300.0


def _older_than(stamp: Optional[str], seconds: float) -> bool:
    if not stamp:
        return True
    try:
        moment = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return True
    return (datetime.now(timezone.utc) - moment).total_seconds() > seconds


def url_host(ip: str) -> str:
    """An address as the authority of a URL: an IPv6 literal goes in brackets."""
    return f"[{ip}]" if ":" in ip and not ip.startswith("[") else ip


async def push_to_sidecar(
    client: httpx.AsyncClient,
    pod_ip: str,
    token: str,
    network_policy: Dict[str, Any],
    seed: Optional[Dict[str, Any]],
) -> None:
    base = f"http://{url_host(pod_ip)}:{EGRESS_PORT}"
    headers = {OPEN_SANDBOX_EGRESS_AUTH_HEADER: token}
    response = await client.post(base + "/policy", json=network_policy, headers=headers)
    if response.status_code // 100 != 2:
        raise ClaimFailed(f"sidecar refused the policy: {response.status_code} {response.text[:200]}")
    if seed is not None:
        response = await client.post(base + "/credential-vault", json=seed, headers=headers)
        if response.status_code // 100 != 2:
            raise ClaimFailed(f"sidecar refused the vault seed: {response.status_code} {response.text[:200]}")


# An authenticated execd route that answers from memory, for the token check at the claim.
EXECD_TOKEN_CHECK_PATH = "/v1/isolated/capabilities"


async def bind_execd(
    client: httpx.AsyncClient,
    pod_ip: str,
    sandbox_id: str,
    token: str,
    envs: Dict[str, str],
    cfg: WarmPoolConfig,
) -> None:
    base = f"http://{url_host(pod_ip)}:{EXECD_PORT}"
    body: Dict[str, Any] = {
        "sandboxId": sandbox_id,
        "generation": 1,
        "accessTokenHash": execd_token_hash(token),
        "envs": envs,
    }
    if cfg.claim_prestart:
        body["lifecycle"] = {
            "version": 1,
            "preStart": {
                "command": list(cfg.claim_prestart),
                "timeoutSeconds": cfg.claim_prestart_timeout_seconds,
            },
        }
    response = await client.post(base + "/internal/init", json=body)
    if response.status_code != 200:
        raise ClaimFailed(f"execd refused the binding: {response.status_code} {response.text[:200]}")
    # The answer that counts: execd serving an authenticated route with the token just
    # issued. /ready and /ping are open before the binding, so they cannot show it.
    # ⚠ NOT /metrics: execd samples the CPU for a whole second before it answers it
    # (cpu.Percent(time.Second) in components/execd/pkg/web/controller/metric.go), which
    # was the largest part of every warm claim -- measured on stage 2026-10-17: 1.0 s of a
    # 1.08 s claim. The capabilities route reads state execd already holds.
    response = await client.get(base + EXECD_TOKEN_CHECK_PATH, headers={EXECD_ACCESS_TOKEN_HEADER: token})
    if response.status_code != 200:
        raise ClaimFailed(f"execd does not accept the issued token: {response.status_code}")
