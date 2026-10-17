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

"""The credential-vault seed's Secret on Kubernetes (WM-25).

A seed (WM-8) holds credentials, so it must not be a plain env value in the pod
template: anyone allowed to read pods or the workload in the sandbox namespace would
read every sandbox's credentials. It goes into a Secret of its own, one per sandbox,
and the egress sidecar reads it through ``valueFrom.secretKeyRef`` under the same
variable name, so the sidecar is unchanged.

Order: the Secret is created AFTER the workload, with an ownerReference to the uid the
create returned, exactly as upstream does for the image-pull Secret. The reverse order
leaks: a server that dies between a Secret it created first and the workload leaves a
credential in the namespace that nothing owns and nothing deletes. Created after, the
Secret is owned from its first instant and the garbage collector removes it with the
workload, on delete and on expiry alike. The pod cannot race ahead of it in practice --
the sidecar is a regular container, started only after the execd init container has
finished -- and if it ever did, the kubelet holds that container in
CreateContainerConfigError and retries; it does not start it without the seed.
"""

import base64
import json
import logging
from typing import Any, Callable, Dict, Optional

from kubernetes.client import V1ObjectMeta, V1OwnerReference, V1Secret

from opensandbox_server.services.constants import SANDBOX_ID_LABEL

logger = logging.getLogger(__name__)

CREDENTIAL_VAULT_SEED_SECRET_PREFIX = "opensandbox-vault-seed"
CREDENTIAL_VAULT_SEED_SECRET_KEY = "seed"
# Marks the Secret as a seed, so a sweep can find every one by label alone.
CREDENTIAL_VAULT_SEED_LABEL = "opensandbox.io/credential-vault-seed"


def credential_vault_seed_secret_name(sandbox_id: str) -> str:
    return f"{CREDENTIAL_VAULT_SEED_SECRET_PREFIX}-{sandbox_id}"


def credential_vault_seed_env_entry(env_name: str, sandbox_id: str) -> Dict[str, Any]:
    """The sidecar's env entry: a reference to the Secret, never the value."""
    return {
        "name": env_name,
        "valueFrom": {
            "secretKeyRef": {
                "name": credential_vault_seed_secret_name(sandbox_id),
                "key": CREDENTIAL_VAULT_SEED_SECRET_KEY,
            }
        },
    }


def build_credential_vault_seed_secret(
    sandbox_id: str,
    seed: Dict[str, Any],
    owner_uid: str,
    owner_api_version: str,
    owner_kind: str,
    owner_name: Optional[str] = None,
) -> V1Secret:
    """The seed as an immutable Opaque Secret owned by the sandbox's workload."""
    payload = base64.b64encode(json.dumps(seed).encode()).decode()
    return V1Secret(
        api_version="v1",
        kind="Secret",
        metadata=V1ObjectMeta(
            name=credential_vault_seed_secret_name(sandbox_id),
            labels={
                SANDBOX_ID_LABEL: sandbox_id,
                CREDENTIAL_VAULT_SEED_LABEL: "true",
            },
            owner_references=[
                V1OwnerReference(
                    api_version=owner_api_version,
                    kind=owner_kind,
                    name=owner_name if owner_name is not None else sandbox_id,
                    uid=owner_uid,
                    controller=False,
                )
            ],
        ),
        type="Opaque",
        immutable=True,
        data={CREDENTIAL_VAULT_SEED_SECRET_KEY: payload},
    )


def create_credential_vault_seed_secret(
    k8s_client: Any,
    namespace: str,
    sandbox_id: str,
    seed: Optional[Dict[str, Any]],
    created: Dict[str, Any],
    owner_api_version: str,
    owner_kind: str,
    roll_back: Callable[[], None],
) -> None:
    """Create the seed's Secret for a workload that was just created; on failure, delete
    the workload and re-raise. A workload left without its Secret would hold its quota in
    CreateContainerConfigError until it expired. No-op without a seed."""
    if seed is None:
        return
    secret = build_credential_vault_seed_secret(
        sandbox_id=sandbox_id,
        seed=seed,
        owner_uid=created["metadata"]["uid"],
        owner_name=created["metadata"]["name"],
        owner_api_version=owner_api_version,
        owner_kind=owner_kind,
    )
    try:
        k8s_client.create_secret(namespace=namespace, body=secret)
        logger.info(f"Created credential vault seed Secret for sandbox {sandbox_id}")
    except Exception:
        logger.warning(
            f"Failed to create credential vault seed Secret for sandbox {sandbox_id}, "
            f"rolling back {owner_kind}"
        )
        try:
            roll_back()
        except Exception as del_exc:
            logger.warning(f"Failed to rollback {owner_kind} {sandbox_id}: {del_exc}")
        raise
