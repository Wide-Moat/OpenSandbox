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

import unittest.mock
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from kubernetes.client.exceptions import ApiException

from opensandbox_server.config import AppConfig, EgressConfig, RuntimeConfig, SecureRuntimeConfig
from opensandbox_server.services.runtime_resolver import (
    SecureRuntimeResolver,
    validate_secure_runtime_on_startup,
)


def _config(runtime_type: str = "docker", secure_runtime=None, egress=None):
    return AppConfig(
        runtime=RuntimeConfig(type=runtime_type, execd_image="opensandbox/execd:test"),
        secure_runtime=secure_runtime,
        egress=egress,
    )


def test_secure_runtime_resolver_disabled_without_runtime() -> None:
    resolver = SecureRuntimeResolver(_config())

    assert resolver.is_enabled() is False
    assert resolver.get_docker_runtime() is None
    assert resolver.get_k8s_runtime_class() is None


def test_secure_runtime_resolver_prefers_explicit_values_and_defaults() -> None:
    docker_resolver = SecureRuntimeResolver(
        _config(secure_runtime=SecureRuntimeConfig(type="gvisor", docker_runtime="custom-runsc"))
    )
    k8s_resolver = SecureRuntimeResolver(
        _config(
            runtime_type="kubernetes",
            secure_runtime=SecureRuntimeConfig(type="kata", k8s_runtime_class="kata-custom"),
        )
    )
    default_docker = SecureRuntimeResolver(
        _config(secure_runtime=SecureRuntimeConfig(type="gvisor", k8s_runtime_class="gvisor"))
    )
    default_k8s = SecureRuntimeResolver(
        _config(
            runtime_type="kubernetes",
            secure_runtime=SecureRuntimeConfig(type="kata", docker_runtime="kata-runtime"),
        )
    )

    assert docker_resolver.is_enabled() is True
    assert docker_resolver.get_docker_runtime() == "custom-runsc"
    assert k8s_resolver.get_k8s_runtime_class() == "kata-custom"
    assert default_docker.get_docker_runtime() == "runsc"
    assert default_k8s.get_k8s_runtime_class() == "kata-qemu"


@pytest.mark.asyncio
async def test_validate_secure_runtime_skips_when_disabled() -> None:
    docker_client = MagicMock()

    await validate_secure_runtime_on_startup(_config(), docker_client=docker_client)

    docker_client.info.assert_not_called()


@pytest.mark.asyncio
async def test_validate_secure_runtime_checks_docker_runtime() -> None:
    docker_client = MagicMock()
    docker_client.info.return_value = {"Runtimes": {"runsc": {"path": "/usr/bin/runsc"}}}
    config = _config(
        secure_runtime=SecureRuntimeConfig(type="gvisor", docker_runtime="runsc")
    )

    await validate_secure_runtime_on_startup(config, docker_client=docker_client)

    docker_client.info.assert_called_once()


@pytest.mark.asyncio
async def test_validate_secure_runtime_rejects_missing_docker_runtime() -> None:
    docker_client = MagicMock()
    docker_client.info.return_value = {"Runtimes": {"runc": {}}}
    config = _config(
        secure_runtime=SecureRuntimeConfig(type="gvisor", docker_runtime="runsc")
    )

    with pytest.raises(ValueError, match="runsc"):
        await validate_secure_runtime_on_startup(config, docker_client=docker_client)


@pytest.mark.asyncio
async def test_validate_secure_runtime_allows_missing_docker_client() -> None:
    config = _config(
        secure_runtime=SecureRuntimeConfig(type="gvisor", docker_runtime="runsc")
    )

    await validate_secure_runtime_on_startup(config, docker_client=None)


@pytest.mark.asyncio
async def test_validate_secure_runtime_checks_k8s_runtime_class() -> None:
    k8s_client = MagicMock()
    config = _config(
        runtime_type="kubernetes",
        secure_runtime=SecureRuntimeConfig(type="gvisor", k8s_runtime_class="gvisor"),
    )

    await validate_secure_runtime_on_startup(config, k8s_client=k8s_client)

    k8s_client.read_runtime_class.assert_called_once_with("gvisor")


@pytest.mark.asyncio
async def test_validate_secure_runtime_rejects_missing_k8s_runtime_class() -> None:
    k8s_client = MagicMock()
    k8s_client.read_runtime_class.side_effect = ApiException(status=404)
    config = _config(
        runtime_type="kubernetes",
        secure_runtime=SecureRuntimeConfig(type="gvisor", k8s_runtime_class="gvisor"),
    )

    with pytest.raises(ValueError, match="RuntimeClass 'gvisor'"):
        await validate_secure_runtime_on_startup(config, k8s_client=k8s_client)


@pytest.mark.asyncio
async def test_validate_secure_runtime_reraises_k8s_api_errors() -> None:
    k8s_client = MagicMock()
    k8s_client.read_runtime_class.side_effect = ApiException(status=500)
    config = _config(
        runtime_type="kubernetes",
        secure_runtime=SecureRuntimeConfig(type="gvisor", k8s_runtime_class="gvisor"),
    )

    with pytest.raises(ApiException):
        await validate_secure_runtime_on_startup(config, k8s_client=k8s_client)


@pytest.mark.asyncio
async def test_validate_secure_runtime_allows_missing_k8s_client() -> None:
    config = _config(
        runtime_type="kubernetes",
        secure_runtime=SecureRuntimeConfig(type="gvisor", k8s_runtime_class="gvisor"),
    )

    await validate_secure_runtime_on_startup(config, k8s_client=None)


@pytest.mark.asyncio
async def test_validate_secure_runtime_skips_unknown_runtime_type() -> None:
    config = SimpleNamespace(
        runtime=SimpleNamespace(type="custom"),
        secure_runtime=SimpleNamespace(
            type="gvisor",
            docker_runtime="runsc",
            k8s_runtime_class=None,
        ),
    )

    await validate_secure_runtime_on_startup(config)


@pytest.mark.asyncio
async def test_validate_startup_warns_gvisor_with_egress() -> None:
    k8s_client = MagicMock()
    config = _config(
        runtime_type="kubernetes",
        secure_runtime=SecureRuntimeConfig(type="gvisor", k8s_runtime_class="gvisor"),
        egress=EgressConfig(image="opensandbox/egress:latest"),
    )

    with unittest.mock.patch(
        "opensandbox_server.services.runtime_resolver.logger"
    ) as mock_logger:
        await validate_secure_runtime_on_startup(config, k8s_client=k8s_client)

    mock_logger.warning.assert_called_once()
    assert "iptables nat" in mock_logger.warning.call_args[0][0]


@pytest.mark.asyncio
async def test_validate_startup_no_warn_gvisor_without_egress() -> None:
    k8s_client = MagicMock()
    config = _config(
        runtime_type="kubernetes",
        secure_runtime=SecureRuntimeConfig(type="gvisor", k8s_runtime_class="gvisor"),
    )

    with unittest.mock.patch(
        "opensandbox_server.services.runtime_resolver.logger"
    ) as mock_logger:
        await validate_secure_runtime_on_startup(config, k8s_client=k8s_client)

    mock_logger.warning.assert_not_called()


@pytest.mark.asyncio
async def test_validate_startup_no_warn_kata_with_egress() -> None:
    k8s_client = MagicMock()
    config = _config(
        runtime_type="kubernetes",
        secure_runtime=SecureRuntimeConfig(type="kata", k8s_runtime_class="kata-qemu"),
        egress=EgressConfig(image="opensandbox/egress:latest"),
    )

    with unittest.mock.patch(
        "opensandbox_server.services.runtime_resolver.logger"
    ) as mock_logger:
        await validate_secure_runtime_on_startup(config, k8s_client=k8s_client)

    mock_logger.warning.assert_not_called()


def _egress_with_enforcement(enforcement: str) -> EgressConfig:
    """Build an egress config carrying ``[egress] enforcement``, when the field exists.

    The key is written as a literal string and filtered against ``model_fields`` rather
    than passed as a keyword, for the reason the sibling checks in ``test_validators.py``
    give: naming a field that an unmodified tree does not have makes the test fail to
    CONSTRUCT, which proves only that a field is missing and goes green the moment one
    exists with nothing behind it. Filtered, the unmodified tree builds a valid config,
    reaches the warning, and fails on what was LOGGED.
    """
    # disable_ipv6 off, as external enforcement requires it to be (see EgressConfig).
    fields = {
        "image": "opensandbox/egress:latest",
        "enforcement": enforcement,
        "disable_ipv6": False,
    }
    return EgressConfig(**{k: v for k, v in fields.items() if k in EgressConfig.model_fields})


@pytest.mark.asyncio
async def test_wm2_no_warn_gvisor_with_external_enforcement() -> None:
    """The warning promises a rejection that external enforcement does not perform.

    Both validators -- ``ensure_credential_proxy_configured`` and
    ``ensure_egress_runtime_compatible`` -- return early under
    ``[egress] enforcement = "external"``, so no sandbox is rejected at creation time.
    A warning saying otherwise is false, and a false warning about a security control
    is worse than none: it is read as a reason to change a configuration that is right.
    """
    k8s_client = MagicMock()
    config = _config(
        runtime_type="kubernetes",
        secure_runtime=SecureRuntimeConfig(type="gvisor", k8s_runtime_class="gvisor"),
        egress=_egress_with_enforcement("external"),
    )

    with unittest.mock.patch(
        "opensandbox_server.services.runtime_resolver.logger"
    ) as mock_logger:
        await validate_secure_runtime_on_startup(config, k8s_client=k8s_client)

    warned = [
        call for call in mock_logger.warning.call_args_list if "iptables nat" in str(call)
    ]
    assert warned == [], f"warned about a rejection that will not happen: {warned}"


@pytest.mark.asyncio
async def test_wm2_still_warns_gvisor_with_sidecar_enforcement() -> None:
    """The guard: the default is unchanged.

    Without this, deleting the warning outright would pass the test above while
    removing a true warning for every deployment that does enforce in the sidecar --
    where the rejection the message describes really does happen.
    """
    k8s_client = MagicMock()
    config = _config(
        runtime_type="kubernetes",
        secure_runtime=SecureRuntimeConfig(type="gvisor", k8s_runtime_class="gvisor"),
        egress=_egress_with_enforcement("sidecar"),
    )

    with unittest.mock.patch(
        "opensandbox_server.services.runtime_resolver.logger"
    ) as mock_logger:
        await validate_secure_runtime_on_startup(config, k8s_client=k8s_client)

    warned = [
        call for call in mock_logger.warning.call_args_list if "iptables nat" in str(call)
    ]
    assert len(warned) == 1, f"expected the gVisor/egress warning, got: {mock_logger.warning.call_args_list}"


@pytest.mark.asyncio
async def test_wm2_docker_still_warns_gvisor_under_external_enforcement() -> None:
    """The warning is suppressed on Kubernetes only.

    The Docker runtime never tells its sidecar that enforcement is external: it judges
    every create as sidecar enforcement and still rejects gVisor with a network_policy
    (``DockerNetworkingMixin._ensure_network_policy_support``). There the warning's
    prediction is true whatever ``[egress] enforcement`` says, and hiding it would leave
    the rejection unannounced.
    """
    docker_client = MagicMock()
    docker_client.info.return_value = {"Runtimes": {"runsc": {"path": "/usr/bin/runsc"}}}
    config = _config(
        runtime_type="docker",
        secure_runtime=SecureRuntimeConfig(type="gvisor", docker_runtime="runsc"),
        egress=_egress_with_enforcement("external"),
    )

    with unittest.mock.patch(
        "opensandbox_server.services.runtime_resolver.logger"
    ) as mock_logger:
        await validate_secure_runtime_on_startup(config, docker_client=docker_client)

    warned = [
        call for call in mock_logger.warning.call_args_list if "iptables nat" in str(call)
    ]
    assert len(warned) == 1, f"expected the gVisor/egress warning, got: {mock_logger.warning.call_args_list}"
