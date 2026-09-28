"""Coverage for the 400 an unusable resourceLimits name produces.

The path from the guard to an HTTP client crosses four layers, and this suite
covers them in three places rather than one, because no single test in this
repository's existing harness spans all four:

  provider   tests/k8s/test_provider_common.py -- the guard raises 400
  provider   tests/k8s/test_batchsandbox_provider.py -- create_workload raises
             and submits nothing to the API server
  service    test_service_create_sandbox_rethrows_provider_http_error (below) --
             the real KubernetesSandboxService.create_sandbox, with only the
             external K8sClient substituted, re-raises the provider's 400 and
             submits no workload
  service    test_quota_classifier_returns_none_for_http_exception (below) --
             unit coverage of the classifier that decides between mapping and
             re-raising
  route/app  test_route_preserves_status_from_service (below) -- the route and
             the application-level HTTPException handler preserve the status

The service test runs production code end to end from the service downward: the
real service, the real provider and the real resource-name guard, with only
``K8sClient`` -- the external Kubernetes boundary -- substituted.
"""

import pytest
from unittest.mock import patch

from fastapi import HTTPException, status
from kubernetes.client import ApiException

from opensandbox_server.services.constants import SandboxErrorCodes
from opensandbox_server.services.k8s.error_helpers import _quota_rejection_message


def _invalid_resource_name_error() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={
            "code": SandboxErrorCodes.INVALID_PARAMETER,
            "message": "Kubernetes runtime cannot use resourceLimits ['memoryMB']",
        },
    )


def test_quota_classifier_returns_none_for_http_exception():
    """Unit coverage of the classifier alone -- it does not execute the service.

    kubernetes_service.create_sandbox catches Exception around create_workload
    and maps to a quota error only when this returns a message. An HTTPException
    is not a 403 ApiException, so it must classify as None. Whether the service
    then re-raises is covered by
    test_service_create_sandbox_rethrows_provider_http_error, which runs the
    real service.
    """
    assert _quota_rejection_message(_invalid_resource_name_error()) is None


def test_quota_rejection_still_classified():
    """Control: the branch that DOES map still maps, so the test above is not
    passing merely because the classifier returns None for everything."""
    quota_exc = ApiException(status=403)
    quota_exc.body = '{"message": "pods \\"x\\" is forbidden: exceeded quota"}'
    assert _quota_rejection_message(quota_exc) is not None


def test_route_preserves_status_from_service(
    client, auth_headers, sample_sandbox_request
):
    """A 400 raised beneath the route reaches the client as 400, not 500.

    This substitutes the service to isolate the route and the application-level
    HTTPException handler in main.py; it does not exercise the provider. The
    provider's own behaviour is covered in tests/k8s, and the service boundary
    between them is covered above.
    """
    request = dict(sample_sandbox_request)
    request["resourceLimits"] = {"cpu": "1", "memoryMB": "1024"}

    with patch(
        "opensandbox_server.api.lifecycle.sandbox_service.create_sandbox",
        side_effect=_invalid_resource_name_error(),
    ):
        response = client.post("/v1/sandboxes", json=request, headers=auth_headers)

    assert response.status_code == 400
    payload = response.json()
    assert payload["code"] == SandboxErrorCodes.INVALID_PARAMETER
    assert "memoryMB" in payload["message"]


@pytest.mark.asyncio
async def test_service_create_sandbox_rethrows_provider_http_error():
    """The real service must surface the provider's 400 and submit no workload.

    This runs production code from the service downward -- the real
    KubernetesSandboxService, the real BatchSandbox provider and the real
    resource-name guard -- with only ``K8sClient``, the external Kubernetes
    boundary, substituted. Nothing under test is replaced by a fake.

    Two properties matter and are asserted separately:

      * the status survives. kubernetes_service.create_sandbox catches
        ``Exception`` around create_workload, so the 400 passes through a broad
        handler that could map it to a 500.
      * nothing is submitted. A create that cannot produce a valid pod must not
        leave a workload behind, and the rollback that runs on the way out must
        not mask the original error with its own.
    """
    import pathlib

    import opensandbox_server
    from opensandbox_server.api.schema import CreateSandboxRequest
    from opensandbox_server.config import load_config
    from opensandbox_server.services.k8s.kubernetes_service import (
        KubernetesSandboxService,
    )

    example = (
        pathlib.Path(opensandbox_server.__file__).parent
        / "examples"
        / "example.config.k8s.toml"
    )
    config = load_config(example)
    # The shipped config points batchsandbox_template_file at ~/, which does not
    # exist in a test environment. Point it at the template shipped beside it so
    # the real TemplateManager loads a real template rather than being mocked.
    assert config.kubernetes is not None
    config.kubernetes.batchsandbox_template_file = str(
        example.parent / "example.batchsandbox-template.yaml"
    )

    with patch(
        "opensandbox_server.services.k8s.kubernetes_service.K8sClient"
    ) as k8s_client_cls:
        client = k8s_client_cls.return_value
        service = KubernetesSandboxService(config)

        request = CreateSandboxRequest.model_validate(
            {
                "image": {"uri": "python:3.11"},
                "entrypoint": ["/bin/sh", "-c", "sleep 1"],
                "resourceLimits": {"cpu": "1", "memoryMB": "1024"},
            }
        )

        with pytest.raises(HTTPException) as exc:
            await service.create_sandbox(request)

    # The provider's 400 survived the service's broad except/rollback path.
    assert exc.value.status_code == 400
    assert "memoryMB" in exc.value.detail["message"]
    # The rollback did not replace it with an error of its own.
    assert exc.value.detail["code"] == SandboxErrorCodes.INVALID_PARAMETER
    # Nothing was submitted to Kubernetes.
    client.create_custom_object.assert_not_called()
