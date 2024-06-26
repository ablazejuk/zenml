#  Copyright (c) ZenML GmbH 2024. All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at:
#
#       https://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
#  or implied. See the License for the specific language governing
#  permissions and limitations under the License.
"""Endpoint definitions for stack deployments."""

import datetime
from typing import Optional, Tuple

from fastapi import APIRouter, Request, Security

from zenml.constants import API, INFO, STACK, STACK_DEPLOYMENT, URL, VERSION_1
from zenml.enums import StackDeploymentProvider
from zenml.models import DeployedStack, StackDeploymentInfo
from zenml.stack_deployments.utils import get_stack_deployment_class
from zenml.zen_server.auth import AuthContext, authorize
from zenml.zen_server.exceptions import error_response
from zenml.zen_server.rbac.models import Action, ResourceType
from zenml.zen_server.rbac.utils import verify_permission
from zenml.zen_server.utils import (
    handle_exceptions,
)

router = APIRouter(
    prefix=API + VERSION_1 + STACK_DEPLOYMENT,
    tags=["stacks"],
    responses={401: error_response, 403: error_response},
)


@router.get(
    INFO,
)
@handle_exceptions
def get_stack_deployment_info(
    provider: StackDeploymentProvider,
    _: AuthContext = Security(authorize),
) -> StackDeploymentInfo:
    """Get information about a stack deployment provider.

    Args:
        provider: The stack deployment provider.

    Returns:
        Information about the stack deployment provider.
    """
    stack_deployment_class = get_stack_deployment_class(provider)
    return StackDeploymentInfo(
        provider=provider,
        description=stack_deployment_class.description(),
        instructions=stack_deployment_class.instructions(),
        post_deploy_instructions=stack_deployment_class.post_deploy_instructions(),
        permissions=stack_deployment_class.permissions(),
        locations=stack_deployment_class.locations(),
    )


@router.get(
    URL,
)
@handle_exceptions
def get_stack_deployment_url(
    request: Request,
    provider: StackDeploymentProvider,
    stack_name: str,
    location: Optional[str] = None,
    auth_context: AuthContext = Security(authorize),
) -> Tuple[str, str]:
    """Return the URL to deploy the ZenML stack to the specified cloud provider.

    Args:
        request: The FastAPI request object.
        provider: The stack deployment provider.
        stack_name: The name of the stack.
        location: The location where the stack should be deployed.
        auth_context: The authentication context.

    Returns:
        The URL to deploy the ZenML stack to the specified cloud provider
        and a text description of the URL.
    """
    verify_permission(
        resource_type=ResourceType.SERVICE_CONNECTOR, action=Action.CREATE
    )
    verify_permission(
        resource_type=ResourceType.STACK_COMPONENT,
        action=Action.CREATE,
    )
    verify_permission(resource_type=ResourceType.STACK, action=Action.CREATE)

    stack_deployment_class = get_stack_deployment_class(provider)
    # Get the base server URL used to call this FastAPI endpoint
    url = request.url.replace(path="").replace(query="")
    # Use HTTPS for the URL
    url = url.replace(scheme="https")

    token = auth_context.access_token
    assert token is not None

    # A new API token is generated for the stack deployment
    expires = datetime.datetime.utcnow() + datetime.timedelta(minutes=60)
    api_token = token.encode(expires=expires)

    return stack_deployment_class(
        stack_name=stack_name, location=location
    ).deploy_url(zenml_server_url=str(url), zenml_server_api_token=api_token)


@router.get(
    STACK,
)
@handle_exceptions
def get_deployed_stack(
    provider: StackDeploymentProvider,
    stack_name: str,
    location: Optional[str] = None,
    date_start: Optional[datetime.datetime] = None,
    _: AuthContext = Security(authorize),
) -> Optional[DeployedStack]:
    """Return a matching ZenML stack that was deployed and registered.

    Args:
        provider: The stack deployment provider.
        stack_name: The name of the stack.
        location: The location where the stack should be deployed.
        date_start: The date when the deployment started.

    Returns:
        The ZenML stack that was deployed and registered or None if the stack
        was not found.
    """
    stack_deployment_class = get_stack_deployment_class(provider)
    return stack_deployment_class(
        stack_name=stack_name, location=location
    ).get_stack(date_start=date_start)
