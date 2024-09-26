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
"""ZenML Pro login utils."""

import re
from uuid import UUID

from zenml.login.pro.constants import ZENML_PRO_URL
from zenml.login.pro.tenant.models import TenantRead


def is_zenml_pro_server(url: str) -> bool:
    """Check if a given URL is a ZenML Pro server.

    Args:
        url: URL to check

    Returns:
        True if the URL is a ZenML Pro tenant, False otherwise
    """
    return (
        re.match(
            r"^(https://)?[a-z0-9]+-zenml\.([a-z]+\.)cloudinfra\.zenml\.io$",
            url,
        )
        is not None
    )
