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
"""ZenML server API token models."""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict


class APIToken(BaseModel):
    """Cached API Token."""

    access_token: str
    expires_in: Optional[int] = None
    expires_at: Optional[datetime] = None
    leeway: Optional[int] = None
    cookie_name: Optional[str] = None
    device_id: Optional[str] = None
    device_metadata: Optional[Dict[str, Any]] = None

    @property
    def expired(self) -> bool:
        """Check if the token is expired.

        Returns:
            bool: True if the token is expired, False otherwise.
        """
        if not self.expires_at:
            return False
        expires_at = self.expires_at
        if self.leeway:
            expires_at -= timedelta(seconds=self.leeway)
        return expires_at < datetime.now(timezone.utc)

    model_config = ConfigDict(
        # Allow extra attributes to allow backwards compatibility
        extra="allow",
    )
