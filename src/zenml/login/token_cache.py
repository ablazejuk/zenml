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
"""ZenML server API token cache support."""

import os
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Dict, Optional

from pydantic import BaseModel

from zenml.config.global_config import GlobalConfiguration
from zenml.io import fileio
from zenml.logger import get_logger
from zenml.utils import yaml_utils
from zenml.utils.singleton import SingletonMetaClass

if TYPE_CHECKING:
    pass


logger = get_logger(__name__)


class APIToken(BaseModel):
    """Cached API Token."""

    access_token: str
    token_type: str
    expires_at: datetime

    @property
    def expired(self) -> bool:
        """Check if the token is expired.

        Returns:
            bool: True if the token is expired, False otherwise.
        """
        return self.expires_at < datetime.now(timezone.utc)


class APITokenCache(metaclass=SingletonMetaClass):
    """API Token Cache.

    Implements a simple cache for API tokens backed by a YAML file on disk.
    """

    tokens: Dict[str, APIToken] = {}

    def __init__(self) -> None:
        """Initializes the API token cache with values loaded from the token cache YAML file.

        APITokenCache is a singleton class: only one instance can exist.
        Calling this constructor multiple times will always yield the same
        instance.

        Args:
            data: Custom configuration options.
        """
        self._load_cache()

    @property
    def _cache_file(self) -> str:
        """Path to the file where the token cache is stored.

        Returns:
            The path to the file where the token cache is stored.
        """
        config_path = GlobalConfiguration().config_directory
        return os.path.join(config_path, "token_cache.yaml")

    def _load_cache(self) -> None:
        """Load the cache from the YAML file if it exists."""
        cache_file = self._cache_file
        token_cache = {}

        if fileio.exists(cache_file):
            token_cache = yaml_utils.read_yaml(cache_file)

        if token_cache is None:
            # This can happen for example if the config file is empty
            token_cache = {}
        elif not isinstance(token_cache, dict):
            logger.warning(
                f"The token cache file {cache_file} is corrupted. "
                "Creating a new token cache file."
            )
            token_cache = {}

        for server_url, token_data in token_cache.items():
            try:
                self.tokens[server_url] = APIToken(**token_data)
            except ValueError as e:
                logger.warning(
                    f"Failed to load token data for {server_url}: {e}. "
                    "Ignoring this token."
                )

    def save_cache(self) -> None:
        """Save the current token cache to the YAML file."""
        cache_file = self._cache_file
        token_cache = {
            server_url: token.model_dump(exclude_none=True)
            for server_url, token in self.tokens.items()
            # Skip expired tokens
            if not token.expired
        }
        yaml_utils.write_yaml(cache_file, token_cache)

    def get_token(self, server_url: str) -> Optional[APIToken]:
        """Retrieve a token from the cache for a specific server URL.

        Args:
            server_url: The server URL for which to retrieve the token.

        Returns:
            The cached token if it exists and is not expired, None otherwise.
        """
        token = self.tokens.get(server_url)
        if token and not token.expired:
            return token
        return None

    def set_token(self, server_url: str, token: APIToken) -> None:
        """Cache a new API token.

        Args:
            server_url: The server URL for which the token is to be cached.
            token: The token to cache.
        """
        self.tokens[server_url] = token
        self.save_cache()


def get_token_cache() -> APITokenCache:
    """Get the global token cache instance.

    Returns:
        APITokenCache: The global token cache instance.
    """
    return APITokenCache()
