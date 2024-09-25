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
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from zenml.config.global_config import GlobalConfiguration
from zenml.io import fileio
from zenml.logger import get_logger
from zenml.login.constants import (
    TOKEN_CACHE_EVICTION_TIME,
    TOKEN_CACHE_FILENAME,
)
from zenml.login.token import APIToken
from zenml.models import OAuthTokenResponse
from zenml.utils import yaml_utils
from zenml.utils.singleton import SingletonMetaClass

logger = get_logger(__name__)


class APITokenCache(metaclass=SingletonMetaClass):
    """API Token Cache.

    Implements a simple cache for API tokens backed by a YAML file on disk.
    """

    tokens: Dict[str, APIToken] = {}
    last_modified_time: Optional[float] = None

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
        return os.path.join(config_path, TOKEN_CACHE_FILENAME)

    def _load_cache(self) -> None:
        """Load the cache from the YAML file if it exists."""
        cache_file = self._cache_file
        token_cache = {}

        if fileio.exists(cache_file):
            token_cache = yaml_utils.read_yaml(cache_file)
            self.last_modified_time = os.path.getmtime(cache_file)

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
            server_url: token.model_dump(exclude_none=True, exclude_unset=True)
            for server_url, token in self.tokens.items()
            # Evict tokens that have expired past the eviction time
            if not token.expires_at
            or token.expires_at + timedelta(seconds=TOKEN_CACHE_EVICTION_TIME)
            > datetime.now(timezone.utc)
        }
        yaml_utils.write_yaml(cache_file, token_cache)
        self.last_modified_time = os.path.getmtime(cache_file)

    def check_and_reload_cache(self) -> None:
        """Check if the token cache file has been modified and reload it if necessary."""
        if not self.last_modified_time:
            return
        cache_file = self._cache_file
        try:
            last_modified_time = os.path.getmtime(cache_file)
        except FileNotFoundError:
            # The cache file has been deleted
            self.last_modified_time = None
            return
        if last_modified_time != self.last_modified_time:
            self._load_cache()

    def get_token(
        self, server_url: str, allow_expired: bool = False
    ) -> Optional[APIToken]:
        """Retrieve a valid token from the cache for a specific server URL.

        Args:
            server_url: The server URL for which to retrieve the token.
            allow_expired: Whether to allow expired tokens to be returned. The
                default behavior is to return None if a token does exist but is
                expired.

        Returns:
            The cached token if it exists and is not expired, None otherwise.
        """
        self.check_and_reload_cache()
        token = self.tokens.get(server_url)
        if token and (not token.expired or allow_expired):
            return token
        return None

    def set_token(
        self, server_url: str, token_response: OAuthTokenResponse
    ) -> APIToken:
        """Cache an API token received from an OAuth2 server.

        Args:
            server_url: The server URL for which the token is to be cached.
            token_response: Token response received from an OAuth2 server.

        Returns:
            APIToken: The cached token.
        """
        if token_response.expires_in:
            expires_at = datetime.now(timezone.utc) + timedelta(
                seconds=token_response.expires_in
            )
            # Best practice to calculate the leeway depending on the token
            # expiration time:
            #
            # - for short-lived tokens (less than 1 hour), use a fixed leeway of
            # a few seconds (e.g., 30 seconds)
            # - for longer-lived tokens (e.g., 1 hour or more), use a
            # percentage-based leeway of 5-10%
            if token_response.expires_in < 3600:
                leeway = 30
            else:
                leeway = token_response.expires_in // 20
        else:
            expires_at = None
            leeway = None

        api_token = APIToken(
            access_token=token_response.access_token,
            expires_in=token_response.expires_in,
            expires_at=expires_at,
            leeway=leeway,
            cookie_name=token_response.cookie_name,
            device_id=token_response.device_id,
            device_metadata=token_response.device_metadata,
        )
        self.tokens[server_url] = api_token
        self.save_cache()

        return api_token


def get_token_cache() -> APITokenCache:
    """Get the global token cache instance.

    Returns:
        APITokenCache: The global token cache instance.
    """
    return APITokenCache()
