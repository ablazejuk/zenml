#  Copyright (c) ZenML GmbH 2022. All Rights Reserved.
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
"""CLI for managing ZenML server deployments."""

import ipaddress
import os
import sys
from typing import Any, Dict, Optional, Union

import click
from rich.errors import MarkupError

import zenml
from zenml.cli import utils as cli_utils
from zenml.cli.cli import cli
from zenml.config.global_config import GlobalConfiguration
from zenml.console import console
from zenml.constants import ENV_ZENML_LOCAL_SERVER
from zenml.enums import ServerProviderType, StoreType
from zenml.exceptions import AuthorizationException, IllegalOperationError
from zenml.logger import get_logger
from zenml.login.web_login import web_login
from zenml.zen_server.utils import get_active_deployment

logger = get_logger(__name__)

LOCAL_ZENML_SERVER_NAME = "local"


def start_local_server(
    docker: bool = False,
    ip_address: Union[
        ipaddress.IPv4Address, ipaddress.IPv6Address, None
    ] = None,
    port: Optional[int] = None,
    blocking: bool = False,
    image: Optional[str] = None,
    ngrok_token: Optional[str] = None,
    legacy: bool = False,
) -> None:
    """Start the ZenML dashboard locally and connect the client to it.

    Args:
        docker: Use a docker deployment instead of the local process.
        ip_address: The IP address to bind the server to.
        port: The port to bind the server to.
        blocking: Block the CLI while the server is running.
        image: A custom Docker image to use for the server, when the
            `--docker` flag is set.
        ngrok_token: An ngrok auth token to use for exposing the ZenML dashboard
            on a public domain. Primarily used for accessing the dashboard in
            Colab.
        legacy: Start the legacy ZenML dashboard instead of the new ZenML
            dashboard.
    """
    from zenml.zen_server.deploy.deployer import ServerDeployer

    gc = GlobalConfiguration()

    # Raise an error if the client is already connected to a remote server.
    if gc.store_configuration.type == StoreType.REST:
        if not gc.zen_store.is_local_store():
            cli_utils.error(
                "Your ZenML client is already connected to a remote server. If "
                "you want to spin up a local ZenML server, please disconnect "
                "from the remote server first by running `zenml logout`."
            )

    if docker:
        from zenml.utils.docker_utils import check_docker

        if not check_docker():
            cli_utils.error(
                "Docker does not seem to be installed on your system. Please "
                "install Docker to use the Docker ZenML server local "
                "deployment or use one of the other deployment options."
            )
        provider = ServerProviderType.DOCKER
    else:
        if sys.platform == "win32" and not blocking:
            cli_utils.error(
                "Running the ZenML server locally as a background process is "
                "not supported on Windows. Please use the `--blocking` flag "
                "to run the server in blocking mode, or run the server in "
                "a Docker container by setting `--docker` instead."
            )
        else:
            pass
        provider = ServerProviderType.LOCAL
    if cli_utils.requires_mac_env_var_warning():
        cli_utils.error(
            "The `OBJC_DISABLE_INITIALIZE_FORK_SAFETY` environment variable "
            "is recommended to run the ZenML server locally on a Mac. "
            "Please set it to `YES` and try again."
        )

    os.environ[ENV_ZENML_LOCAL_SERVER] = str(True)

    deployer = ServerDeployer()

    server = get_active_deployment(local=True)
    if server and server.config.provider != provider:
        deployer.remove_server(LOCAL_ZENML_SERVER_NAME)

    config_attrs: Dict[str, Any] = dict(
        name=LOCAL_ZENML_SERVER_NAME,
        provider=provider,
    )
    if not docker:
        config_attrs["blocking"] = blocking
    elif image:
        config_attrs["image"] = image
    if port is not None:
        config_attrs["port"] = port
    if ip_address is not None and provider in [
        ServerProviderType.LOCAL,
        ServerProviderType.DOCKER,
    ]:
        config_attrs["ip_address"] = ip_address
    config_attrs["use_legacy_dashboard"] = legacy

    from zenml.zen_server.deploy.deployment import ServerDeploymentConfig

    server_config = ServerDeploymentConfig(**config_attrs)
    if blocking:
        from zenml.constants import (
            DEFAULT_USERNAME,
        )

        cli_utils.declare(
            "The local ZenML dashboard is about to deploy in a "
            "blocking process. You can connect to it using the "
            f"'{DEFAULT_USERNAME}' username and an empty password."
        )
    server = deployer.deploy_server(server_config)

    if not blocking:
        from zenml.constants import (
            DEFAULT_PASSWORD,
            DEFAULT_USERNAME,
        )

        deployer.connect_to_server(
            LOCAL_ZENML_SERVER_NAME,
            DEFAULT_USERNAME,
            DEFAULT_PASSWORD,
        )

        if server.status and server.status.url:
            cli_utils.declare(
                f"The local ZenML dashboard is available at "
                f"'{server.status.url}'. You can connect to it using the "
                f"'{DEFAULT_USERNAME}' username and an empty password. "
            )
            zenml.show(
                ngrok_token=ngrok_token,
                username=DEFAULT_USERNAME,
                password=DEFAULT_PASSWORD,
            )


# @click.option(
#     "--ngrok-token",
#     type=str,
#     default=None,
#     help="Specify an ngrok auth token to use for exposing the ZenML server.",
# )
# @cli.command("show", help="Show the ZenML dashboard.")
# def show(ngrok_token: Optional[str] = None) -> None:
#     """Show the ZenML dashboard.

#     Args:
#         ngrok_token: An ngrok auth token to use for exposing the ZenML dashboard
#             on a public domain. Primarily used for accessing the dashboard in
#             Colab.
#     """
#     try:
#         zenml.show(ngrok_token=ngrok_token)
#     except RuntimeError as e:
#         cli_utils.error(str(e))


@cli.command("logout", help="Shut down the local ZenML dashboard.")
def logout() -> None:
    """Shut down the local ZenML dashboard."""
    server = get_active_deployment(local=True)

    if not server:
        cli_utils.declare("The local ZenML dashboard is not running.")

    else:
        from zenml.zen_server.deploy.deployer import ServerDeployer

        deployer = ServerDeployer()
        deployer.remove_server(server.config.name)
        cli_utils.declare("The local ZenML dashboard has been shut down.")

        os.environ[ENV_ZENML_LOCAL_SERVER] = str(False)

        gc = GlobalConfiguration()
        gc.set_default_store()


@cli.command(
    "login",
    help=(
        """Login to a ZenML server.

    Examples:

      * to connect to a ZenML deployment using web login:

        zenml connect --url=http://zenml.example.com:8080

      * to connect to a ZenML deployment using command line arguments:

        zenml connect --url=http://zenml.example.com:8080 --username=admin

      * to use a configuration file:

        zenml connect --config=/path/to/zenml_config.yaml

      * when no arguments are supplied, ZenML will attempt to connect to the
        last ZenML server deployed from the local host using the 'zenml deploy'
        command.

    The configuration file must be a YAML or JSON file with the following
    attributes:

        url: The URL of the ZenML server.

        username: The username to use for authentication.

        password: The password to use for authentication.

        verify_ssl: Either a boolean, in which case it controls whether the
            server's TLS certificate is verified, or a string, in which case it
            must be a path to a CA certificate bundle to use or the CA bundle
            value itself.

        http_timeout: The number of seconds to wait for HTTP requests to the
            ZenML server to be successful before issuing a timeout error
            (default: 5).

    Example configuration:

        url: https://ac8ef63af203226194a7725ee71d85a-7635928635.us-east-1.elb.amazonaws.com/zenml\n
        username: admin\n
        password: Pa$$word123\n
        verify_ssl: |\n
        -----BEGIN CERTIFICATE-----
        MIIDETCCAfmgAwIBAgIQYUmQg2LR/pHAMZb/vQwwXjANBgkqhkiG9w0BAQsFADAT
        MREwDwYDVQQDEwh6ZW5tbC1jYTAeFw0yMjA5MjYxMzI3NDhaFw0yMzA5MjYxMzI3\n
        ...\n
        ULnzA0JkRWRnFqH6uXeJo1KAVqtxn1xf8PYxx3NlNDr9wi8KKwARf2lwm6sH4mvq
        1aZ/0iYnGKCu7rLJzxeguliMf69E\n
        -----END CERTIFICATE-----
        http_timeout: 10

    """
    ),
)
@click.option(
    "--url",
    "-u",
    help="The URL where the ZenML server is running.",
    required=False,
    type=str,
)
@click.option(
    "--api-key",
    help="Use an API key to authenticate with a ZenML server. If "
    "omitted, the web login will be used. If set, you will be prompted "
    "to enter the API key.",
    is_flag=True,
    default=False,
    type=click.BOOL,
)
@click.option(
    "--no-verify-ssl",
    is_flag=True,
    help="Whether to verify the server's TLS certificate",
    default=False,
)
@click.option(
    "--ssl-ca-cert",
    help="A path to a CA bundle file to use to verify the server's TLS "
    "certificate or the CA bundle value itself",
    required=False,
    type=str,
)
@click.option(
    "--local",
    is_flag=True,
    help="Start a local ZenML server and connect to it.",
    default=False,
    type=click.BOOL,
)
@click.option(
    "--docker",
    is_flag=True,
    help="Start the local ZenML server as a Docker container instead of a local "
    "process. Only used when `--local` is set.",
    default=False,
    type=click.BOOL,
)
@click.option(
    "--port",
    type=int,
    default=None,
    help="Use a custom TCP port value for the local ZenML server. Only used "
    "when `--local` is set.",
)
@click.option(
    "--ip-address",
    type=ipaddress.ip_address,
    default=None,
    help="Have the local ZenML server listen on an IP address different than "
    "the default localhost.",
)
@click.option(
    "--blocking",
    is_flag=True,
    help="Run the local ZenML server in blocking mode. The CLI will not return "
    "until the server exits or is stopped with CTRL+C. Only used when `--local` "
    "is set.",
    default=False,
    type=click.BOOL,
)
@click.option(
    "--image",
    type=str,
    default=None,
    help="Use a custom Docker image for the local ZenML server. Only used when "
    "both `--local` and `--docker` are set.",
)
@click.option(
    "--ngrok-token",
    type=str,
    default=None,
    help="Specify an ngrok auth token to use for exposing the local ZenML "
    "dashboard on a public domain. Primarily used for accessing the "
    "dashboard in Colab.",
)
@click.option(
    "--legacy",
    is_flag=True,
    help="Use the legacy ZenML dashboard with the local ZenML server instead "
    "of the new ZenML dashboard. Only used when `--local` is set.",
    default=False,
    type=click.BOOL,
)
def login(
    url: Optional[str] = None,
    api_key: bool = False,
    no_verify_ssl: bool = False,
    ssl_ca_cert: Optional[str] = None,
    local: bool = False,
    docker: bool = False,
    ip_address: Union[
        ipaddress.IPv4Address, ipaddress.IPv6Address, None
    ] = None,
    port: Optional[int] = None,
    blocking: bool = False,
    image: Optional[str] = None,
    ngrok_token: Optional[str] = None,
    legacy: bool = False,
) -> None:
    """Connect to a remote ZenML server.

    Args:
        url: The URL where the ZenML server is reachable.
        api_key: Whether to use an API key to authenticate with the ZenML
            server.
        no_verify_ssl: Whether to verify the server's TLS certificate.
        ssl_ca_cert: A path to a CA bundle to use to verify the server's TLS
            certificate or the CA bundle value itself.
        local: Start and connect to a local ZenML server instead of a remote
            server.
        docker: Use a local Docker server instead of a local process.
        ip_address: The IP address to bind the local server to.
        port: The port to bind the local server to.
        blocking: Block the CLI while the local server is running.
        image: A custom Docker image to use for the local Docker server, when
            the `docker` flag is set.
        ngrok_token: An ngrok auth token to use for exposing the local ZenML
            dashboard on a public domain. Primarily used for accessing the
            dashboard in Colab.
        legacy: Start the legacy ZenML dashboard instead of the new ZenML
            dashboard.
    """
    from zenml.zen_stores.base_zen_store import BaseZenStore

    if local:
        start_local_server(
            docker=docker,
            ip_address=ip_address,
            port=port,
            blocking=blocking,
            image=image,
            ngrok_token=ngrok_token,
            legacy=legacy,
        )
        return

    store_dict: Dict[str, Any] = {}

    if url is None:
        from zenml.login.pro.client import ZenMLProClient
        web_login()
        client = ZenMLProClient()
        tenants = client.tenant.list()

        cli_utils.print_pydantic_models(
            tenants, columns=["id", "name", "status"]
        )


    else:
        verify_ssl: Union[str, bool] = (
            ssl_ca_cert if ssl_ca_cert is not None else not no_verify_ssl
        )

        cli_utils.declare(f"Connecting to: '{url}'...")

        store_dict["url"] = url
        store_type = BaseZenStore.get_store_type(url)
        if store_type == StoreType.REST:
            store_dict["verify_ssl"] = verify_ssl
            if api_key:
                store_dict["api_key"] = api_key
            else:
                store_dict["api_token"] = web_login(
                    url=url, verify_ssl=verify_ssl
                )
        elif store_type == StoreType.SQL:
            if not username:
                username = click.prompt("Username", type=str)

                store_dict["username"] = username

                if password is None:
                    password = click.prompt(
                        f"Password for user {username} (press ENTER for empty password)",
                        default="",
                        hide_input=True,
                    )
                store_dict["password"] = password

        store_config_class = BaseZenStore.get_store_config_class(store_type)
        assert store_config_class is not None

    store_config = store_config_class.model_validate(store_dict)
    try:
        GlobalConfiguration().set_store(store_config)
    except IllegalOperationError:
        cli_utils.warning(
            f"User '{username}' does not have sufficient permissions to "
            f"access the server at '{url}'."
        )
    except AuthorizationException as e:
        cli_utils.warning(f"Authorization error: {e}")


# @cli.command("disconnect", help="Disconnect from a ZenML server.")
# def disconnect_server() -> None:
#     """Disconnect from a ZenML server."""
#     from zenml.zen_server.deploy.deployer import ServerDeployer
#     from zenml.zen_stores.base_zen_store import BaseZenStore

#     gc = GlobalConfiguration()

#     url = gc.store_configuration.url
#     store_type = BaseZenStore.get_store_type(url)
#     if store_type == StoreType.REST:
#         deployer = ServerDeployer()
#         deployer.disconnect_from_server()
#     else:
#         gc.set_default_store()
#         cli_utils.declare("Restored default store configuration.")


# @cli.command("logs", help="Show the logs for the local or cloud ZenML server.")
# @click.option(
#     "--local",
#     is_flag=True,
#     help="Show the logs for the local ZenML server.",
# )
# @click.option(
#     "--follow",
#     "-f",
#     is_flag=True,
#     help="Continue to output new log data as it becomes available.",
# )
# @click.option(
#     "--tail",
#     "-t",
#     type=click.INT,
#     default=None,
#     help="Only show the last NUM lines of log output.",
# )
# @click.option(
#     "--raw",
#     "-r",
#     is_flag=True,
#     help="Show raw log contents (don't pretty-print logs).",
# )
# def logs(
#     local: bool = False,
#     follow: bool = False,
#     raw: bool = False,
#     tail: Optional[int] = None,
# ) -> None:
#     """Display the logs for a ZenML server.

#     Args:
#         local: Whether to show the logs for the local ZenML server.
#         follow: Continue to output new log data as it becomes available.
#         tail: Only show the last NUM lines of log output.
#         raw: Show raw log contents (don't pretty-print logs).
#     """
#     server = get_active_deployment(local=True)
#     if not local:
#         remote_server = get_active_deployment(local=False)
#         if remote_server is not None:
#             server = remote_server

#     if server is None:
#         cli_utils.error(
#             "The local ZenML dashboard is not running. Please call `zenml "
#             "up` first to start the ZenML dashboard locally."
#         )

#     server_name = server.config.name

#     from zenml.zen_server.deploy.deployer import ServerDeployer

#     deployer = ServerDeployer()

#     cli_utils.declare(f"Showing logs for server: {server_name}")

#     from zenml.zen_server.deploy.exceptions import (
#         ServerDeploymentNotFoundError,
#     )

#     try:
#         logs = deployer.get_server_logs(server_name, follow=follow, tail=tail)
#     except ServerDeploymentNotFoundError as e:
#         cli_utils.error(f"Server not found: {e}")

#     for line in logs:
#         # don't pretty-print log lines that are already pretty-printed
#         if raw or line.startswith("\x1b["):
#             console.print(line, markup=False)
#         else:
#             try:
#                 console.print(line)
#             except MarkupError:
#                 console.print(line, markup=False)
