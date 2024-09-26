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
from typing import Any, Dict, List, Optional, Union
import uuid

import click
from ray import get
from sqlalchemy import column
import yaml
from rich.errors import MarkupError

import zenml
from zenml.cli import utils as cli_utils
from zenml.cli.cli import TagGroup, cli
from zenml.client import Client
from zenml.config.global_config import GlobalConfiguration
from zenml.console import console
from zenml.constants import ENV_ZENML_LOCAL_SERVER
from zenml.enums import CliCategories, ServerProviderType, StoreType
from zenml.exceptions import AuthorizationException, IllegalOperationError
from zenml.logger import get_logger
from zenml.utils import yaml_utils
from zenml.zen_server.utils import get_local_server
from zenml.login.web_login import web_login
from zenml.utils import yaml_utils

logger = get_logger(__name__)

LOCAL_ZENML_SERVER_NAME = "local"


@cli.command("up", help="Start the ZenML dashboard locally.")
@click.option(
    "--docker",
    is_flag=True,
    help="Start the ZenML dashboard as a Docker container instead of a local "
    "process.",
    default=False,
    type=click.BOOL,
)
@click.option(
    "--port",
    type=int,
    default=None,
    help="Use a custom TCP port value for the ZenML dashboard.",
)
@click.option(
    "--ip-address",
    type=ipaddress.ip_address,
    default=None,
    help="Have the ZenML dashboard listen on an IP address different than the "
    "localhost.",
)
@click.option(
    "--blocking",
    is_flag=True,
    help="Run the ZenML dashboard in blocking mode. The CLI will not return "
    "until the dashboard is stopped.",
    default=False,
    type=click.BOOL,
)
@click.option(
    "--connect",
    is_flag=True,
    help="Connect the client to the local server even when already connected "
    "to a remote ZenML server.",
    default=False,
    type=click.BOOL,
)
@click.option(
    "--image",
    type=str,
    default=None,
    help="Use a custom Docker image for the ZenML server. Only used when "
    "`--docker` is set.",
)
@click.option(
    "--ngrok-token",
    type=str,
    default=None,
    help="Specify an ngrok auth token to use for exposing the ZenML server.",
)
@click.option(
    "--legacy",
    is_flag=True,
    help="Start the legacy ZenML dashboard instead of the new ZenML dashboard.",
    default=False,
    type=click.BOOL,
)
def up(
    docker: bool = False,
    ip_address: Union[
        ipaddress.IPv4Address, ipaddress.IPv6Address, None
    ] = None,
    port: Optional[int] = None,
    blocking: bool = False,
    connect: bool = False,
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
        connect: Connect the client to the local server even when already
            connected to a remote ZenML server.
        image: A custom Docker image to use for the server, when the
            `--docker` flag is set.
        ngrok_token: An ngrok auth token to use for exposing the ZenML dashboard
            on a public domain. Primarily used for accessing the dashboard in
            Colab.
        legacy: Start the legacy ZenML dashboard instead of the new ZenML
            dashboard.
    """
    from zenml.zen_server.deploy.deployer import ServerDeployer

    if connect:
        logger.warning(
            "The `--connect` flag is deprecated, has no effect, and will be "
            "removed in a future release."
        )

    gc = GlobalConfiguration()

    # Raise an error if the client is already connected to a remote server.
    if gc.store_configuration.type == StoreType.REST:
        if not gc.zen_store.is_local_store():
            cli_utils.error(
                "Your ZenML client is already connected to a remote server. If "
                "you want to spin up a local ZenML server, please disconnect "
                "from the remote server first by running `zenml disconnect`."
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

    server = get_local_server()
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


@click.option(
    "--ngrok-token",
    type=str,
    default=None,
    help="Specify an ngrok auth token to use for exposing the ZenML server.",
)
@cli.command("show", help="Show the ZenML dashboard.")
def show(ngrok_token: Optional[str] = None) -> None:
    """Show the ZenML dashboard.

    Args:
        ngrok_token: An ngrok auth token to use for exposing the ZenML dashboard
            on a public domain. Primarily used for accessing the dashboard in
            Colab.
    """
    try:
        zenml.show(ngrok_token=ngrok_token)
    except RuntimeError as e:
        cli_utils.error(str(e))


@cli.command("down", help="Shut down the local ZenML dashboard.")
def down() -> None:
    """Shut down the local ZenML dashboard."""
    server = get_local_server()

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
    "status", help="Show information about the current configuration."
)
def status() -> None:
    """Show details about the current configuration."""
    gc = GlobalConfiguration()
    client = Client()

    store_cfg = gc.store_configuration

    # Write about the current ZenML server
    cli_utils.declare("-----ZenML Server Status-----")
    if gc.uses_default_store():
        cli_utils.declare(
            f"Connected to a local ZenML database: ('{store_cfg.url}')"
        )
    else:
        cli_utils.declare(f"Connected to a ZenML server: '{store_cfg.url}'")

    # Write about the active entities
    scope = "repository" if client.uses_local_configuration else "global"
    cli_utils.declare(f"  The active user is: '{client.active_user.name}'")
    cli_utils.declare(
        f"  The active workspace is: '{client.active_workspace.name}' "
        f"({scope})"
    )
    cli_utils.declare(
        f"  The active stack is: '{client.active_stack_model.name}' ({scope})"
    )

    if client.root:
        cli_utils.declare(f"Active repository root: {client.root}")

    # Write about the configuration files
    cli_utils.declare(f"Using configuration from: '{gc.config_directory}'")
    cli_utils.declare(
        f"Local store files are located at: '{gc.local_stores_path}'"
    )

    server = get_local_server()
    if server:
        cli_utils.declare("The status of the local dashboard:")
        cli_utils.print_server_deployment(server)


@cli.command(
    "connect",
    help=(
        """Connect to a remote ZenML server.

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
    "--username",
    help="The username that is used to authenticate with a ZenML server. If "
    "omitted, the web login will be used.",
    required=False,
    type=str,
)
@click.option(
    "--password",
    help="The password that is used to authenticate with a ZenML server. If "
    "omitted, a prompt will be shown to enter the password.",
    required=False,
    type=str,
)
@click.option(
    "--api-key",
    help="Use an API key to authenticate with a ZenML server. If "
    "omitted, the web login will be used.",
    required=False,
    type=str,
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
    "--config",
    help="Use a YAML or JSON configuration or configuration file.",
    required=False,
    type=str,
)
@click.option(
    "--raw-config",
    is_flag=True,
    help="Whether to use the configuration without prompting for missing "
    "fields.",
    default=False,
)
def connect(
    url: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    api_key: Optional[str] = None,
    no_verify_ssl: bool = False,
    ssl_ca_cert: Optional[str] = None,
    config: Optional[str] = None,
    raw_config: bool = False,
) -> None:
    """Connect to a remote ZenML server.

    Args:
        url: The URL where the ZenML server is reachable.
        username: The username that is used to authenticate with the ZenML
            server.
        password: The password that is used to authenticate with the ZenML
            server.
        api_key: The API key that is used to authenticate with the ZenML
            server.
        no_verify_ssl: Whether to verify the server's TLS certificate.
        ssl_ca_cert: A path to a CA bundle to use to verify the server's TLS
            certificate or the CA bundle value itself.
        config: A YAML or JSON configuration or configuration file to use.
        raw_config: Whether to use the configuration without prompting for
            missing fields.
    """
    from zenml.config.store_config import StoreConfiguration
    from zenml.zen_stores.base_zen_store import BaseZenStore

    if password is not None:
        cli_utils.warning(
            "Supplying password values in the command line is not safe. "
            "Please consider using the prompt option."
        )

    # Raise an error if a local server is running when trying to connect to
    # another server
    active_deployment = get_local_server()
    if (
        active_deployment
        and active_deployment.status
        and active_deployment.status.url != url
    ):
        cli_utils.error(
            "You're trying to connect to a remote ZenML server but already "
            "have a local server running. This can lead to unexpected "
            "behavior. Please shut down the local server by running "
            "`zenml down` before connecting to a remote server."
        )

    store_dict: Dict[str, Any] = {}
    verify_ssl: Union[str, bool] = (
        ssl_ca_cert if ssl_ca_cert is not None else not no_verify_ssl
    )

    if config:
        if os.path.isfile(config):
            store_dict = yaml_utils.read_yaml(config)
        else:
            store_dict = yaml.safe_load(config)
        if not isinstance(store_dict, dict):
            cli_utils.error(
                "The configuration argument must be JSON/YAML content or "
                "point to a valid configuration file."
            )

        if raw_config:
            store_config = StoreConfiguration.model_validate(store_dict)
            GlobalConfiguration().set_store(store_config)
            return

        url = store_dict.get("url", url)
        username = username or store_dict.get("username")
        password = password or store_dict.get("password")
        api_key = api_key or store_dict.get("api_key")
        verify_ssl = store_dict.get("verify_ssl", verify_ssl)

    if not url:
        url = click.prompt("ZenML server URL", type=str)
    else:
        cli_utils.declare(f"Connecting to: '{url}'...")
    assert url is not None

    store_dict["url"] = url
    store_type = BaseZenStore.get_store_type(url)
    if store_type == StoreType.REST:
        store_dict["verify_ssl"] = verify_ssl

    if not username and not api_key:
        if store_type == StoreType.REST:
            store_dict["api_token"] = web_login(url=url, verify_ssl=verify_ssl)
        else:
            username = click.prompt("Username", type=str)

    if username:
        cli_utils.warning(
            "Connecting to a ZenML server using a username and password is "
            "not recommended because the password is locally stored on your "
            "filesystem. You should consider using the web login workflow by "
            "omitting the `--username` and `--password` flags. An alternative "
            "for non-interactive environments is to create and use a service "
            "account API key (see https://docs.zenml.io/how-to/connecting-to-zenml/connect-with-a-service-account "
            "for more information)."
        )

        store_dict["username"] = username

        if password is None:
            password = click.prompt(
                f"Password for user {username} (press ENTER for empty password)",
                default="",
                hide_input=True,
            )
        store_dict["password"] = password
    elif api_key:
        store_dict["api_key"] = api_key

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


@cli.command("disconnect", help="Disconnect from a ZenML server.")
def disconnect_server() -> None:
    """Disconnect from a ZenML server."""
    from zenml.zen_server.deploy.deployer import ServerDeployer
    from zenml.zen_stores.base_zen_store import BaseZenStore

    gc = GlobalConfiguration()

    url = gc.store_configuration.url
    store_type = BaseZenStore.get_store_type(url)
    if store_type == StoreType.REST:
        deployer = ServerDeployer()
        deployer.disconnect_from_server()
    else:
        gc.set_default_store()
        cli_utils.declare("Restored default store configuration.")


@cli.command("logs", help="Show the logs for the local ZenML server.")
@click.option(
    "--follow",
    "-f",
    is_flag=True,
    help="Continue to output new log data as it becomes available.",
)
@click.option(
    "--tail",
    "-t",
    type=click.INT,
    default=None,
    help="Only show the last NUM lines of log output.",
)
@click.option(
    "--raw",
    "-r",
    is_flag=True,
    help="Show raw log contents (don't pretty-print logs).",
)
def logs(
    follow: bool = False,
    raw: bool = False,
    tail: Optional[int] = None,
) -> None:
    """Display the logs for a ZenML server.

    Args:
        follow: Continue to output new log data as it becomes available.
        tail: Only show the last NUM lines of log output.
        raw: Show raw log contents (don't pretty-print logs).
    """
    server = get_local_server()
    if server is None:
        cli_utils.error(
            "The local ZenML dashboard is not running. Please call `zenml "
            "up` first to start the ZenML dashboard locally."
        )

    server_name = server.config.name

    from zenml.zen_server.deploy.deployer import ServerDeployer

    deployer = ServerDeployer()

    cli_utils.declare(f"Showing logs for server: {server_name}")

    from zenml.zen_server.deploy.exceptions import (
        ServerDeploymentNotFoundError,
    )

    try:
        logs = deployer.get_server_logs(server_name, follow=follow, tail=tail)
    except ServerDeploymentNotFoundError as e:
        cli_utils.error(f"Server not found: {e}")

    for line in logs:
        # don't pretty-print log lines that are already pretty-printed
        if raw or line.startswith("\x1b["):
            console.print(line, markup=False)
        else:
            try:
                console.print(line)
            except MarkupError:
                console.print(line, markup=False)


@cli.group(cls=TagGroup, tag=CliCategories.MANAGEMENT_TOOLS)
def server() -> None:
    """Commands for managing ZenML servers."""


@server.command(
    "list",
    help="""List all ZenML servers that this client is logged in to.
    
    This list includes the following:

      * ZenML Pro servers that the authenticated user is a member of. The client
        needs to be logged to ZenML Pro via `zenml login` to access these servers.

      * ZenML servers that the client has already logged in to to via
        `zenml login --url`.

      * the local ZenML server started with `zenml login --local`, if one is
        running.

    This list does not include ZenML servers that are not accessible: servers
    that are not running, or are running ZenML versions incompatible with the
    client, or are no longer accessible due to an expired authentication. To
    include these servers in the list, use the `--all` flag.
    """,
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Show verbose output.",
)
@click.option(
    "--all",
    "-a",
    is_flag=True,
    help="Show all ZenML servers, including those that are not running, "
    "or that are running ZenML versions that are not compatible with the "
    "client, or those with an expired authentication.",
)
def server_list(verbose: bool = False, all: bool = False) -> None:
    """List all ZenML servers that this client is authorized to access.

    Args:
        verbose: Whether to show verbose output.
        all: Whether to show all ZenML servers.
    """
    from zenml.login.pro.client import ZenMLProClient
    from zenml.login.pro.tenant.models import TenantRead, TenantStatus
    from zenml.login.token_cache import get_token_cache

    token_cache = get_token_cache()
    pro_token = token_cache.get_pro_token(allow_expired=True)
    current_store_config = GlobalConfiguration().store_configuration

    if pro_token:
        try:
            client = ZenMLProClient()
            servers = client.tenant.list(member_only=True)
        except AuthorizationException as e:
            cli_utils.warning(f"ZenML Pro authorization error: {e}")
        else:
            if not all:
                servers = [
                    s
                    for s in servers
                    if s.status == TenantStatus.AVAILABLE
                    and s.version == zenml.__version__
                ]

            if not servers:
                cli_utils.declare("No ZenML Pro servers found.")
                if not all:
                    cli_utils.declare(
                        "Hint: use the `--all` flag to show all ZenML servers, "
                        "including those that the client is not currently "
                        "accessible."
                    )
            else:
                if verbose:
                    columns = [
                        "id",
                        "name",
                        "organization_name",
                        "organization_id",
                        "version",
                        "status",
                        "state_reason",
                        "dashboard_url",
                    ]
                elif all:
                    columns = [
                        "id",
                        "name",
                        "organization_name",
                        "version",
                        "status",
                        "dashboard_url",
                    ]
                else:
                    columns = [
                        "id",
                        "name",
                        "organization_name",
                        "dashboard_url",
                    ]

                # Figure out if the client is already connected to one of the
                # servers in the list
                current_server: List[TenantRead] = []
                if current_store_config.type == StoreType.REST:
                    current_server = [
                        s for s in servers if s.url == current_store_config.url
                    ]

                cli_utils.print_pydantic_models(
                    servers,
                    columns=columns,
                    rename_columns={
                        "organization_name": "organization",
                        "organization_id": "organization ID",
                        "dashboard_url": "URL",
                        "state_reason": "state reason",
                    },
                    active_models=current_server,
                    show_active=True,
                )


@server.command(
    "connect",
    help="""Connect to a remote ZenML server.

    Use this command to connect the client to one of the ZenML servers that the
    client is already logged in to. The list of servers that can be used with
    this CLI command can be fetched by running `zenml server list`.

    The server argument can be one of the following:

    * The name or UUID of a ZenML Pro server to connect to.
    * The URL of a ZenML server to connect to.
    * 'local' to connect to the local ZenML server, if running.

    Examples:

        * to connect to a ZenML Pro server by name:

            zenml server connect my-zenml-server

        * to connect to a ZenML Pro server by URL:

            zenml server connect http://zenml.example.com:8080

        * to connect to the local ZenML server:

            zenml server connect local
    """,
)
@click.argument("server", type=str, required=True)
@click.option(
    "--force",
    "-f",
    is_flag=True,
    help="Force the client to connect to a ZenML server with an incompatible "
    "version.",
)
def server_connect(server: str, force: bool = False) -> None:
    """Connect to a remote ZenML server.

    Args:
        server: The name of the ZenML server to connect to.
        force: Whether to force the client to connect to a server with an
            incompatible version.
    """
    from zenml.config.store_config import StoreConfiguration
    from zenml.login.pro.client import ZenMLProClient
    from zenml.login.pro.tenant.models import TenantRead, TenantStatus
    from zenml.login.pro.utils import is_zenml_pro_server
    from zenml.login.token_cache import get_token_cache

    token_cache = get_token_cache()

    def connect_to_server(url: str) -> None:
        """Connect the client to a ZenML server.

        Args:
            url: The URL of the ZenML server to connect to.
        """
        store_config = StoreConfiguration(
            url=url,
            type=StoreType.REST,
        )
        try:
            GlobalConfiguration().set_store(store_config)
        except IllegalOperationError:
            cli_utils.error(
                f"You do not have sufficient permissions to "
                f"access the server at '{url}'."
            )
        except AuthorizationException as e:
            cli_utils.error(f"Authorization error: {e}")

        cli_utils.declare(f"Connected to ZenML server: {url}")

    def connect_to_pro_server(server: TenantRead) -> None:
        """Connect the client to a ZenML Pro server.

        Args:
            server: The ZenML Pro server to connect to.
        """
        if server.status != TenantStatus.AVAILABLE or not server.url:
            cli_utils.error(
                f"The ZenML Pro server '{server.name}' is not currently "
                f"running. Visit the ZenML Pro dashboard to manage the server "
                f"status at: {server.dashboard_url}"
            )

        if server.version and server.version != zenml.__version__:
            if not force:
                cli_utils.error(
                    f"The ZenML Pro server '{server.name}' is running ZenML "
                    f"version {server.version}, which is incompatible with the "
                    f"client version {zenml.__version__}. To connect to this "
                    f"server, update the client to the server's version or pass "
                    f"the `--force` flag to connect anyway."
                )

            cli_utils.warning(
                f"The ZenML Pro server '{server.name}' is running ZenML "
                f"version {server.version}, which is incompatible with the "
                f"client version {zenml.__version__}."
            )

        connect_to_server(server.url)

    try:
        client = ZenMLProClient()
        servers = client.tenant.list(member_only=True)
    except AuthorizationException:
        servers = []

    if server.startswith("http://") or server.startswith("https://"):
        # The server argument is a URL
        if is_zenml_pro_server(server):
            # The server is a ZenML Pro server; look up the server by URL
            servers = [s for s in servers if s.url == server.rstrip("/")]
            if not servers:
                cli_utils.error(
                    f"No ZenML Pro server found with URL '{server}'."
                )
            connect_to_pro_server(servers[0])
            return

        # The server is not a ZenML Pro server; look up a cached API token
        token = token_cache.get_token(server, allow_expired=True)
        if not token:
            cli_utils.error(
                f"The client is not logged in to a ZenML server with URL "
                f"'{server}'. Please log in to the server first using "
                "`zenml login {server}`."
            )
        if token.expired:
            cli_utils.error(
                f"The client's authentication for the server with URL "
                f"'{server}' has expired. Please log in to the server again "
                f"using `zenml login {server}`."
            )
        connect_to_server(server)
        return

    try:
        server_id = uuid.UUID(server)
    except ValueError:
        pass
    else:
        # Look up the server by ID
        servers = [s for s in servers if s.id == server_id]
        if not servers or not servers[0].url:
            cli_utils.error(f"No ZenML Pro server found with ID '{server}'.")
        connect_to_pro_server(servers[0])
        return

    # Look up the server by name
    servers = [s for s in servers if s.name == server]
    if len(servers) > 1:
        cli_utils.error(
            f"Multiple ZenML Pro servers found with name '{server}' in "
            "multiple organizations. Please specify the server by ID "
            f"or URL instead: {', '.join([str(s.id) for s in servers])}"
        )
    if not servers:
        cli_utils.error(f"No ZenML Pro server found with name '{server}'.")
    connect_to_pro_server(servers[0])
