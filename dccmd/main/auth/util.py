"""
Module with utility functions for authentication
- Login (OAuth flows)
- Initialize instance with CLI config
"""
import logging
import sys

import typer
import httpx
from dracoon import DRACOON, OAuth2ConnectionType
from dracoon.client import DRACOONConnection
from dracoon.errors import HTTPUnauthorizedError, HTTPStatusError

from dccmd.main.util import (format_error_message, format_success_message,
                             graceful_exit, parse_base_url)
from dccmd.main.models.errors import DCPathParseError, DCClientParseError
from .credentials import (
    store_client_credentials,
    get_client_credentials,
    delete_client_credentials,
    delete_credentials,
    store_credentials,
    get_credentials,
)

async def login(
    base_url: str,
    refresh_token: str = None,
    cli_mode: bool = False,
    username=None,
    password=None,
    debug: bool = False,
) -> DRACOON:
    """function to authenticate in DRACOON - returns an authenticated instance"""

    # validate DRACOON url
    is_dracoon = await is_dracoon_url(base_url=base_url)

    if not is_dracoon:
        typer.echo(format_error_message(msg=f"Invalid DRACOON url: {base_url}"))
        sys.exit(2)

    # get OAuth client
    try:
        client_id, client_secret = get_client_credentials(base_url)
    except DCClientParseError:
        client_id, client_secret = await register_client(base_url)

    # instantiate DRACOON
    log_level = logging.INFO

    if debug:
        log_level = logging.DEBUG

    dracoon = DRACOON(
        base_url=base_url,
        client_id=client_id,
        client_secret=client_secret,
        log_level=log_level,
        log_stream=debug,
    )

    # password flow
    if cli_mode:
        dracoon = await _login_password_flow(base_url, dracoon, username, password)
    # refresh token
    elif refresh_token:
        dracoon = await _login_refresh_token(base_url, dracoon, refresh_token)
    # auth code flow
    else:
        dracoon = await _login_prompt(base_url, dracoon)

    return dracoon


async def init_dracoon(
    url_str: str, username: str, password: str, cli_mode: bool, debug: bool
) -> tuple[DRACOON, str]:
    """function to initialize DRACOON - returns an authenticated instance"""

    # get DRACOON base url
    try:
        base_url = parse_base_url(url_str)
    except DCPathParseError:
        typer.echo(
            format_error_message(
                msg=f"Invalid DRACOON url format: {url_str} (example: dracoon.team/myroom/folder)"
            )
        )
        sys.exit(1)

    # get stored credentials
    refresh_token = get_credentials(base_url)

    # log in
    dracoon = await login(
        base_url=base_url,
        refresh_token=refresh_token,
        cli_mode=cli_mode,
        username=username,
        password=password,
        debug=debug,
    )

    return dracoon, base_url


async def _login_password_flow(
    base_url: str, dracoon: DRACOON, username: str, password: str
) -> DRACOON:

    if username is None or password is None:
        msg = "Missing credentials: username and password mandatory if using cli mode."
        typer.echo(f"{format_error_message(msg)}")
        sys.exit(2)

    try:
        await dracoon.connect(
            OAuth2ConnectionType.password_flow, username=username, password=password
        )
    except HTTPUnauthorizedError as err:
        await graceful_exit(dracoon=dracoon)
        err_body = err.error.response.json()
        if "error" in err_body and err_body["error"] == "invalid_client":
            typer.echo(
                format_error_message(
                    msg="Invalid client configuration: client removed."
                )
            )
            sys.exit(1)
        else:
            typer.echo(format_error_message(msg="Wrong username or password."))
    except HTTPStatusError:
        await graceful_exit(dracoon=dracoon)
        typer.echo(format_error_message(msg="Login failed."))
    except httpx.ConnectError:
        await graceful_exit(dracoon=dracoon)
        typer.echo(format_error_message(msg="Login failed."))

    save_creds = typer.confirm("Save credentials?", abort=False, default=True)

    if save_creds:
        store_credentials(
            base_url=base_url, refresh_token=dracoon.client.connection.refresh_token
        )

    return dracoon


async def _login_prompt(base_url: str, dracoon: DRACOON) -> DRACOON:

    typer.echo("Please authenticate via following link:")
    typer.echo(dracoon.get_code_url())
    auth_code = typer.prompt("Please enter auth code")
    try:
        await dracoon.connect(auth_code=auth_code)
    except HTTPUnauthorizedError:
        graceful_exit(dracoon=dracoon)
        typer.echo(format_error_message(msg="Wrong authorization code."))
    except httpx.ConnectError:
        graceful_exit(dracoon=dracoon)
        typer.echo(format_error_message(msg="Login failed (check authorization code)."))

    save_creds = typer.confirm("Save credentials?", abort=False, default=True)

    if save_creds:
        store_credentials(
            base_url=base_url, refresh_token=dracoon.client.connection.refresh_token
        )

    return dracoon


async def _login_refresh_token(
    base_url: str, dracoon: DRACOON, refresh_token: str
) -> DRACOON:
    dracoon.client.connection = DRACOONConnection(None, None, None, refresh_token, None)
    try:
        await dracoon.connect(connection_type=OAuth2ConnectionType.refresh_token)
    except HTTPUnauthorizedError as err:

        await graceful_exit(dracoon=dracoon)

        err_body = err.error.response.json()
        if "error" in err_body and err_body["error"] == "invalid_client":
            typer.echo(
                format_error_message(
                    msg="Invalid client configuration: client removed."
                )
            )
            delete_client_credentials(base_url)
            raise typer.Abort()
        else:
            delete_credentials(base_url=base_url)
            typer.echo(format_error_message(msg="Refresh token expired."))
    except HTTPStatusError:
        graceful_exit(dracoon=dracoon)
        typer.echo(format_error_message(msg="Login failed."))
    except httpx.ConnectError:
        graceful_exit(dracoon=dracoon)
        typer.echo(format_error_message(msg="Login failed."))

    # store new refresh token
    store_credentials(
        base_url=base_url, refresh_token=dracoon.client.connection.refresh_token
    )

    return dracoon


async def is_dracoon_url(base_url: str) -> bool:
    """verify if URL is valid DRACOON url"""

    if base_url[-1] == "/":
        base_url = base_url[:-1]

    info_url = base_url + "/public/software/version"

    async with httpx.AsyncClient() as client:

        try:
            res = await client.get(info_url)
            res.raise_for_status()
        except httpx.ConnectError:
            return False
        except httpx.HTTPStatusError:
            return False

    return True

async def register_client(base_url: str):
    """register client (OAuth2)"""

    base_url = parse_base_url(f"{base_url}/")

    if not await is_dracoon_url(base_url):
        typer.echo(format_error_message(msg=f"Invalid DRACOON url: {base_url}"))
        sys.exit(2)

    #pylint: disable=C0301
    typer.echo(
        "OAuth2 client needs to be configured to use DRACOON Commander. Authorization code flow is recommended."
    )
    client_id = typer.prompt("Please enter client id")
    client_secret = typer.prompt("Please enter client secret")

    client_id = str(client_id).strip()
    client_secret = str(client_secret).strip()

    store_client_credentials(base_url, client_id, client_secret)
    typer.echo(
        format_success_message(
            msg=f"Stored client credentials for DRACOON url: {base_url}"
        )
    )

    return client_id, client_secret


def remove_client(base_url: str):
    """remove client config from keychain"""

    base_url = parse_base_url(f"{base_url}/")

    client_id, client_secret = get_client_credentials(base_url)

    if client_id and client_secret:
        delete_client_credentials(base_url)
        typer.echo(
            format_success_message(
                msg=f"Removed client credentials for DRACOON url: {base_url}"
            )
        )
    else:
        typer.echo(
            format_error_message(
                msg=f"Client config not found for DRACOON url: {base_url}."
            )
        )
