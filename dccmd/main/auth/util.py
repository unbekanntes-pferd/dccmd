"""
Module with utility functions for authentication
- Login (OAuth flows)
- Initialize instance with CLI config
"""
import logging
import sys
from typing import Tuple

import typer
import httpx
from dracoon import DRACOON, OAuth2ConnectionType
from dracoon.errors import HTTPUnauthorizedError, DRACOONHttpError, HTTPBadRequestError
from dccmd import __version__ as dccmd_version
from dccmd import __name__ as dccmd_name
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

DEFAULT_TIMEOUT_CONFIG = httpx.Timeout(None, connect=None, read=None)

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
        sys.exit(1)

    # get OAuth client
    try:
        client_id, client_secret = get_client_credentials(base_url, cli_mode)
    except DCClientParseError:
        client_id, client_secret = await register_client(base_url, cli_mode)

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
        log_file_out=True,
        raise_on_err=True
    )
    
    # set custom user agent
    dracoon_user_agent = dracoon.client.http.headers["User-Agent"]
    dracoon.client.http.headers["User-Agent"] = f"{dccmd_name}|{dccmd_version}|{dracoon_user_agent}"

    # set custom client with no timeout, up- and downloader with same client !!!
    dracoon.client.http = httpx.AsyncClient(headers=dracoon.client.headers, timeout=DEFAULT_TIMEOUT_CONFIG)
    dracoon.client.uploader = httpx.AsyncClient(timeout=DEFAULT_TIMEOUT_CONFIG)
    dracoon.client.downloader = dracoon.client.uploader

    # password flow
    if cli_mode:
        try:
            dracoon = await _login_password_flow(base_url, dracoon, username, password, cli_mode)
        except HTTPUnauthorizedError:
            await graceful_exit(dracoon=dracoon)
            typer.echo(format_error_message(msg='Wrong username/password.'))
            sys.exit(1)
        except DRACOONHttpError:
            await graceful_exit(dracoon=dracoon)
            typer.echo(format_error_message(msg='An error ocurred during login'))
            sys.exit(1)       
    # refresh token
    elif refresh_token:
        try:
            dracoon = await _login_refresh_token(base_url, dracoon, refresh_token)
        # invalid refresh token
        except HTTPBadRequestError:
            dracoon = await _login_prompt(base_url, dracoon)
        except DRACOONHttpError:
            typer.echo(format_error_message(msg='An error ocurred during login'))
            sys.exit(1)

    # auth code flow
    else:
        try:
            dracoon = await _login_prompt(base_url, dracoon)
        except HTTPBadRequestError:
            typer.echo(format_error_message(msg='Invalid authorization code.'))
            sys.exit(1)
        except DRACOONHttpError:
            typer.echo(format_error_message(msg='An error ocurred during login'))
            sys.exit(1)


    return dracoon


async def init_dracoon(
    url_str: str, username: str, password: str, cli_mode: bool, debug: bool
) -> Tuple[DRACOON, str]:
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
    refresh_token = get_credentials(base_url, cli_mode)

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
    base_url: str, dracoon: DRACOON, username: str, password: str, cli_mode: bool
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
    except DRACOONHttpError:
        await graceful_exit(dracoon=dracoon)
        typer.echo(format_error_message(msg="Login failed."))

    if not cli_mode:
        save_creds = typer.confirm("Save credentials?", abort=False, default=True)
    else:
        save_creds = False

    if save_creds or cli_mode:
        store_credentials(
            base_url=base_url, refresh_token=dracoon.client.connection.refresh_token, cli_mode=cli_mode
        )

    return dracoon


async def _login_prompt(base_url: str, dracoon: DRACOON) -> DRACOON:

    typer.echo("Please authenticate via following link:")
    typer.echo(dracoon.get_code_url())
    auth_code = typer.prompt("Please enter auth code")
    try:
        await dracoon.connect(auth_code=auth_code)
    except HTTPUnauthorizedError:
        await graceful_exit(dracoon=dracoon)
        typer.echo(format_error_message(msg="Wrong authorization code."))
    except DRACOONHttpError:
        graceful_exit(dracoon=dracoon)
        typer.echo(format_error_message(msg="Login failed (check authorization code)."))

    save_creds = typer.confirm("Save credentials?", abort=False, default=True)

    if save_creds:
        store_credentials(
            base_url=base_url, refresh_token=dracoon.client.connection.refresh_token, cli_mode=False
        )

    return dracoon


async def _login_refresh_token(
    base_url: str, dracoon: DRACOON, refresh_token: str, cli_mode: bool
) -> DRACOON:
    
    try:
        await dracoon.connect(connection_type=OAuth2ConnectionType.refresh_token, refresh_token=refresh_token)
        store_credentials(
        base_url=base_url, refresh_token=dracoon.client.connection.refresh_token
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
            delete_client_credentials(base_url, cli_mode)
            raise typer.Abort()
        else:
            delete_credentials(base_url=base_url, cli_mode=cli_mode)
            typer.echo(format_error_message(msg="Refresh token expired."))
    except HTTPBadRequestError as err:
        await graceful_exit(dracoon=dracoon)
        err_body = err.error.response.json()
        if "error" in err_body and err_body["error"] == "invalid_grant":
            delete_credentials(base_url=base_url, cli_mode=cli_mode)
            typer.echo(format_error_message(msg="Refresh token expired."))
            await _login_prompt(base_url=base_url, dracoon=dracoon)

    except DRACOONHttpError as err:
        await graceful_exit(dracoon=dracoon)
        typer.echo(format_error_message(msg="Login failed."))
        raise typer.Abort() from err

    return dracoon


async def is_dracoon_url(base_url: str) -> bool:
    """verify if URL is valid DRACOON url"""

    if base_url[-1] == "/":
        base_url = base_url[:-1]

    info_url = base_url + "/api/v4/public/software/version"

    async with httpx.AsyncClient() as client:
        try:
            res = await client.get(info_url)
            res.raise_for_status()
        except httpx.ConnectError as err:
            return False
        except httpx.HTTPStatusError as err:
            return False

    return True

async def register_client(base_url: str, cli_mode: bool):
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
    
    store_client_credentials(base_url, client_id, client_secret, cli_mode)
    typer.echo(
        format_success_message(
            msg=f"Stored client credentials for DRACOON url: {base_url}"
        )
    )

    return client_id, client_secret


def remove_client(base_url: str, cli_mode: bool):
    """remove client config from keychain"""

    base_url = parse_base_url(f"{base_url}/")

    client_id, client_secret = get_client_credentials(base_url, cli_mode)

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
