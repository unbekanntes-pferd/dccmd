# std import
import sys
import asyncio
import logging

# external imports
import typer
import httpx
from dracoon import DRACOON, OAuth2ConnectionType
from dracoon.client import DRACOONConnection
from dracoon.errors import HTTPUnauthorizedError, HTTPStatusError, HTTPNotFoundError

# internal imports
from .credentials import (
    get_credentials,
    store_credentials,
    delete_credentials,
    get_client_credentials,
    store_client_credentials,
    delete_client_credentials,
    get_crypto_credentials,
    store_crypto_credentials,
    delete_crypto_credentials,
)
from .util import login
from ..util import (
    format_error_message,
    format_success_message,
    graceful_exit,
    parse_base_url,
)
from ..models.errors import DCClientParseError


auth_app = typer.Typer()


@auth_app.command()
def rm(
    base_url: str = typer.Argument(..., help="Base DRACOON url (example: dracoon.team)")
):
    """removes auth token(refresh token) for OAuth2 authentication in DRACOON"""

    base_url = parse_base_url(full_path=f"{base_url}/")
    creds = get_credentials(base_url)
    crypto = get_crypto_credentials(base_url)

    if not creds:
        typer.echo(format_error_message(msg=f"No token stored DRACOON url: {base_url}"))
        sys.exit(1)

    delete_credentials(base_url)

    if crypto:
        delete_crypto_credentials(base_url)
        typer.echo(
            format_success_message(msg=f"Encryption password removed for {base_url}")
        )
    typer.echo(format_success_message(msg=f"Refresh token removed for {base_url}"))


@auth_app.command()
def ls(
    base_url: str = typer.Argument(..., help="Base DRACOON url (example: dracoon.team)")
):
    """displays auth info for OAuth2 authentication in DRACOON"""

    async def _ls():

        parsed_base_url = parse_base_url(full_path=f"{base_url}/")
        refresh_token = get_credentials(parsed_base_url)
        crypto_creds = get_crypto_credentials(parsed_base_url)

        if not refresh_token:
            typer.echo(
                format_error_message(msg=f"No token stored DRACOON url: {base_url}")
            )
            typer.Abort()
        if not crypto_creds:
            typer.echo(
                format_error_message(
                    msg=f"No encryption password stored for DRACOON url: {base_url}"
                )
            )
        else:
            typer.echo(
                format_success_message(msg=f"Encryption password stored for {base_url}")
            )

        typer.echo(format_success_message(msg=f"Refresh token stored for {base_url}"))

        display_user_info = typer.confirm(text="Display user info?")

        if display_user_info:
            dracoon = await login(base_url=parsed_base_url, refresh_token=refresh_token)
            typer.echo(
                f"Username: {dracoon.user_info.userName} ({dracoon.user_info.firstName} {dracoon.user_info.lastName})"
            )

    asyncio.run(_ls())
