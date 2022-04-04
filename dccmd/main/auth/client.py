"""
Module exporting client app
Contains sub commands to set up and configure
OAuth2 client app for a given DRACOON url
"""

import sys
import asyncio

import typer

from dccmd.main.models.errors import DCClientParseError
from dccmd.main.util import format_error_message, format_success_message, parse_base_url
from .credentials import get_client_credentials
from .util import register_client, remove_client


client_app = typer.Typer()


@client_app.command()
def register(
    base_url: str = typer.Argument(..., help="Base DRACOON url (example: dracoon.team)")
):
    """sets up client (client id and secret) for OAuth2 authentication in DRACOON"""
    asyncio.run(register_client(base_url))


@client_app.command()
#pylint: disable=C0103
def rm(
    base_url: str = typer.Argument(..., help="Base DRACOON url (example: dracoon.team)")
):
    """removes client (client id and secret) for OAuth2 authentication in DRACOON"""

    try:
        remove_client(base_url)
    except DCClientParseError:
        typer.echo(
            format_error_message(msg=f"Client not found for DRACOON url: {base_url}.")
        )
        sys.exit(1)


@client_app.command()
#pylint: disable=C0103
def ls(
    base_url: str = typer.Argument(..., help="Base DRACOON url (example: dracoon.team)")
):
    """displays client (client id and secret) for OAuth2 authentication in DRACOON"""

    base_url = parse_base_url(f"{base_url}/")
    try:
        client_id, client_secret = get_client_credentials(base_url)
    except DCClientParseError:
        typer.echo(
            format_error_message(msg=f"Client not found for DRACOON url: {base_url}")
        )
        sys.exit(1)

    typer.echo(format_success_message(msg=f"Client id for {base_url}: {client_id}"))
    display_secret = typer.confirm(text="Display client secret?", default=False)

    if display_secret:
        typer.echo(
            format_success_message(msg=f"Client secret for {base_url}: {client_secret}")
        )
