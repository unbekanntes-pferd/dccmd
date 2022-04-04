"""
Module exporting crypto subcommands
- Remove crypto password
- Distribute file keys
"""

import sys
import asyncio

import typer
from dracoon.nodes.models import NodeType

from dccmd.main.auth.credentials import (
    get_crypto_credentials,
    delete_crypto_credentials,
)
from dccmd.main.auth.util import init_dracoon
from dccmd.main.util import parse_base_url, format_error_message, format_success_message, parse_path

from .keys import distribute_missing_keys
from .util import init_keypair

crypto_app = typer.Typer()


@crypto_app.command()
#pylint: disable=C0103
def ls(
    base_url: str = typer.Argument(..., help="Base DRACOON url (example: dracoon.team)")
):
    """displays if encryption password is stored for DRACOON url"""
    base_url = parse_base_url(full_path=f"{base_url}/")
    crypto = get_crypto_credentials(base_url)

    if not crypto:
        typer.echo(
            format_error_message(
                msg=f"No encryption password stored for DRACOON url: {base_url}"
            )
        )
        sys.exit(1)

    typer.echo(format_success_message(msg=f"Encryption password stored for {base_url}"))


@crypto_app.command()
#pylint: disable=C0103
def rm(
    base_url: str = typer.Argument(..., help="Base DRACOON url (example: dracoon.team)")
):
    """removes encryption password for given DRACOON url"""

    base_url = parse_base_url(full_path=f"{base_url}/")
    crypto = get_crypto_credentials(base_url)

    if not crypto:
        typer.echo(
            format_error_message(
                msg=f"No encryption password stored for DRACOON url: {base_url}"
            )
        )
        sys.exit(1)

    delete_crypto_credentials(base_url)

    typer.echo(
        format_success_message(msg=f"Encryption password removed for {base_url}")
    )


@crypto_app.command()
def distribute(
    target_path: str = typer.Argument(
        ...,
        help="Path to node or file in DRACOON for which file keys need to be distributed.",
    ),
    cli_mode: bool = typer.Option(
        False, help="When active, accepts username and password"
    ),
    debug: bool = typer.Option(
        False, help="When active, sets log level to DEBUG and streams log"
    ),
    username: str = typer.Argument(
        None, help="Username to log in to DRACOON - only works with active cli mode"
    ),
    password: str = typer.Argument(
        None, help="Password to log in to DRACOON - only works with active cli mode"
    ),
):
    """ Distribute missing file keys if available """
    async def _distribute_keys():

        dracoon, base_url = await init_dracoon(
            url_str=target_path,
            username=username,
            password=password,
            cli_mode=cli_mode,
            debug=debug,
        )

        crypto_secret = get_crypto_credentials(base_url)
        await init_keypair(dracoon=dracoon, base_url=base_url, crypto_secret=crypto_secret)

        # remove base url from path
        parsed_path = parse_path(full_path=target_path)

        if parsed_path != "/":
            parent_node = await dracoon.nodes.get_node_from_path(path=parsed_path)
        elif parsed_path == "/":
            parent_node = None
            distrib_node_id = None

        # node id must be from parent room if folder
        if parent_node and parent_node.type == NodeType.folder:
            distrib_node_id = parent_node.authParentId
        if parent_node and parent_node.type == NodeType.room:
            distrib_node_id = parent_node.id

        await distribute_missing_keys(dracoon=dracoon, room_id=distrib_node_id)

    asyncio.run(_distribute_keys())
