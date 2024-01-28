"""
Helper functions to handle crypto (keypair operations)
"""
import sys
import typer

from dracoon import DRACOON
from dracoon.errors import HTTPNotFoundError, DRACOONHttpError

from dccmd.main.util import graceful_exit, format_error_message
from dccmd.main.auth.credentials import store_crypto_credentials


async def get_keypair(dracoon: DRACOON, crypto_secret: str):
    """get keypair from DRACOON"""
    try:
        await dracoon.get_keypair(secret=crypto_secret)
    except ValueError:
        await graceful_exit(dracoon=dracoon)
        typer.echo(format_error_message(msg="Encryption password is incorrect."))
        sys.exit(1)
    except HTTPNotFoundError:
        await graceful_exit(dracoon=dracoon)
        typer.echo(
            format_error_message(
                msg="No keypair set - keypair required to work with encrypted rooms."
            )
        )
        sys.exit(1)
    except DRACOONHttpError:
        await graceful_exit(dracoon=dracoon)
        typer.echo(format_error_message(msg="An error ocurred getting the keypair."))
        sys.exit(1)

async def init_keypair(dracoon: DRACOON, base_url: str, cli_mode: bool, crypto_secret: str = None):
    """ handle keypair storage """
    if not crypto_secret:
        crypto_secret = typer.prompt(
                    "Enter encryption password: ", hide_input=True
                )
        if not cli_mode:
            save_creds = typer.confirm(
                    "Save credentials?", abort=False, default=True
                )
        else:
            save_creds = False

        await get_keypair(dracoon=dracoon, crypto_secret=crypto_secret)

        if save_creds or cli_mode:
            store_crypto_credentials(
                        base_url=base_url, crypto_secret=crypto_secret, cli_mode=cli_mode
                    )

    await get_keypair(dracoon=dracoon, crypto_secret=crypto_secret)
